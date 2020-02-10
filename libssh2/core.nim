import ../libssh2, asyncdispatch, asyncnet, logging, strformat, os, posix, posix_utils
import types, utils, session

export session

proc newSSHClient*(): SSHClient =
  var rc {.global.}: cint = -1
  if rc != 0:
    # only run once per application life time
    rc = init(0)
    if rc != 0:
      raise newException(SSHException, "libssh2 initialization failed")
  result = new SSHClient

proc authWithAgent(s: SSHClient, username: string) =
  var
    identity: AgentPublicKey
    prevIdentity: AgentPublicKey

  s.agent = s.session.agentInit()
  if s.agent.isNil:
    raise newException(SSHException, "Failure initializing ssh-agent support")

  if s.agent.agentConnect() < 0:
    raise newException(SSHException, "Failure connecting to ssh-agent")

  if s.agent.agentListIdentities() < 0:
    raise newException(SSHException, "Failure requesting identities to ssh-agent")

  while true:
    var rc = s.agent.agentGetIdentity(addr identity, prevIdentity)
    if rc == 1:
      break
    elif rc < 0:
      raise newException(SSHException, "Failure obtaining identity from ssh-agent support")
    else:
      while true:
        rc = s.agent.agentUserauth(username, identity)
        if rc != LIBSSH2_ERROR_EAGAIN:
          break
      if rc != 0:
        raise newException(AuthenticationException, &"Authentication with username {username} and public key {identity.comment} failed!")
      else:
        debug "Authentication with username {server.user} and public key {identity.comment} succeeded"
        break
    prevIdentity = identity

proc authWithPassword(s: SSHClient, username: string, password: string) =
  if s.session.userauthPassword(username, password, nil) != 0:
    raise newException(AuthenticationException, &"Authentication with username {username} and password failed!")
  else:
    debug "Authentication by password succeeded."

proc disconnect*(c: SSHClient) =
  if c.agent != nil:
    discard c.agent.agentDisconnect()
    c.agent.agentFree()
    c.agent = nil

  if c.session != nil:
    while c.session.sessionDisconnect("libssh2 wrapper for Nim, libssh2.nim/core") == LIBSSH2_ERROR_EAGAIN:
      discard
    discard c.session.sessionFree()
    c.session = nil

  c.socket.close()
  libssh2.exit()

proc connect*(s: SSHClient, hostname: string, username: string, port = Port(22), password = "", useAgent = false) {.async.} =
  s.socket = newAsyncSocket()
  await s.socket.connect(hostname, port)
  s.session = sessionInit()
  s.session.sessionSetBlocking(0)

  var rc: cint
  while true:
    rc = s.session.sessionHandshake(s.socket.getFd())
    if rc  != LIBSSH2_ERROR_EAGAIN:
      break
  if rc != 0:
    raise newException(SSHException, "Failure establing ssh connection")

  if useAgent:
    s.authWithAgent(username)
  else:
    s.authWithPassword(username, password)

proc execCommand*(s: SSHClient, command: string): Future[(string, string, int)] {.async.} =
  var channel: Channel
  while true:
    channel = s.session.channelOpenSession()
    if channel == nil and s.session.sessionLastError(nil, 0, 0) == LIBSSH2_ERROR_EAGAIN:
      discard s.waitsocket()
    else:
      break

  if channel == nil:
    raise newException(SSHException, "Unable to open a session")

  var rc: cint
  while true:
    rc = channel.channelExec(command)
    if rc != LIBSSH2_ERROR_EAGAIN:
      break

  if rc != 0:
    raise newException(SSHException, &"Error execute command: {rc}")

  var
    buffer: array[0..1024, char]
    stdout: string
    stderr: string
    exitcode = 127

  while true:
    zeroMem(addr buffer, buffer.len)
    rc = channel.channelRead(addr buffer, buffer.len)
    if rc > 0:
      stdout.add($cast[cstring](addr buffer))
    elif rc == LIBSSH2_ERROR_EAGAIN:
      discard s.waitsocket()
    else:
      break

  while true:
    zeroMem(addr buffer, buffer.len)
    rc = channel.channelReadStderr(addr buffer, buffer.len)
    if rc > 0:
      stderr.add($cast[cstring](addr buffer))
    elif rc == LIBSSH2_ERROR_EAGAIN:
      discard s.waitsocket()
    else:
      break

  while true:
    rc = channel.channelClose()
    if rc == LIBSSH2_ERROR_EAGAIN:
      discard s.waitsocket()
    else:
      break
  if rc == 0:
    exitcode = channel.channelGetExitStatus()
  discard channel.channelFree()
  result = (stdout, stderr, exitcode)

proc sendFile(s: SSHClient, localPath: string, remotePath: string) =
  var channel: Channel
  if not localPath.fileExists():
    raise newException(FileNotFoundException, &"{localPath}: No such file or directory")
  let stat = stat(localPath)
  while true:
    channel = s.session.scpSend(remotePath, stat.st_mode.int and 777, stat.st_size)
    if channel != nil:
      break
    if channel == nil and s.session.sessionLastErrno() != LIBSSH2_ERROR_EAGAIN:
      var
        errmsg: cstring
        errlen: int
        err = s.session.sessionLastError(addr errmsg, errlen, 0)
      raise newException(SSHException, &"scp: {remotePath}: {errmsg} ({err})")
  debug "SCP session waiting to send file"
  var buffer = alloc0(1024)
  var f = open(localPath, fmRead)
  while true:
    var bytesRead = f.readBuffer(buffer, 1024)
    if bytesRead <= 0:
      break

    var bytesWrite: cint
    while true:
      bytesWrite = channel.channelWrite(cast[cstring](buffer), bytesRead)
      if bytesWrite == LIBSSH2_ERROR_EAGAIN:
        discard s.waitsocket()
      else:
        break
    if bytesWrite != bytesRead:
      raise newException(SSHException, &"Unable to write data to SCP channel: {bytesWrite}")

  dealloc(buffer)

  while channel.channelSendEof() == LIBSSH2_ERROR_EAGAIN: discard
  while channel.channelWaitEof() == LIBSSH2_ERROR_EAGAIN: discard
  while channel.channelWaitClosed() == LIBSSH2_ERROR_EAGAIN: discard
  #var rc: cint
  #while true:
  #  rc = channel.channelClose()
  #  if rc == LIBSSH2_ERROR_EAGAIN:
  #    discard s.waitsocket()
  #  else:
  #    break
  #echo rc
  #if rc == 0:
  #  echo channel.channelGetExitStatus()
  discard channel.channelFree()

when isMainModule:
  proc main() {.async.} =
    var client = newSSHClient()
    try:
      await client.connect("10.8.11.12", "root", useAgent=true)
      echo await client.execCommand("/tmp/test.sh &")
      echo await client.execCommand("rm /tmp/LICENSE")
      echo await client.execCommand("ls /tmp")
      client.sendFile("LICENSE", "/tmp/LICENSE")
      echo await client.execCommand("ls /tmp")
      echo await client.execCommand("uptime")
    except:
      client.disconnect()

  waitFor main()

