import os
import net
import posix
import base64

import ../libssh2


var
  username = "root"
  password = "S3cret"
  pubkeyFile = "~/.ssh/id_rsa.pub"
  privkeyFile = "~/.ssh/id_rsa"
  hostname = "127.0.0.1"
  command = "uptime"

if paramCount() > 0:
  hostname = paramStr(1)

if paramCount() > 1:
  username = paramStr(2)

if paramCount() > 2:
  password = paramStr(3)

if paramCount() > 3:
  command = paramStr(4)



var rc = init(0)
if rc != 0:
  quit "libssh2 initialization failed", rc

var sock = newSocket()
sock.connect(hostname, Port(22))

proc shutdown(s: Session) =
  discard s.sessionDisconnect("Normal shutdown, thank you for playing")
  discard s.sessionFree()
  sock.close()
  libssh2.exit()
  quit()

proc waitsocket(socket_fd: SocketHandle, s: Session): int =
  var timeout: Timeval
  var fd: TFdSet
  var writefd: TFdSet
  var readfd: TFdSet
  var dir: int

  timeout.tv_sec = 10.Time
  timeout.tv_usec = 0

  FD_ZERO(fd)
  FD_SET(socket_fd, fd)

  dir = s.sessionBlockDirections()

  if((dir and LIBSSH2_SESSION_BLOCK_INBOUND) == LIBSSH2_SESSION_BLOCK_INBOUND):
    readfd = fd

  if((dir and LIBSSH2_SESSION_BLOCK_OUTBOUND) == LIBSSH2_SESSION_BLOCK_OUTBOUND):
    writefd = fd

  var sfd  = cast[cint](socket_fd) + 1

  result = select(sfd, addr readfd, addr writefd, nil, addr timeout);

var session = sessionInit()

session.sessionSetBlocking(0)

while true:
  rc = session.sessionHandshake(sock.getFd())
  if rc != LIBSSH2_ERROR_EAGAIN:
    break

if rc != 0:
  quit "failure establing ssh connection"


var knownHosts = session.knownHostInit()
if knownHosts.isNil:
  session.shutdown()

rc = knownHosts.knownHostReadfile("dummy_known_hosts", LIBSSH2_KNOWNHOST_FILE_OPENSSH)
if rc < 0:
  echo "Read knownhost error: ", rc
else:
  echo "Parsed ", rc, " knownhosts"

var length: int
var typ: int

var fingerprint = session.sessionHostkey(length, typ)
if fingerprint.isNil:
  echo "Unable to fetch hostkey"
  session.shutdown()

var host: knownhost_st
let check = knownHosts.knownHostCheckP(hostname, 22, fingerprint, length, LIBSSH2_KNOWNHOST_TYPE_PLAIN or LIBSSH2_KNOWNHOST_KEYENC_RAW or LIBSSH2_KNOWNHOST_KEY_SSHRSA, addr host)
echo "Host check: ", check, " key: ", if check <= LIBSSH2_KNOWNHOST_CHECK_MISMATCH: host.key else: "<none>"


rc = knownHosts.knownHostAddC(hostname, nil, fingerprint, length, nil, 0, LIBSSH2_KNOWNHOST_TYPE_PLAIN or LIBSSH2_KNOWNHOST_KEYENC_RAW or LIBSSH2_KNOWNHOST_KEY_SSHRSA, nil)
if rc == 0:
  echo "Add knownhost succeeded!"
else:
  echo "Failed to add knownhost: ", rc

knownHosts.knownHostWritefile("dummy_known_hosts", LIBSSH2_KNOWNHOST_FILE_OPENSSH)
knownHosts.knownHostFree()

if password.len > 0:
  while true:
    rc = session.userauthPassword(username, password, nil)
    if rc != LIBSSH2_ERROR_EAGAIN:
      break

  if rc != 0:
    echo "Authentication by password failed!"
    session.shutdown()

else:
  while true:
    rc = session.userauthPublickeyFromFile(username, pubkeyFile, privkeyFile, password)
    if rc != LIBSSH2_ERROR_EAGAIN:
      break

  if rc != 0:
    echo  "Authentication by public key failed!"
    session.shutdown()
var channel: Channel
while true:
  channel = session.channelOpenSession()
  if channel.isNil and session.sessionLastError(nil, 0, 0) == LIBSSH2_ERROR_EAGAIN:
    discard waitsocket(sock.getFd(), session)
  else:
    break

if channel.isNil:
  echo "Unable to open a session"
  session.shutdown()

while true:
  rc = channel.channelExec(command)
  if rc != LIBSSH2_ERROR_EAGAIN:
    break

if rc != 0:
  echo "Error"
  session.shutdown()

var bytecount = 0
while true:
  var buffer: array[0..1024, char]
  rc = channel.channelRead(addr buffer, buffer.len)
  if rc > 0:
    bytecount += rc
    var res = ""
    for i in 0..rc-1:
      res.add(buffer[i])
    echo "We read: ", res
  if rc == LIBSSH2_ERROR_EAGAIN:
    discard waitsocket(sock.getFd(), session)
  else:
    break

var  exitcode = 127
while true:
  rc = channel.channelClose()
  if rc == LIBSSH2_ERROR_EAGAIN:
    discard waitsocket(sock.getFd(), session)
  else:
    break

var exitsignal: cstring

if rc == 0:
  exitcode = channel.channelGetExitStatus()
  discard channel.channelGetExitSignal(exitSignal, 0, nil, 0, nil, 0)

if not exitSignal.isNil:
  echo "Got sinal: ", exitSignal
else:
  echo "EXIT: ", exitcode, " bytecount: ", bytecount

discard channel.channelFree()
