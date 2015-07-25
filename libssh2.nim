import rawsockets

when defined(windows):
  const
    libname = "libssh2.dll"
elif defined(macosx):
  const
    libname = "libssh2.1.dylib"
elif defined(unix):
  const
    libname = "libssh2.so"
type
  SSH2Struct {.final, pure.} = object
  Agent* = ptr SSH2Struct
  AgentPublicKey* = ptr SSH2Struct
  Session* = ptr SSH2Struct
  Channel* = ptr SSH2Struct
  Listener* = ptr SSH2Struct
  KnownHosts* = ptr SSH2Struct
  PollFd* = ptr SSH2Struct
  PublicKey* = ptr SSH2Struct

  knownhost_st* {.final, pure.} = object
    magic*: cint
    node*: ptr int
    name: cstring
    key: cstring
    typemask: cint

  publickey_attribute_st* {.final, pure.} = object
    name*: cstring
    nameLen*: culong
    value*: cstring
    valueLen*: culong
    mandatory*: cchar

  publickey_list_st* {.final, pure.} = object
    packet*: cchar
    name*: cstring
    nameLen*: culong
    blob*: cstring
    blobLen*: culong
    attrs*: publickey_attribute_st


const
  LIBSSH2_HOSTKEY_HASH_MD5* = 1
  LIBSSH2_HOSTKEY_HASH_SHA1* = 2

  SSH_EXTENDED_DATA_STDERR* = 1

  # Channel API
  LIBSSH2_CHANNEL_WINDOW_DEFAULT* = (2*1024*1024)
  LIBSSH2_CHANNEL_PACKET_DEFAULT* = 32768
  LIBSSH2_CHANNEL_MINADJUST* = 1024

  # Extended Data Handling
  LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL* = 0
  LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE* = 1
  LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE* = 2

  # Defaults for pty requests
  LIBSSH2_TERM_WIDTH* = 80
  LIBSSH2_TERM_HEIGHT* = 24
  LIBSSH2_TERM_WIDTH_PX* = 0
  LIBSSH2_TERM_HEIGHT_PX* = 0

{.pragma: ssh2,
  cdecl,
  dynlib: libname,
  importc: "libssh2_$1"
.}


proc agent_connect*(a: Agent): int {.ssh2.}
  ## Connect to an ssh-agent running on the system.
  ##
  ## Returns 0 if succeeded, or a negative value for error.

proc agent_disconnect*(a: Agent): int {.ssh2.}

proc agent_free*(a: Agent) {.ssh2.}

proc agent_get_identity*(a: Agent, store: ptr AgentPublicKey, prev: AgentPublicKey) {.ssh2.}

proc agent_init*(s: Session): Agent {.ssh2.}

proc agent_list_identities*(a: Agent): int {.ssh2.}

proc agent_userauth*(a: Agent, username: cstring, identity: AgentPublicKey): int {.ssh2.}

proc banner_set*(s: Session, banner: cstring): int {.ssh2.}

proc channel_close*(c: Channel): int {.ssh2.}

proc channel_direct_tcpip_ex*(s: Session, host: cstring, port: int, shost: cstring, sport: int): Channel {.ssh2.}

proc channel_direct_tcpip*(s: Session, host: cstring, port: int): Channel {.inline.} =
  s.channel_direct_tcpip_ex(host, port, "127.0.0.1", 22)

proc channel_eof*(c: Channel): int {.ssh2.}

proc channel_flush_ex*(c: Channel, streamId: int): int {.ssh2.}

proc channel_flush*(c: Channel): int {.inline.} =
  c.channel_flush_ex(0)

proc channel_flush_stderr*(c: Channel): int {.inline.} =
  c.channel_flush_ex(SSH_EXTENDED_DATA_STDERR)

proc channel_forward_accept*(listener: Listener): Channel {.ssh2.}

proc channel_forward_cancel*(listener: Listener): int {.ssh2.}

proc channel_forward_listen_ex*(s: Session, host: cstring, port: int, boundPort: int, queueMaxsize: int): Listener {.ssh2.}

proc channel_forward_listen*(s: Session, port: int): Listener {.inline.} =
  s.channel_forward_listen_ex(nil, port, 0, 16)

proc channel_free*(c: Channel): int {.ssh2.}

proc channel_get_exit_signal*(c: Channel, exitSignal: cstring, exitSignalLen: int, errmsg: cstring, errmsgLen: int, langtag: cstring, langtagLen: int): int {.ssh2.}

proc channel_get_exit_status*(c: Channel): int {.ssh2.}

proc channel_handle_extended_data2*(c: Channel, ignoreMode: int): int {.ssh2.}

proc channel_handle_extended_data*(c: Channel, ignoreMode: int) {.ssh2.}

proc channel_ignore_extended_data*(c: Channel, ignoreMode: int) {.inline.} =
  if ignoreMode == 0:
    c.channel_handle_extended_data(LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE)
  else:
    c.channel_handle_extended_data(LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL)

proc channel_open_ex*(s: Session, channelType: cstring, channelTypeLen: uint, windowSize: uint, packetSize: uint, message: cstring, messageLen: uint): Channel {.ssh2.}

proc channel_open_session*(s: Session): Channel {.inline.} =
  let channelType: cstring = "session"
  s.channel_open_ex(channelType, channelType.len.uint, LIBSSH2_CHANNEL_WINDOW_DEFAULT, LIBSSH2_CHANNEL_PACKET_DEFAULT, nil, 0)

proc channel_process_startup*(c: Channel, request: cstring, requestLen: uint, message: cstring, messageLen: uint): int {.ssh2.}

proc channel_read_ex*(c: Channel, streamId: int, buf: var cstring, bufLen: int): int {.ssh2.}

proc channel_read*(c: Channel, buf: var cstring, bufLen: int): int {.inline.} =
  c.channel_read_ex(0, buf, bufLen)

proc channel_read_stderr*(c: Channel, buf: var cstring, bufLen: int): int {.inline.} =
  c.channel_read_ex(SSH_EXTENDED_DATA_STDERR, buf, bufLen)

proc channel_receive_window_adjust2*(c: Channel, adjustment: uint64, force: char, window: uint): int {.ssh2.}

proc channel_receive_window_adjust*(c: Channel, adjustment: uint64, force: char): uint64 {.ssh2.}

proc channel_request_pty_ex*(s: Session, term: cstring, termLen: uint, modes: cstring, modeLen: uint, width, height, widthPx, heightPx: int): int {.ssh2.}

proc channel_request_pty*(s: Session, term: cstring): int {.inline.} =
  s.channel_request_pty_ex(term, term.len.uint, nil, 0, LIBSSH2_TERM_WIDTH, LIBSSH2_TERM_HEIGHT, LIBSSH2_TERM_WIDTH_PX, LIBSSH2_TERM_HEIGHT_PX)

proc channel_request_pty_size_ex*(c: Channel, width, height, widthPx, heightPx: int): int {.ssh2.}

proc channel_request_pty_size*(c: Channel, width, height: int): int {.inline.} =
  c.channel_request_pty_size_ex(width, height, 0, 0)

proc channel_send_eof*(c: Channel): int {.ssh2.}
  ## Tell the remote host that no further data will be sent on the specified channel.
  ## Processes typically interpret this as a closed stdin descriptor.
  ##
  ## Return 0 on success or negative on failure.
  ## It returns LIBSSH2_ERROR_EAGAIN when it would otherwise block.
  ## While LIBSSH2_ERROR_EAGAIN is a negative number, it isn't really a failure per se.

proc channel_set_blocking*(c: Channel, blocking: int) {.ssh2.}
  ## set or clear blocking mode on channel

proc channel_setenv_ex*(c: Channel, varname: cstring, varnameLen: uint, value: cstring, valueLen: uint): int {.ssh2.}

proc channel_setenv*(c: Channel, name, value: cstring): int {.inline.} =
  c.channel_setenv_ex(name, name.len.uint, value, value.len.uint)

proc channel_shell*(c: Channel): int {.inline.} =
  let command: cstring = "shell"
  c.channel_process_startup(command, command.len.uint, nil, 0)

proc channel_subsystem*(c: Channel, subsystem: cstring): int {.inline.} =
  let command: cstring = "subsystem"
  c.channel_process_startup(command, command.len.uint, subsystem, subsystem.len.uint)

proc channel_wait_closed*(c: Channel): int {.ssh2.}

proc channel_wait_eof*(c: Channel): int {.ssh2.}

proc channel_window_read_ex*(c: Channel, readAvail, windowSizeInitial: uint64): uint64 {.ssh2.}

proc channel_window_read*(c: Channel): uint64 {.inline.} =
  c.channel_window_read_ex(0, 0)

proc channel_window_write_ex*(c: Channel, windowSizeInitial: uint64): uint64 {.ssh2.}

proc channel_window_write*(c: Channel): uint64 {.inline.} =
  c.channel_window_write_ex(0)

proc channel_write_ex*(c: Channel, streamId: int, buf: cstring, bufLen: int): int {.ssh2.}

proc channel_write*(c: Channel, buf: cstring, bufLen: int): int {.inline.} =
  c.channel_write_ex(0, buf, bufLen)

proc channel_write_stderr*(c: Channel, buf: cstring, bufLen: int): int {.inline.} =
  c.channel_write_ex(SSH_EXTENDED_DATA_STDERR, buf, bufLen)

proc channel_x11_req_ex*(c: Channel, singleConnection: int, authProto, authCookie: cstring, screenNumber: int): int {.ssh2.}

proc channel_x11_req*(c: Channel, screenNumber: int): int {.inline.} =
  c.channel_x11_req_ex(0, nil, nil, screenNumber)

proc exit*() {.ssh2.}

proc free*() {.ssh2.}

proc hostkey_hash*(s: Session, hashType: int): cstring {.ssh2.}

proc init*(flags: int): int {.ssh2.}

proc keepalive_config*(s: Session, waitReply: int, interval: uint) {.ssh2.}

proc keepalive_send*(s: Session, secondsToNext: int): int {.ssh2.}

proc knownhost_add*(h: KnownHosts, host, salt, key: cstring, keyLen: int, typeMask: int, kh: knownhost_st): int {.ssh2.}

proc knownhost_addc*(h: KnownHosts, host, salt, key: cstring, keyLen: int, comment: cstring, commentLen, typemask: int, kh: knownhost_st): int {.ssh2.}

proc knownhost_check*(h: KnownHosts, host, key: cstring, keyLen, typeMask, int, kh: knownhost_st): int {.ssh2.}

proc knownhost_checkp*(h: KnownHosts, host: cstring, port: int, key: cstring, keyLen, typeMask: int, kh: knownhost_st): int {.ssh2.}

proc knownhost_del*(h: KnownHosts, kh: knownhost_st): int {.ssh2.}

proc knownhost_free*(h: KnownHosts) {.ssh2.}

proc knownhost_get*(h: KnownHosts, store: var knownhost_st, prev: knownhost_st) {.ssh2.}

proc knownhost_init*(s: Session): KnownHosts {.ssh2.}

proc knownhost_readfile*(h: KnownHosts, filename: cstring, typ: int): int {.ssh2.}

proc knownhost_readline*(h: KnownHosts, line: cstring, lineLen, typ, int): int {.ssh2.}

proc knownhost_writefile*(h: KnownHosts, filename: cstring, typ: int) {.ssh2.}

proc knownhost_writeline*(h: KnownHosts, known: knownhost_st, buf: cstring, bufLen, outLen, typ: int) {.ssh2.}

proc poll*(fds: PollFd, nfds: uint, timeout: int64): int {.ssh2.}

proc poll_channel_read*(c: Channel, extended: int): int {.ssh2.}

proc publickey_add_ex*(p: PublicKey, name: cstring, nameLen: int, blob: cstring, blobLen: int, overwrite: int, numAttrs: uint64, attrs: openArray[publickey_attribute_st]): int {.ssh2.}

proc publickey_add*(p: PublicKey, name: cstring, blob: cstring, blobLen: int, overwrite: int, numAttrs: uint64, attrs: openArray[publickey_attribute_st]): int {.inline.} =
  p.publickey_add_ex(name, name.len, blob, blobLen, overwrite, numAttrs, attrs)

proc publickey_init*(s: Session): PublicKey {.ssh2.}

proc publickey_list_fetch*(p: PublicKey, numKeys: uint64, pkeyList: var publickey_list_st): int {.ssh2.}

proc publickey_list_free*(p: PublicKey, pkeyList: publickey_list_st) {.ssh2.}

proc publickey_remove_ex*(p: PublicKey, name: cstring, nameLen: int, blob: cstring, blobLen: int): int {.ssh2.}

proc publickey_remove*(p: PublicKey, name, blob: cstring, blobLen: int): int {.inline.} =
  p.publickey_remove_ex(name, name.len, blob, blobLen)

proc publickey_shutdown*(p: PublicKey): int {.ssh2.}

proc scp_recv*() {.ssh2.}

proc scp_send_ex*() {.ssh2.}

proc session_abstract*() {.ssh2.}

proc session_banner_get*() {.ssh2.}

proc session_banner_set*() {.ssh2.}

proc session_block_directions*() {.ssh2.}

proc session_callback_set*() {.ssh2.}

proc session_disconnect_ex*() {.ssh2.}

proc session_flag*() {.ssh2.}

proc session_free*() {.ssh2.}

proc session_get_blocking*() {.ssh2.}

proc session_get_timeout*() {.ssh2.}

proc session_handshake*(s: Session, fd: SocketHandle): int {.ssh2.}

proc session_hostkey*() {.ssh2.}

proc session_init_ex*(a, b, c, d: int): Session {.ssh2.}

proc session_init*(): Session =
  session_init_ex(0, 0, 0, 0)

proc session_last_errno*() {.ssh2.}

proc session_last_error*() {.ssh2.}

proc session_method_pref*() {.ssh2.}

proc session_methods*() {.ssh2.}

proc session_set_blocking*() {.ssh2.}

proc session_set_timeout*() {.ssh2.}

proc session_startup*() {.ssh2.}

proc session_supported_algs*() {.ssh2.}

proc sftp_close_handle*() {.ssh2.}

proc sftp_fstat_ex*() {.ssh2.}

proc sftp_fstatvfs*() {.ssh2.}

proc sftp_get_channel*() {.ssh2.}

proc sftp_init*() {.ssh2.}

proc sftp_last_error*() {.ssh2.}

proc sftp_mkdir_ex*() {.ssh2.}

proc sftp_open_ex*() {.ssh2.}

proc sftp_read*() {.ssh2.}

proc sftp_readdir_ex*() {.ssh2.}

proc sftp_rename_ex*() {.ssh2.}

proc sftp_rmdir_ex*() {.ssh2.}

proc sftp_seek*() {.ssh2.}

proc sftp_seek64*() {.ssh2.}

proc sftp_shutdown*() {.ssh2.}

proc sftp_stat_ex*() {.ssh2.}

proc sftp_statvfs*() {.ssh2.}

proc sftp_symlink_ex*() {.ssh2.}

proc sftp_tell*() {.ssh2.}

proc sftp_tell64*() {.ssh2.}

proc sftp_unlink_ex*() {.ssh2.}

proc sftp_write*() {.ssh2.}

proc trace*() {.ssh2.}

proc trace_sethandler*() {.ssh2.}

proc userauth_authenticated*() {.ssh2.}

proc userauth_hostbased_fromfile_ex*() {.ssh2.}

proc userauth_keyboard_interactive_ex*() {.ssh2.}

proc userauth_list*(s: Session, username: cstring, usernameLen: int): cstring {.ssh2.}

proc userauth_password_ex*() {.ssh2.}

proc userauth_publickey*() {.ssh2.}

proc userauth_publickey_fromfile_ex*() {.ssh2.}

proc version*(version: int): cstring {.ssh2.}


when isMainModule:
  echo "libssh2 version: ", version(0)
