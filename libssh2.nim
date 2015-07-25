import posix
import times
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

  Sftp* = ptr SSH2Struct
  SftpHandle* = ptr SSH2Struct
  SftpAttributes* = ptr SSH2Struct
  SftpStatVFS* = ptr SSH2Struct

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

  # Disconnect Codes (defined by SSH protocol)
  SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT* = 1
  SSH_DISCONNECT_PROTOCOL_ERROR* = 2
  SSH_DISCONNECT_KEY_EXCHANGE_FAILED* = 3
  SSH_DISCONNECT_RESERVED* = 4
  SSH_DISCONNECT_MAC_ERROR* = 5
  SSH_DISCONNECT_COMPRESSION_ERROR* = 6
  SSH_DISCONNECT_SERVICE_NOT_AVAILABLE* = 7
  SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED* = 8
  SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE* = 9
  SSH_DISCONNECT_CONNECTION_LOST* = 10
  SSH_DISCONNECT_BY_APPLICATION* = 11
  SSH_DISCONNECT_TOO_MANY_CONNECTIONS* = 12
  SSH_DISCONNECT_AUTH_CANCELLED_BY_USER* = 13
  SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE* = 14
  SSH_DISCONNECT_ILLEGAL_USER_NAME* = 15

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

proc scp_recv*(s: Session, path: cstring, sb: TStat) {.ssh2.}

proc scp_send_ex*(s: Session, path: cstring, mode, size: int, mtime, atime: int64): Channel {.ssh2.}

proc scp_send*(s: Session, path: cstring, mode, size: int): Channel {.inline.} =
  s.scp_send_ex(path, mode, size, 0, 0)

proc scp_send64*(s: Session, path: cstring, mode: int, size: uint64, mtime, atime: Time): Channel {.ssh2.}

proc session_abstract*(s: Session): ptr Session {.ssh2.}

proc session_banner_get*(s: Session): cstring {.ssh2.}

proc session_banner_set*(s: Session, banner: cstring): int {.ssh2.}

proc session_block_directions*(s: Session): int {.ssh2.}

proc session_callback_set*(s: Session, cbtype: int, f: ptr) {.ssh2.}

proc session_disconnect_ex*(s: Session, reason: int, description, lang: cstring): int {.ssh2.}

proc session_disconnect*(s: Session, description: cstring): int {.inline.} =
  s.session_disconnect_ex(SSH_DISCONNECT_BY_APPLICATION, description, "")

proc session_flag*(s: Session, flag, value: int): int {.ssh2.}

proc session_free*(s: Session): int {.ssh2.}

proc session_get_blocking*(s: Session): int {.ssh2.}

proc session_get_timeout*(s: Session): int64 {.ssh2.}

proc session_handshake*(s: Session, fd: SocketHandle): int {.ssh2.}

proc session_hostkey*(s: Session, length, typ: int): cstring {.ssh2.}

proc session_init_ex*(a, b, c, d: int): Session {.ssh2.}

proc session_init*(): Session =
  session_init_ex(0, 0, 0, 0)

proc session_last_errno*(s: Session): int {.ssh2.}

proc session_last_error*(s: Session, errormsg: var cstring, errmsgLen, wantBuf: int): int {.ssh2.}

proc session_method_pref*(s: Session, methodType: int, prefs: cstring): int {.ssh2.}

proc session_methods*(s: Session, methodType: int): cstring {.ssh2.}

proc session_set_blocking*(s: Session, blocking: int) {.ssh2.}

proc session_set_timeout*(s: Session, timeout: uint) {.ssh2.}

proc session_startup*(s: Session, socket: int): int {.ssh2.}

proc session_supported_algs*(s: Session, methodType: int, algs: var cstring) {.ssh2.}

proc sftp_close_handle*(h: SftpHandle): int {.ssh2.}

proc sftp_close*(h: SftpHandle): int {.inline.} =
  h.sftp_close_handle()

proc sftp_closedir*(h: SftpHandle): int {.inline.} =
  h.sftp_close_handle()

proc sftp_fstat_ex*(h: SftpHandle, attrs: SftpAttributes, setstat: int): int {.ssh2.}

proc sftp_fstat*(h: SftpHandle, attrs: SftpAttributes): int {.inline.} =
  h.sftp_fstat_ex(attrs, 0)

proc sftp_fsetstat*(h: SftpHandle, attrs: SftpAttributes): int {.inline.} =
  h.sftp_fstat_ex(attrs, 1)

proc sftp_fstatvfs*(h: SftpHandle, path: cstring, pathLen: int, st: SftpStatVFS) {.ssh2.}

proc sftp_fsync*(h: SftpHandle): int {.ssh2.}

proc sftp_get_channel*(s: Sftp): Channel {.ssh2.}

proc sftp_init*(s: Session): Sftp {.ssh2.}

proc sftp_last_error*(s: Sftp): uint64 {.ssh2.}

proc sftp_lstat(s: Sftp, path: cstring, attrs: SftpAttributes): int {.ssh2.}

proc sftp_mkdir_ex*(s: Sftp, path: cstring, pathLen: uint, mode: uint64): int {.ssh2.}

proc sftp_mkdir*(s: Sftp, path: cstring, mode: uint64): int {.inline.} =
  s.sftp_mkdir_ex(path, path.len.uint, mode)

proc sftp_open_ex*(s: Sftp, filename: cstring, filenameLen: uint, flags: uint64, mode: int64, openType: int): SftpHandle {.ssh2.}

proc sftp_open*(s: Sftp, filename: cstring, flags: uint64, mode: uint64): SftpHandle {.inline.} =
  s.sftp_open_ex(filename, filename.len.uint, 0, 0, LIBSSH2_SFTP_OPENFILE)

proc sftp_opendir*(s: Sftp, filename: cstring, flags: uint64, mode: uint64): SftpHandle {.inline.} =
  s.sftp_open_ex(filename, filename.len.uint, 0, 0, LIBSSH2_SFTP_OPENDIR)

proc sftp_read*(h: SftpHandle, buf: ptr cstring, bufMaxLen: int): int {.ssh2.}

proc sftp_readdir_ex*(h: SftpHandle, buf: ptr cstring, bufMaxLen: int, longEntry: ptr cstring, longEntryMaxLen: int, attrs: ptr SftpAttributes): int {.ssh2.}

proc sftp_readdir*(h: SftpHandle, buf: ptr cstring, bufMaxLen: int, attrs: ptr SftpAttributes): int {.inline.} =
  h.sftp_readdir_ex(buf, bufMaxLen, nil, 0, attrs)

proc sftp_symlink_ex*(s: Sftp, path: cstring, pathLen: uint, target: pointer, targetLen: uint, linkType: int): int {.ssh2.}

proc sftp_readlink*(h: Sftp, path: cstring, target: pointer, maxLen: uint): int {.inline.} =
  h.sftp_symlink_ex(path, path.len.uint, target, maxLen, LIBSSH2_SFTP_READLINK)

proc sftp_realpath*(h: Sftp, path: cstring, target: pointer, maxLen: uint): int {.inline.} =
  h.sftp_symlink_ex(path, path.len.uint, target, maxLen, LIBSSH2_SFTP_REALPATH)

proc sftp_rename_ex*(s: Sftp, source: cstring, sourceLen: uint, dest: cstring, destLen: uint, flags: int64): int {.ssh2.}

proc sftp_rename*(s: Sftp, source, dest: cstring): int {.inline.} =
  s.sftp_rename_ex(source, source.len.uint, dest, dest.len.uint,  LIBSSH2_SFTP_RENAME_OVERWRITE or LIBSSH2_SFTP_RENAME_ATOMIC o LIBSSH2_SFTP_RENAME_NATIVE)

proc sftp_rmdir_ex*(s: Sftp, path: cstring, pathLen: uint): int {.ssh2.}

proc sftp_rmdir*(s: Sftp, path: cstring): int {.inline.} =
  s.sftp_rmdir_ex(path, path.len.uint)

proc sftp_seek*(h: SftpHandle, offset: int) {.ssh2.}

proc sftp_seek64*(h: SftpHandle, offset: int64) {.ssh2.}

proc sftp_rewind*(h: SftpHandle) {.inline.} =
  h.sftp_seek64(0)

proc sftp_shutdown*(s: Sftp): int {.ssh2.}

proc sftp_stat_ex*(h: SftpHandle, attrs: pointer, setstat: int): int {.ssh2.}

proc sftp_stat(h: SftpHandle, path: cstring, attrs: pointer): int {.inline.} =
  sftp_stat_ex(h, attrs, 0)

proc sftp_setstat(h: SftpHandle, path: cstring, attrs: pointer): int {.inline.} =
  sftp_stat_ex(h, attrs, 1)

proc sftp_statvfs*(s: Sftp, path: cstring, pathLen: int, st: ptr SftpAttributes) {.ssh2.}

proc sftp_fstatvfs*(h: SftpHandle, st: ptr SftpAttributes) {.ssh2.}

proc sftp_symlink*(s: Sftp, orig, linkPath: cstring): int {.inline.} =
  sftp_symlink_ex(s, orig, orig.len.uint, linkPath, linkPath.len.uint, LIBSSH2_SFTP_SYMLINK)

proc sftp_tell*(h: SftpHandle): int {.ssh2.}

proc sftp_tell64*(h: SftpHandle): int64 {.ssh2.}

proc sftp_unlink_ex*(s: Sftp, filename: cstring, filenameLen: uint): int {.ssh2.}

proc sftp_unlink*(s: Sftp, filename: cstring): int {.inline.} =
  sftp_unlink_ex(s, filename, filename.len.uint)

proc sftp_write*(h: SftpHandle, buf: pointer, count: int): int {.ssh2.}

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
