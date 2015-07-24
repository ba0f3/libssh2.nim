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

const
  LIBSSH2_HOSTKEY_HASH_MD5* = 1
  LIBSSH2_HOSTKEY_HASH_SHA1* = 2

{.pragma: ssh2,
  cdecl,
  dynlib: libname,
  importc: "libssh2_$1"
.}


proc agent_connect*(a: Agent): int {.ssh2.}
proc agent_disconnect*(a: Agent): int {.ssh2.}
proc agent_free*(a: Agent) {.ssh2.}
proc agent_get_identity*(a: Agent, store: ptr AgentPublicKey, prev: AgentPublicKey) {.ssh2.}
proc agent_init*(s: Session): Agent {.ssh2.}
proc agent_list_identities*(a: Agent): int {.ssh2.}
proc agent_userauth*(a: Agent, username: cstring, identity: AgentPublicKey): int {.ssh2.}
proc banner_set*(s: Session, banner: cstring): int {.ssh2.}

proc channel_close*(c: Channel): int {.ssh2.}
proc channel_direct_tcpip_ex*(s: Session, host: cstring, port: int, shost: cstring, sport: int): Channel {.ssh2.}
proc channel_eof*(c: Channel): int {.ssh2.}
proc channel_flush_ex*(c: Channel, command: cstring): int {.ssh2.}
proc channel_forward_accept*(listener: Listener): Channel {.ssh2.}
proc channel_forward_cancel*(listener: Listener): int {.ssh2.}
proc channel_forward_listen_ex*(s: Session, host: cstring, port: int, boundPort: int, queueMaxsize: int): Listener {.ssh2.}
proc channel_free*(c: Channel): int {.ssh2.}
proc channel_get_exit_signal*(c: Channel, exitSignal: cstring, exitSignalLen: int, errmsg: cstring, errmsgLen: int, langtag: cstring, langtagLen: int): int {.ssh2.}
proc channel_get_exit_status*(c: Channel): int {.ssh2.}
proc channel_handle_extended_data2*(c: Channel, ignoreMode: int): int {.ssh2.}
proc channel_handle_extended_data*(c: Channel, ignoreMode: int) {.ssh2.}
proc channel_open_ex*(s: Session, channelType: cstring, channelTypeLen: uint, windowSize: uint, packetSize: uint, message: cstring, messageLen: uint): Channel {.ssh2.}
proc channel_process_startup*(c: Channel, request: cstring, requestLen: uint, message: string, messageLen: uint): int {.ssh2.}
proc channel_read_ex*(c: Channel, streamId: int, buf: cstring, bufLen: int): int {.ssh2.}
proc channel_receive_window_adjust2*(c: Channel, adjustment: uint64, force: char, window: uint): int {.ssh2.}
proc channel_receive_window_adjust*(c: Channel, adjustment: uint64, force: char): uint64 {.ssh2.}
proc channel_request_pty_ex*(s: Session, term: cstring): int {.ssh2.}
proc channel_request_pty_size_ex*() {.ssh2.}
proc channel_send_eof*() {.ssh2.}
proc channel_set_blocking*() {.ssh2.}
proc channel_setenv_ex*() {.ssh2.}
proc channel_wait_closed*() {.ssh2.}
proc channel_wait_eof*() {.ssh2.}
proc channel_window_read_ex*() {.ssh2.}
proc channel_window_write_ex*() {.ssh2.}
proc channel_write_ex*() {.ssh2.}
proc channel_x11_req_ex*() {.ssh2.}
proc exit*() {.ssh2.}
proc free*() {.ssh2.}
proc hostkey_hash*(s: Session, hashType: int): cstring {.ssh2.}
proc init*(flags: int): int {.ssh2.}
proc keepalive_config*() {.ssh2.}
proc keepalive_send*() {.ssh2.}
proc knownhost_add*() {.ssh2.}
proc knownhost_addc*() {.ssh2.}
proc knownhost_check*() {.ssh2.}
proc knownhost_checkp*() {.ssh2.}
proc knownhost_del*() {.ssh2.}
proc knownhost_free*() {.ssh2.}
proc knownhost_get*() {.ssh2.}
proc knownhost_init*() {.ssh2.}
proc knownhost_readfile*() {.ssh2.}
proc knownhost_readline*() {.ssh2.}
proc knownhost_writefile*() {.ssh2.}
proc knownhost_writeline*() {.ssh2.}
proc poll*() {.ssh2.}
proc poll_channel_read*() {.ssh2.}
proc publickey_add_ex*() {.ssh2.}
proc publickey_init*() {.ssh2.}
proc publickey_list_fetch*() {.ssh2.}
proc publickey_list_free*() {.ssh2.}
proc publickey_remove_ex*() {.ssh2.}
proc publickey_shutdown*() {.ssh2.}
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
  result = session_init_ex(0, 0, 0, 0)

#proc session_init*(): Session {.cdecl, dynlib: libname, importc:"libssh2_session_init".}
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
