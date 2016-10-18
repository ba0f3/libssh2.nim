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

{.pragma: ssh2,
  cdecl,
  dynlib: libname,
  importc: "libssh2_$1"
.}


type
  Function* = proc () {.cdecl.}
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

  knownhost_st* {.final, pure.} = ref object
    magic*: cint
    node*: ptr int
    name*: cstring
    key*: cstring
    typemask*: cint

  publickey_attribute_st* {.final, pure.} = ref object
    name*: cstring
    nameLen*: culong
    value*: cstring
    valueLen*: culong
    mandatory*: cchar

  publickey_list_st* {.final, pure.} = ref object
    packet*: cchar
    name*: cstring
    nameLen*: culong
    blob*: cstring
    blobLen*: culong
    attrs*: publickey_attribute_st

  passwd_changereq_func* = proc(session: Session, newpw: ptr cstring, newpwLen: int, abstract: pointer) {.cdecl.}


const
  LIBSSH2_INVALID_SOCKET* = -1
  LIBSSH2_DH_GEX_MINGROUP* = 1024
  LIBSSH2_DH_GEX_OPTGROUP* = 1536
  LIBSSH2_DH_GEX_MAXGROUP* = 2048
  LIBSSH2_TERM_WIDTH* = 80
  LIBSSH2_TERM_HEIGHT* = 24
  LIBSSH2_TERM_WIDTH_PX* = 0
  LIBSSH2_TERM_HEIGHT_PX* = 0
  LIBSSH2_SOCKET_POLL_UDELAY* = 250000
  LIBSSH2_SOCKET_POLL_MAXLOOPS* = 120
  LIBSSH2_PACKET_MAXCOMP* = 32000
  LIBSSH2_PACKET_MAXDECOMP* = 40000
  LIBSSH2_PACKET_MAXPAYLOAD* = 40000
  LIBSSH2_CALLBACK_IGNORE* = 0
  LIBSSH2_CALLBACK_DEBUG* = 1
  LIBSSH2_CALLBACK_DISCONNECT* = 2
  LIBSSH2_CALLBACK_MACERROR* = 3
  LIBSSH2_CALLBACK_X11* = 4
  LIBSSH2_CALLBACK_SEND* = 5
  LIBSSH2_CALLBACK_RECV* = 6
  LIBSSH2_METHOD_KEX* = 0
  LIBSSH2_METHOD_HOSTKEY* = 1
  LIBSSH2_METHOD_CRYPT_CS* = 2
  LIBSSH2_METHOD_CRYPT_SC* = 3
  LIBSSH2_METHOD_MAC_CS* = 4
  LIBSSH2_METHOD_MAC_SC* = 5
  LIBSSH2_METHOD_COMP_CS* = 6
  LIBSSH2_METHOD_COMP_SC* = 7
  LIBSSH2_METHOD_LANG_CS* = 8
  LIBSSH2_METHOD_LANG_SC* = 9
  LIBSSH2_FLAG_SIGPIPE* = 1
  LIBSSH2_FLAG_COMPRESS* = 2
  LIBSSH2_POLLFD_SOCKET* = 1
  LIBSSH2_POLLFD_CHANNEL* = 2
  LIBSSH2_POLLFD_LISTENER* = 3
  LIBSSH2_POLLFD_POLLIN* = 0x0001
  LIBSSH2_POLLFD_POLLPRI* = 0x0002
  LIBSSH2_POLLFD_POLLEXT* = 0x0002
  LIBSSH2_POLLFD_POLLOUT* = 0x0004
  LIBSSH2_POLLFD_POLLERR* = 0x0008
  LIBSSH2_POLLFD_POLLHUP* = 0x0010
  LIBSSH2_POLLFD_SESSION_CLOSED* = 0x0010
  LIBSSH2_POLLFD_POLLNVAL* = 0x0020
  LIBSSH2_POLLFD_POLLEX* = 0x0040
  LIBSSH2_POLLFD_CHANNEL_CLOSED* = 0x0080
  LIBSSH2_POLLFD_LISTENER_CLOSED* = 0x0080
  LIBSSH2_SESSION_BLOCK_INBOUND* = 0x0001
  LIBSSH2_SESSION_BLOCK_OUTBOUND* = 0x0002
  LIBSSH2_HOSTKEY_HASH_MD5* = 1
  LIBSSH2_HOSTKEY_HASH_SHA1* = 2
  LIBSSH2_HOSTKEY_TYPE_UNKNOWN* = 0
  LIBSSH2_HOSTKEY_TYPE_RSA* = 1
  LIBSSH2_HOSTKEY_TYPE_DSS* = 2
  LIBSSH2_ERROR_NONE* = 0
  LIBSSH2_ERROR_SOCKET_NONE* = -1
  LIBSSH2_ERROR_BANNER_RECV* = -2
  LIBSSH2_ERROR_BANNER_SEND* = -3
  LIBSSH2_ERROR_INVALID_MAC* = -4
  LIBSSH2_ERROR_KEX_FAILURE* = -5
  LIBSSH2_ERROR_ALLOC* = -6
  LIBSSH2_ERROR_SOCKET_SEND* = -7
  LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE* = -8
  LIBSSH2_ERROR_TIMEOUT* = -9
  LIBSSH2_ERROR_HOSTKEY_INIT* = -10
  LIBSSH2_ERROR_HOSTKEY_SIGN* = -11
  LIBSSH2_ERROR_DECRYPT* = -12
  LIBSSH2_ERROR_SOCKET_DISCONNECT* = -13
  LIBSSH2_ERROR_PROTO* = -14
  LIBSSH2_ERROR_PASSWORD_EXPIRED* = -15
  LIBSSH2_ERROR_FILE* = -16
  LIBSSH2_ERROR_METHOD_NONE* = -17
  LIBSSH2_ERROR_AUTHENTICATION_FAILED* = -18
  LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED* = LIBSSH2_ERROR_AUTHENTICATION_FAILED
  LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED* = -19
  LIBSSH2_ERROR_CHANNEL_OUTOFORDER* = -20
  LIBSSH2_ERROR_CHANNEL_FAILURE* = -21
  LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED* = -22
  LIBSSH2_ERROR_CHANNEL_UNKNOWN* = -23
  LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED* = -24
  LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED* = -25
  LIBSSH2_ERROR_CHANNEL_CLOSED* = -26
  LIBSSH2_ERROR_CHANNEL_EOF_SENT* = -27
  LIBSSH2_ERROR_SCP_PROTOCOL* = -28
  LIBSSH2_ERROR_ZLIB* = -29
  LIBSSH2_ERROR_SOCKET_TIMEOUT* = -30
  LIBSSH2_ERROR_SFTP_PROTOCOL* = -31
  LIBSSH2_ERROR_REQUEST_DENIED* = -32
  LIBSSH2_ERROR_METHOD_NOT_SUPPORTED* = -33
  LIBSSH2_ERROR_INVAL* = -34
  LIBSSH2_ERROR_INVALID_POLL_TYPE* = -35
  LIBSSH2_ERROR_PUBLICKEY_PROTOCOL* = -36
  LIBSSH2_ERROR_EAGAIN* = -37
  LIBSSH2_ERROR_BUFFER_TOO_SMALL* = -38
  LIBSSH2_ERROR_BAD_USE* = -39
  LIBSSH2_ERROR_COMPRESS* = -40
  LIBSSH2_ERROR_OUT_OF_BOUNDARY* = -41
  LIBSSH2_ERROR_AGENT_PROTOCOL* = -42
  LIBSSH2_ERROR_SOCKET_RECV* = -43
  LIBSSH2_ERROR_ENCRYPT* = -44
  LIBSSH2_ERROR_BAD_SOCKET* = -45
  LIBSSH2_ERROR_KNOWN_HOSTS* = -46
  LIBSSH2_ERROR_BANNER_NONE* = LIBSSH2_ERROR_BANNER_RECV
  LIBSSH2_INIT_NO_CRYPTO* = 0x0001
  LIBSSH2_CHANNEL_WINDOW_DEFAULT* = (2*1024*1024)
  LIBSSH2_CHANNEL_PACKET_DEFAULT* = 32768
  LIBSSH2_CHANNEL_MINADJUST* = 1024
  LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL* = 0
  LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE* = 1
  LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE* = 2
  LIBSSH2CHANNEL_EAGAIN* = LIBSSH2_ERROR_EAGAIN
  LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA* = -1
  LIBSSH2_CHANNEL_FLUSH_ALL* = -2
  LIBSSH2_KNOWNHOST_TYPE_MASK* = 0xffff
  LIBSSH2_KNOWNHOST_TYPE_PLAIN* = 1
  LIBSSH2_KNOWNHOST_TYPE_SHA1* = 2
  LIBSSH2_KNOWNHOST_TYPE_CUSTOM* = 3
  LIBSSH2_KNOWNHOST_KEYENC_MASK* = (3 shl 16)
  LIBSSH2_KNOWNHOST_KEYENC_RAW* = (1 shl 16)
  LIBSSH2_KNOWNHOST_KEYENC_BASE64* = (2 shl 16)
  LIBSSH2_KNOWNHOST_KEY_MASK* = (7 shl 18)
  LIBSSH2_KNOWNHOST_KEY_SHIFT* = 18
  LIBSSH2_KNOWNHOST_KEY_RSA1* = (1 shl 18)
  LIBSSH2_KNOWNHOST_KEY_SSHRSA* = (2 shl 18)
  LIBSSH2_KNOWNHOST_KEY_SSHDSS* = (3 shl 18)
  LIBSSH2_KNOWNHOST_KEY_UNKNOWN* = (7 shl 18)
  LIBSSH2_KNOWNHOST_CHECK_MATCH* = 0
  LIBSSH2_KNOWNHOST_CHECK_MISMATCH* = 1
  LIBSSH2_KNOWNHOST_CHECK_NOTFOUND* = 2
  LIBSSH2_KNOWNHOST_CHECK_FAILURE* = 3
  LIBSSH2_KNOWNHOST_FILE_OPENSSH* = 1
  LIBSSH2_TRACE_TRANS* = (1 shl 1)
  LIBSSH2_TRACE_KEX* = (1 shl 2)
  LIBSSH2_TRACE_AUTH* = (1 shl 3)
  LIBSSH2_TRACE_CONN* = (1 shl 4)
  LIBSSH2_TRACE_SCP* = (1 shl 5)
  LIBSSH2_TRACE_SFTP* = (1 shl 6)
  LIBSSH2_TRACE_ERROR* = (1 shl 7)
  LIBSSH2_TRACE_PUBLICKEY* = (1 shl 8)
  LIBSSH2_TRACE_SOCKET* = (1 shl 9)
  LIBSSH2_SFTP_OPENFILE* = 0
  LIBSSH2_SFTP_OPENDIR* = 1
  LIBSSH2_SFTP_RENAME_OVERWRITE* = 0x00000001
  LIBSSH2_SFTP_RENAME_ATOMIC* = 0x00000002
  LIBSSH2_SFTP_RENAME_NATIVE* = 0x00000004
  LIBSSH2_SFTP_STAT* = 0
  LIBSSH2_SFTP_LSTAT* = 1
  LIBSSH2_SFTP_SETSTAT* = 2
  LIBSSH2_SFTP_SYMLINK* = 0
  LIBSSH2_SFTP_READLINK* = 1
  LIBSSH2_SFTP_REALPATH* = 2
  LIBSSH2_SFTP_ATTR_SIZE* = 0x00000001
  LIBSSH2_SFTP_ATTR_UIDGID* = 0x00000002
  LIBSSH2_SFTP_ATTR_PERMISSIONS* = 0x00000004
  LIBSSH2_SFTP_ATTR_ACMODTIME* = 0x00000008
  LIBSSH2_SFTP_ATTR_EXTENDED* = 0x80000000
  LIBSSH2_SFTP_ST_RDONLY* = 0x00000001
  LIBSSH2_SFTP_ST_NOSUID* = 0x00000002
  LIBSSH2_SFTP_TYPE_REGULAR* = 1
  LIBSSH2_SFTP_TYPE_DIRECTORY* = 2
  LIBSSH2_SFTP_TYPE_SYMLINK* = 3
  LIBSSH2_SFTP_TYPE_SPECIAL* = 4
  LIBSSH2_SFTP_TYPE_UNKNOWN* = 5
  LIBSSH2_SFTP_TYPE_SOCKET* = 6
  LIBSSH2_SFTP_TYPE_CHAR_DEVICE* = 7
  LIBSSH2_SFTP_TYPE_BLOCK_DEVICE* = 8
  LIBSSH2_SFTP_TYPE_FIFO* = 9
  LIBSSH2_SFTP_S_IFMT* = 0170000
  LIBSSH2_SFTP_S_IFIFO* = 0010000
  LIBSSH2_SFTP_S_IFCHR* = 0020000
  LIBSSH2_SFTP_S_IFDIR* = 0040000
  LIBSSH2_SFTP_S_IFBLK* = 0060000
  LIBSSH2_SFTP_S_IFREG* = 0100000
  LIBSSH2_SFTP_S_IFLNK* = 0120000
  LIBSSH2_SFTP_S_IFSOCK* = 0140000
  LIBSSH2_SFTP_S_IRWXU* = 0000700
  LIBSSH2_SFTP_S_IRUSR* = 0000400
  LIBSSH2_SFTP_S_IWUSR* = 0000200
  LIBSSH2_SFTP_S_IXUSR* = 0000100
  LIBSSH2_SFTP_S_IRWXG* = 0000070
  LIBSSH2_SFTP_S_IRGRP* = 0000040
  LIBSSH2_SFTP_S_IWGRP* = 0000020
  LIBSSH2_SFTP_S_IXGRP* = 0000010
  LIBSSH2_SFTP_S_IRWXO* = 0000007
  LIBSSH2_SFTP_S_IROTH* = 0000004
  LIBSSH2_SFTP_S_IWOTH* = 0000002
  LIBSSH2_SFTP_S_IXOTH* = 0000001
  LIBSSH2_FXF_READ* = 0x00000001
  LIBSSH2_FXF_WRITE* = 0x00000002
  LIBSSH2_FXF_APPEND* = 0x00000004
  LIBSSH2_FXF_CREAT* = 0x00000008
  LIBSSH2_FXF_TRUNC* = 0x00000010
  LIBSSH2_FXF_EXCL* = 0x00000020
  LIBSSH2_FX_OK* = 0
  LIBSSH2_FX_EOF* = 1
  LIBSSH2_FX_NO_SUCH_FILE* = 2
  LIBSSH2_FX_PERMISSION_DENIED* = 3
  LIBSSH2_FX_FAILURE* = 4
  LIBSSH2_FX_BAD_MESSAGE* = 5
  LIBSSH2_FX_NO_CONNECTION* = 6
  LIBSSH2_FX_CONNECTION_LOST* = 7
  LIBSSH2_FX_OP_UNSUPPORTED* = 8
  LIBSSH2_FX_INVALID_HANDLE* = 9
  LIBSSH2_FX_NO_SUCH_PATH* = 10
  LIBSSH2_FX_FILE_ALREADY_EXISTS* = 11
  LIBSSH2_FX_WRITE_PROTECT* = 12
  LIBSSH2_FX_NO_MEDIA* = 13
  LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM* = 14
  LIBSSH2_FX_QUOTA_EXCEEDED* = 15
  LIBSSH2_FX_UNKNOWN_PRINCIPLE* = 16
  LIBSSH2_FX_UNKNOWN_PRINCIPAL* = 16
  LIBSSH2_FX_LOCK_CONFlICT* = 17
  LIBSSH2_FX_DIR_NOT_EMPTY* = 18
  LIBSSH2_FX_NOT_A_DIRECTORY* = 19
  LIBSSH2_FX_INVALID_FILENAME* = 20
  LIBSSH2_FX_LINK_LOOP* = 21
  LIBSSH2SFTP_EAGAIN* = LIBSSH2_ERROR_EAGAIN


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
  SSH_EXTENDED_DATA_STDERR* = 1

proc agent_connect*(a: Agent): cint {.ssh2.}
  ## Connect to an ssh-agent running on the system.
  ##
  ## Returns 0 if succeeded, or a negative value for error.

proc agent_disconnect*(a: Agent): cint {.ssh2.}

proc agent_free*(a: Agent) {.ssh2.}

proc agent_get_identity*(a: Agent, store: ptr AgentPublicKey, prev: AgentPublicKey) {.ssh2.}

proc agent_init*(s: Session): Agent {.ssh2.}

proc agent_list_identities*(a: Agent): cint {.ssh2.}

proc agent_userauth*(a: Agent, username: cstring, identity: AgentPublicKey): cint {.ssh2.}

proc banner_set*(s: Session, banner: cstring): cint {.ssh2.}

proc channel_close*(c: Channel): cint {.ssh2.}

proc channel_direct_tcpip_ex*(s: Session, host: cstring, port: int, shost: cstring, sport: int): Channel {.ssh2.}

proc channel_direct_tcpip*(s: Session, host: cstring, port: int): Channel {.inline.} =
  channel_direct_tcpip_ex(s, host, port, "127.0.0.1", 22)

proc channel_eof*(c: Channel): cint {.ssh2.}

proc channel_flush_ex*(c: Channel, streamId: int): cint {.ssh2.}

proc channel_flush*(c: Channel): cint {.inline.} =
  channel_flush_ex(c, 0)

proc channel_flush_stderr*(c: Channel): cint {.inline.} =
  channel_flush_ex(c, SSH_EXTENDED_DATA_STDERR)

proc channel_forward_accept*(listener: Listener): Channel {.ssh2.}

proc channel_forward_cancel*(listener: Listener): cint {.ssh2.}

proc channel_forward_listen_ex*(s: Session, host: cstring, port: int, boundPort: int, queueMaxsize: int): Listener {.ssh2.}

proc channel_forward_listen*(s: Session, port: int): Listener {.inline.} =
  channel_forward_listen_ex(s, nil, port, 0, 16)

proc channel_free*(c: Channel): cint {.ssh2.}

proc channel_get_exit_signal*(c: Channel, exitSignal: cstring, exitSignalLen: int, errmsg: cstring, errmsgLen: int, langtag: cstring, langtagLen: int): cint {.ssh2.}

proc channel_get_exit_status*(c: Channel): cint {.ssh2.}

proc channel_handle_extended_data2*(c: Channel, ignoreMode: int): cint {.ssh2.}

proc channel_handle_extended_data*(c: Channel, ignoreMode: int) {.ssh2.}

proc channel_ignore_extended_data*(c: Channel, ignoreMode: int) {.inline.} =
  if ignoreMode == 0:
    channel_handle_extended_data(c, LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE)
  else:
    channel_handle_extended_data(c, LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL)

proc channel_open_ex*(s: Session, channelType: cstring, channelTypeLen: uint, windowSize: uint, packetSize: uint, message: cstring, messageLen: uint): Channel {.ssh2.}

proc channel_open_session*(s: Session): Channel {.inline.} =
  let channelType: cstring = "session"
  channel_open_ex(s, channelType, channelType.len.uint, LIBSSH2_CHANNEL_WINDOW_DEFAULT, LIBSSH2_CHANNEL_PACKET_DEFAULT, nil, 0)

proc channel_process_startup*(c: Channel, request: cstring, requestLen: uint, message: cstring, messageLen: uint): cint {.ssh2.}

proc channel_exec*(c: Channel, command: cstring): cint {.inline.} =
  let request: cstring = "exec"
  channel_process_startup(c, request, request.len.uint, command, command.len.uint)

proc channel_read_ex*(c: Channel, streamId: int, buf: pointer, bufLen: int): cint {.ssh2.}

proc channel_read*(c: Channel, buf: pointer, bufLen: int): cint {.inline.} =
  channel_read_ex(c, 0, buf, bufLen)

proc channel_read_stderr*(c: Channel, buf: var cstring, bufLen: int): cint {.inline.} =
  channel_read_ex(c, SSH_EXTENDED_DATA_STDERR, buf, bufLen)

proc channel_receive_window_adjust2*(c: Channel, adjustment: uint64, force: char, window: uint): cint {.ssh2.}

proc channel_receive_window_adjust*(c: Channel, adjustment: uint64, force: char): uint64 {.ssh2.}

proc channel_request_pty_ex*(s: Session, term: cstring, termLen: uint, modes: cstring, modeLen: uint, width, height, widthPx, heightPx: int): cint {.ssh2.}

proc channel_request_pty*(s: Session, term: cstring): cint {.inline.} =
  channel_request_pty_ex(s, term, term.len.uint, nil, 0, LIBSSH2_TERM_WIDTH, LIBSSH2_TERM_HEIGHT, LIBSSH2_TERM_WIDTH_PX, LIBSSH2_TERM_HEIGHT_PX)

proc channel_request_pty_size_ex*(c: Channel, width, height, widthPx, heightPx: int): cint {.ssh2.}

proc channel_request_pty_size*(c: Channel, width, height: int): cint {.inline.} =
  channel_request_pty_size_ex(c, width, height, 0, 0)

proc channel_send_eof*(c: Channel): cint {.ssh2.}
  ## Tell the remote host that no further data will be sent on the specified channel.
  ## Processes typically interpret this as a closed stdin descriptor.
  ##
  ## Return 0 on success or negative on failure.
  ## It returns LIBSSH2_ERROR_EAGAIN when it would otherwise block.
  ## While LIBSSH2_ERROR_EAGAIN is a negative number, it isn't really a failure per se.

proc channel_set_blocking*(c: Channel, blocking: int) {.ssh2.}
  ## set or clear blocking mode on channel

proc channel_setenv_ex*(c: Channel, varname: cstring, varnameLen: uint, value: cstring, valueLen: uint): cint {.ssh2.}

proc channel_setenv*(c: Channel, name, value: cstring): cint {.inline.} =
  channel_setenv_ex(c, name, name.len.uint, value, value.len.uint)

proc channel_shell*(c: Channel): cint {.inline.} =
  let command: cstring = "shell"
  channel_process_startup(c, command, command.len.uint, nil, 0)

proc channel_subsystem*(c: Channel, subsystem: cstring): cint {.inline.} =
  let command: cstring = "subsystem"
  channel_process_startup(c, command, command.len.uint, subsystem, subsystem.len.uint)

proc channel_wait_closed*(c: Channel): cint {.ssh2.}

proc channel_wait_eof*(c: Channel): cint {.ssh2.}

proc channel_window_read_ex*(c: Channel, readAvail, windowSizeInitial: uint64): uint64 {.ssh2.}

proc channel_window_read*(c: Channel): uint64 {.inline.} =
  channel_window_read_ex(c, 0, 0)

proc channel_window_write_ex*(c: Channel, windowSizeInitial: uint64): uint64 {.ssh2.}

proc channel_window_write*(c: Channel): uint64 {.inline.} =
  channel_window_write_ex(c, 0)

proc channel_write_ex*(c: Channel, streamId: int, buf: cstring, bufLen: int): cint {.ssh2.}

proc channel_write*(c: Channel, buf: cstring, bufLen: int): cint {.inline.} =
  channel_write_ex(c, 0, buf, bufLen)

proc channel_write_stderr*(c: Channel, buf: cstring, bufLen: int): cint {.inline.} =
  channel_write_ex(c, SSH_EXTENDED_DATA_STDERR, buf, bufLen)

proc channel_x11_req_ex*(c: Channel, singleConnection: int, authProto, authCookie: cstring, screenNumber: int): cint {.ssh2.}

proc channel_x11_req*(c: Channel, screenNumber: int): cint {.inline.} =
  channel_x11_req_ex(c, 0, nil, nil, screenNumber)

proc exit*() {.ssh2.}

proc free*() {.ssh2.}

proc hostkey_hash*(s: Session, hashType: int): cstring {.ssh2.}

proc init*(flags: int): cint {.ssh2.}

proc keepalive_config*(s: Session, waitReply: int, interval: uint) {.ssh2.}

proc keepalive_send*(s: Session, secondsToNext: int): cint {.ssh2.}

proc knownhost_add*(h: KnownHosts, host, salt, key: cstring, keyLen: int, typeMask: int, kh: knownhost_st): cint {.ssh2, deprecated.}

proc knownhost_addc*(h: KnownHosts, host, salt, key: cstring, keyLen: int, comment: cstring, commentLen, typemask: int, kh: ptr knownhost_st): cint {.ssh2.}

proc knownhost_check*(h: KnownHosts, host, key: cstring, keyLen, typeMask, int, kh: knownhost_st): cint {.ssh2.}

proc knownhost_checkp*(h: KnownHosts, host: cstring, port: int, key: cstring, keyLen, typeMask: int, kh: ptr knownhost_st): cint {.ssh2.}

proc knownhost_del*(h: KnownHosts, kh: knownhost_st): cint {.ssh2.}

proc knownhost_free*(h: KnownHosts) {.ssh2.}

proc knownhost_get*(h: KnownHosts, store: ptr knownhost_st, prev: knownhost_st) {.ssh2.}

proc knownhost_init*(s: Session): KnownHosts {.ssh2.}

proc knownhost_readfile*(h: KnownHosts, filename: cstring, typ: int): cint {.ssh2.}

proc knownhost_readline*(h: KnownHosts, line: cstring, lineLen, typ: int): cint {.ssh2.}

proc knownhost_writefile*(h: KnownHosts, filename: cstring, typ: int) {.ssh2.}

proc knownhost_writeline*(h: KnownHosts, known: knownhost_st, buf: cstring, bufLen, outLen, typ: int) {.ssh2.}

proc poll*(fds: PollFd, nfds: uint, timeout: int64): cint {.ssh2.}

proc poll_channel_read*(c: Channel, extended: int): cint {.ssh2.}

proc publickey_add_ex*(p: PublicKey, name: cstring, nameLen: int, blob: cstring, blobLen: int, overwrite: int, numAttrs: uint64, attrs: openArray[publickey_attribute_st]): cint {.ssh2.}

proc publickey_add*(p: PublicKey, name: cstring, blob: cstring, blobLen: int, overwrite: int, numAttrs: uint64, attrs: openArray[publickey_attribute_st]): cint {.inline.} =
  publickey_add_ex(p, name, name.len, blob, blobLen, overwrite, numAttrs, attrs)

proc publickey_init*(s: Session): PublicKey {.ssh2.}

proc publickey_list_fetch*(p: PublicKey, numKeys: uint64, pkeyList: var publickey_list_st): cint {.ssh2.}

proc publickey_list_free*(p: PublicKey, pkeyList: publickey_list_st) {.ssh2.}

proc publickey_remove_ex*(p: PublicKey, name: cstring, nameLen: int, blob: cstring, blobLen: int): cint {.ssh2.}

proc publickey_remove*(p: PublicKey, name, blob: cstring, blobLen: int): cint {.inline.} =
  publickey_remove_ex(p, name, name.len, blob, blobLen)

proc publickey_shutdown*(p: PublicKey): cint {.ssh2.}

proc scp_recv*(s: Session, path: cstring, sb: Stat) {.ssh2.}

proc scp_send_ex*(s: Session, path: cstring, mode, size: int, mtime, atime: int64): Channel {.ssh2.}

proc scp_send*(s: Session, path: cstring, mode, size: int): Channel {.inline.} =
  scp_send_ex(s, path, mode, size, 0, 0)

proc scp_send64*(s: Session, path: cstring, mode: int, size: uint64, mtime, atime: Time): Channel {.ssh2.}

proc session_abstract*(s: Session): ptr pointer {.ssh2.}

proc session_banner_get*(s: Session): cstring {.ssh2.}

proc session_banner_set*(s: Session, banner: cstring): cint {.ssh2.}

proc session_block_directions*(s: Session): cint {.ssh2.}

proc session_callback_set*(s: Session, cbtype: int, f: ptr) {.ssh2.}

proc session_disconnect_ex*(s: Session, reason: int, description, lang: cstring): cint {.ssh2.}

proc session_disconnect*(s: Session, description: cstring): cint {.inline.} =
  session_disconnect_ex(s, SSH_DISCONNECT_BY_APPLICATION, description, "")

proc session_flag*(s: Session, flag, value: int): cint {.ssh2.}

proc session_free*(s: Session): cint {.ssh2.}

proc session_get_blocking*(s: Session): cint {.ssh2.}

proc session_get_timeout*(s: Session): clong {.ssh2.}

proc session_handshake*(s: Session, fd: SocketHandle): cint {.ssh2.}

proc session_hostkey*(s: Session, length, typ: var int): cstring {.ssh2.}

proc session_init_ex*(a, b, c, d: int): Session {.ssh2.}

proc session_init*(): Session =
  session_init_ex(0, 0, 0, 0)

proc session_last_errno*(s: Session): cint {.ssh2.}

proc session_last_error*(s: Session, errormsg: ptr cstring, errmsgLen, wantBuf: int): cint {.ssh2.}

proc session_method_pref*(s: Session, methodType: int, prefs: cstring): cint {.ssh2.}

proc session_methods*(s: Session, methodType: int): cstring {.ssh2.}

proc session_set_blocking*(s: Session, blocking: int) {.ssh2.}

proc session_set_timeout*(s: Session, timeout: uint) {.ssh2.}

proc session_startup*(s: Session, socket: int): cint {.ssh2.}

proc session_supported_algs*(s: Session, methodType: int, algs: var cstring) {.ssh2.}

proc sftp_close_handle*(h: SftpHandle): cint {.ssh2.}

proc sftp_close*(h: SftpHandle): cint {.inline.} =
  sftp_close_handle(h)

proc sftp_closedir*(h: SftpHandle): cint {.inline.} =
  sftp_close_handle(h)

proc sftp_fstat_ex*(h: SftpHandle, attrs: SftpAttributes, setstat: int): cint {.ssh2.}

proc sftp_fstat*(h: SftpHandle, attrs: SftpAttributes): cint {.inline.} =
  sftp_fstat_ex(h, attrs, 0)

proc sftp_fsetstat*(h: SftpHandle, attrs: SftpAttributes): cint {.inline.} =
  sftp_fstat_ex(h, attrs, 1)

proc sftp_fstatvfs*(h: SftpHandle, path: cstring, pathLen: int, st: SftpStatVFS) {.ssh2.}

# TODO: could not import: libssh2_sftp_fsync
#proc sftp_fsync*(h: SftpHandle): cint {.ssh2.}

proc sftp_get_channel*(s: Sftp): Channel {.ssh2.}

proc sftp_init*(s: Session): Sftp {.ssh2.}

proc sftp_last_error*(s: Sftp): uint64 {.ssh2.}

# TODO: could not import
#proc sftp_lstat*(s: Sftp, path: cstring, attrs: SftpAttributes): cint {.ssh2.}

proc sftp_mkdir_ex*(s: Sftp, path: cstring, pathLen: uint, mode: uint64): cint {.ssh2.}

proc sftp_mkdir*(s: Sftp, path: cstring, mode: uint64): cint {.inline.} =
  sftp_mkdir_ex(s, path, path.len.uint, mode)

proc sftp_open_ex*(s: Sftp, filename: cstring, filenameLen: uint, flags: uint64, mode: int64, openType: int): SftpHandle {.ssh2.}

proc sftp_open*(s: Sftp, filename: cstring, flags: uint64, mode: uint64): SftpHandle {.inline.} =
  sftp_open_ex(s, filename, filename.len.uint, 0, 0, LIBSSH2_SFTP_OPENFILE)

proc sftp_opendir*(s: Sftp, filename: cstring, flags: uint64, mode: uint64): SftpHandle {.inline.} =
  sftp_open_ex(s, filename, filename.len.uint, 0, 0, LIBSSH2_SFTP_OPENDIR)

proc sftp_read*(h: SftpHandle, buf: ptr cstring, bufMaxLen: int): cint {.ssh2.}

proc sftp_readdir_ex*(h: SftpHandle, buf: ptr cstring, bufMaxLen: int, longEntry: ptr cstring, longEntryMaxLen: int, attrs: ptr SftpAttributes): cint {.ssh2.}

proc sftp_readdir*(h: SftpHandle, buf: ptr cstring, bufMaxLen: int, attrs: ptr SftpAttributes): cint {.inline.} =
  sftp_readdir_ex(h, buf, bufMaxLen, nil, 0, attrs)

proc sftp_symlink_ex*(s: Sftp, path: cstring, pathLen: uint, target: pointer, targetLen: uint, linkType: int): cint {.ssh2.}

proc sftp_readlink*(s: Sftp, path: cstring, target: pointer, maxLen: uint): cint {.inline.} =
  sftp_symlink_ex(s, path, path.len.uint, target, maxLen, LIBSSH2_SFTP_READLINK)

proc sftp_realpath*(s: Sftp, path: cstring, target: pointer, maxLen: uint): cint {.inline.} =
  sftp_symlink_ex(s, path, path.len.uint, target, maxLen, LIBSSH2_SFTP_REALPATH)

proc sftp_rename_ex*(s: Sftp, source: cstring, sourceLen: uint, dest: cstring, destLen: uint, flags: int64): cint {.ssh2.}

proc sftp_rename*(s: Sftp, source, dest: cstring): cint {.inline.} =
  sftp_rename_ex(s, source, source.len.uint, dest, dest.len.uint,  LIBSSH2_SFTP_RENAME_OVERWRITE or LIBSSH2_SFTP_RENAME_ATOMIC or LIBSSH2_SFTP_RENAME_NATIVE)

proc sftp_rmdir_ex*(s: Sftp, path: cstring, pathLen: uint): cint {.ssh2.}

proc sftp_rmdir*(s: Sftp, path: cstring): cint {.inline.} =
  sftp_rmdir_ex(s, path, path.len.uint)

proc sftp_seek*(h: SftpHandle, offset: int) {.ssh2.}

proc sftp_seek64*(h: SftpHandle, offset: int64) {.ssh2.}

proc sftp_rewind*(h: SftpHandle) {.inline.} =
  sftp_seek64(h, 0)

proc sftp_shutdown*(s: Sftp): cint {.ssh2.}

proc sftp_stat_ex*(h: SftpHandle, attrs: pointer, setstat: int): cint {.ssh2.}

proc sftp_stat*(h: SftpHandle, path: cstring, attrs: pointer): cint {.inline.} =
  sftp_stat_ex(h, attrs, 0)

proc sftp_setstat*(h: SftpHandle, path: cstring, attrs: pointer): cint {.inline.} =
  sftp_stat_ex(h, attrs, 1)

proc sftp_statvfs*(s: Sftp, path: cstring, pathLen: int, st: ptr SftpAttributes) {.ssh2.}

proc sftp_fstatvfs*(h: SftpHandle, st: ptr SftpAttributes) {.ssh2.}

proc sftp_symlink*(s: Sftp, orig, linkPath: cstring): cint {.inline.} =
  sftp_symlink_ex(s, orig, orig.len.uint, linkPath, linkPath.len.uint, LIBSSH2_SFTP_SYMLINK)

proc sftp_tell*(h: SftpHandle): cint {.ssh2.}

proc sftp_tell64*(h: SftpHandle): clong {.ssh2.}

proc sftp_unlink_ex*(s: Sftp, filename: cstring, filenameLen: uint): cint {.ssh2.}

proc sftp_unlink*(s: Sftp, filename: cstring): cint {.inline.} =
  sftp_unlink_ex(s, filename, filename.len.uint)

proc sftp_write*(h: SftpHandle, buf: pointer, count: int): cint {.ssh2.}

proc trace*(s: Session, bitMask: int) {.ssh2.}

proc trace_sethandler*(s: Session, context: pointer, callback: pointer) {.ssh2.}

proc userauth_authenticated*(s: Session): cint {.ssh2.}

proc userauth_hostbased_fromfile_ex*(s: Session, uname: cstring, unameLen: uint, pk, pv, pp, hname: cstring, hNameLen: uint, localUame: cstring, localUnameLen: uint): cint {.ssh2.}

proc userauth_hostbased_fromfile*(s: Session, uname: cstring, unameLen: uint, pk, pv, pp, hostname: cstring): cint {.inline.} =
  userauth_hostbased_fromfile_ex(s, uname, uname.len.uint, pk, pv, pp, hostname, hostname.len.uint, uname, uname.len.uint)

proc userauth_keyboard_interactive_ex*(s: Session, uname: cstring, unameLen: uint, cb: Function): cint {.ssh2.}

proc userauth_keyboard_interactive*(s: Session, uname: cstring, cb: Function): cint {.inline.} =
  userauth_keyboard_interactive_ex(s, uname, uname.len.uint, cb)

proc userauth_list*(s: Session, username: cstring, usernameLen: int): cstring {.ssh2.}

proc userauth_password_ex*(s: Session, uname: cstring, unameLen: uint, password: cstring, passwordLen: uint, cb: passwd_changereq_func): cint {.ssh2.}

proc userauth_password*(s: Session, uname: cstring, password: cstring, cb: passwd_changereq_func): cint {.inline.} =
  userauth_password_ex(s, uname, uname.len.uint, password, password.len.uint, cb)

proc userauth_publickey*(s: Session, user: cstring, pkdata: cstring, pubkeydataLen: int, cb: Function) {.ssh2.}

proc userauth_publickey_fromfile_ex*(s: Session, uname: cstring, unameLen: uint, pk, pv, pp: cstring): cint {.ssh2.}

proc userauth_publickey_fromfile*(s: Session, uname: cstring, pk, pv, pp: cstring): cint {.inline.} =
  userauth_publickey_fromfile_ex(s, uname, uname.len.uint, pk, pv, pp)

when defined(ssl):
  proc userauth_publickey_frommemory*(s: Session, uname: cstring, unameLen: int, pk: cstring, pkLen: int, pv: cstring, pvLen: int, pp: cstring, ppLen: int): cint {.ssh2.}

proc version*(version: int): cstring {.ssh2.}

when isMainModule:
  echo "libssh2 version: ", version(0)
