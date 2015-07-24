import libssh2
import net

var rc = init(0)
if rc != 0:
  quit "libssh2 initialization failed", rc

var sock = newSocket()
sock.connect("127.0.0.1", Port(22))

var session = sessionInit()
if session.sessionHandshake(sock.getFd()) != 0:
  quit "failure  establing ssh connection"

var fingerprint = session.hostkeyHash(LIBSSH2_HOSTKEY_HASH_SHA1)
echo "Fingerprint: ", fingerprint

echo "User auth list: ", session.userauthList("root", 4)
