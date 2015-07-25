import net
import hex
import strutils

import ../libssh2

var rc = init(0)
if rc != 0:
  quit "libssh2 initialization failed", rc

var sock = newSocket()
sock.connect("192.168.100.143", Port(22))

var session = sessionInit()
if session.sessionHandshake(sock.getFd()) != 0:
  quit "failure  establing ssh connection"

var fingerprint = session.hostkeyHash(LIBSSH2_HOSTKEY_HASH_SHA1)
echo "Fingerprint: ", encode($fingerprint)

var authlist =  split($session.userauthList("root", 4), ",")
echo "User auth list: ", authlist

var auth_pw = 0
if "password" in authlist:
  auth_pw = auth_pw or 1

if "keyboard-interactive" in authlist:
  auth_pw = auth_pw or 2

if "publickey" in authlist:
  auth_pw = auth_pw or 4


echo auth_pw
