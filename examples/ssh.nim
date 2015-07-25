import os
import net
import hex
import strutils

import ../libssh2


var
  username = "root"
  password = "S3cret"
  pubkeyFile = "~/.ssh/id_rsa.pub"
  privkeyFile = "~/.ssh/id_rsa"
  hostname = "127.0.0.1"

if paramCount() > 1:
  hostname = paramStr(1)

if paramCount() > 2:
  username = paramStr(2)

if paramCount() > 3:
  password = paramStr(3)


var rc = init(0)
if rc != 0:
  quit "libssh2 initialization failed", rc

var sock = newSocket()
sock.connect(hostname, Port(22))

var session = sessionInit()
if session.sessionHandshake(sock.getFd()) != 0:
  quit "failure  establing ssh connection"

var fingerprint = session.hostkeyHash(LIBSSH2_HOSTKEY_HASH_SHA1)
echo "Fingerprint: ", encode($fingerprint)

var authlist =  split($session.userauthList(username, username.len), ",")
echo "User auth list: ", authlist

var auth_pw = 0
if "password" in authlist:
  auth_pw = auth_pw or 1

if "keyboard-interactive" in authlist:
  auth_pw = auth_pw or 2

if "publickey" in authlist:
  auth_pw = auth_pw or 4

if paramCount() > 4:
  if (auth_pw and 1) == 1 and paramStr(4) == "-p":
    auth_pw = 1
  if (auth_pw and 2) == 2 and paramStr(4) == "-i":
    auth_pw = 2
  if (auth_pw and 4) == 4 and paramStr(4) == "-k":
    auth_pw = 4

proc shutdown(s: Session) =
  discard session.sessionDisconnect("Normal shutdown, thank you for playing")
  discard session.sessionFree()
  sock.close()
  libssh2.exit()

proc skip_shell(c: var Channel) =
  if not c.isNil:
    discard c.channelFree()
  c = nil

if (auth_pw and 1) == 1:
  if session.userauthPassword(username, password, nil) != 0:
    echo "Authentication by password failed!"
    session.shutdown()
  else:
    echo "Authentication by password succeeded."
elif (auth_pw and 2) == 2:
  if session.userauthKeyboardInteractive(username, nil) != 0:
    echo "Authentication by keyboard-interactive failed!"
    session.shutdown()
  else:
    echo "Authentication by keyboard-interactive succeeded."
elif (auth_pw and 4) == 4:
  if session.userauthPublickeyFromFile(username, pubkeyFile, privkeyFile, password) != 0:
    echo  "Authentication by public key failed!"
    session.shutdown()
  else:
    echo "Authentication by public key succeeded."
else:
  echo "No supported authentication method found!"
  session.shutdown()

var channel = session.channelOpenSession()
if channel.isNil:
  echo "Unable to open a session"
  session.shutdown()

discard channel.channelSetEnv("FOO", "bar")

if channel.channelReQuestPty("vanilla") != 0:
  echo "Failed requesting pty"
  channel.skip_shell()

if channel.channelShell() != 0:
  echo "Unable to request shell on allocated pty"
  session.shutdown()
