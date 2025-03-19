# libssh2.nim
Nim wrapper for libssh2

A Nim binding for the [libssh2](https://www.libssh2.org/) library, providing SSH client functionality.

For documentation please refer to [libssh2](http://www.libssh2.org/docs.html) website.

## Version Compatibility

This wrapper is compatible with libssh2 version 1.11.1 and includes support for:
- Security key authentication
- Various crypto engines
- Session timeouts
- Modern host key types
- All standard libssh2 functionality

## Installation

### Using Nimble

The easiest way to install libssh2.nim is using the Nimble package manager:

```
nimble install libssh2
```

### Dependencies

In order to use this wrapper, libssh2 must be installed on your system:

#### Mac OSX:
```
$ port install libssh2
```
or
```
$ brew install libssh2
```

#### Ubuntu/Debian:
```
$ apt-get install libssh2-1-dev
```

#### Windows:
There are several ways to install libssh2 on Windows:

1. Using vcpkg:
```
vcpkg install libssh2
```

2. Using MSYS2:
```
pacman -S mingw-w64-x86_64-libssh2
```

3. Download pre-built binaries from the libssh2 website or build from source.

## Basic Usage

Here's a simple example of how to connect to an SSH server:

```nim
import libssh2

proc main() =
  # Initialize libssh2
  discard libssh2_init(0)
  
  # Create a new session instance
  let session = libssh2_session_init()
  defer: libssh2_session_free(session)
  
  # Connect to the server using your preferred socket library
  # ... socket connection code ... 
  let socket = connectToServer("example.com", 22)
  
  # Start the SSH session on the connected socket
  if libssh2_session_handshake(session, socket) != 0:
    echo "Failed to establish SSH session"
    return
  
  # Authenticate
  if libssh2_userauth_password(session, "username", "password") != 0:
    echo "Authentication failed"
    return
    
  echo "Successfully connected and authenticated"
  
  # Clean up
  libssh2_exit()

when isMainModule:
  main()
```

See the examples directory for more comprehensive usage examples.

## License

This Nim wrapper is distributed under the MIT License.

libssh2 itself is licensed under the BSD license. See the [libssh2 license](https://www.libssh2.org/license.html) for details.
