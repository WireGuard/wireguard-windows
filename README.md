# [WireGuard](https://www.wireguard.com/) for Windows

Nothing to see here yet. Come back later.

### Requirements

  - [Wintun](https://git.zx2c4.com/wintun) (at runtime)
  - [Go ≥1.12.2](https://golang.org/) (for compilation)
  - [Mingw](http://www.mingw.org/) (for compilation)

### Building on Windows

The build script will take care of downloading, verifying, and extracting the right versions of Go, Mingw, and Patch.

```
C:\Projects> git clone https://git.zx2c4.com/wireguard-windows
C:\Projects> cd wireguard-windows
C:\Projects\wireguard-windows> build
```

### Building on Linux

You must first have Go and Mingw installed.

```
$ sudo apt install mingw-w64 golang-go
$ git clone https://git.zx2c4.com/wireguard-windows
$ cd wireguard-windows
$ make
```

### Running

After you've built the application, run `amd64\wireguard.exe` to install the manager service and show the UI.

```
C:\Projects\wireguard-windows> amd64\wireguard.exe
```

### Signing Binaries

Add a file called `sign.bat` in the root of this repository with these contents, or similar:

```
set SigningCertificate=DF98E075A012ED8C86FBCF14854B8F9555CB3D45
set TimestampServer=http://timestamp.digicert.com
```
