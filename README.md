# [WireGuard](https://www.wireguard.com/) for Windows

This is a fully-featured WireGuard client for Windows that uses [Wintun](https://www.wintun.net/).

### Building

Windows 10 64-bit is required. The build script will take care of downloading, verifying, and extracting the right versions of the various dependencies:

```
C:\Projects> git clone https://git.zx2c4.com/wireguard-windows
C:\Projects> cd wireguard-windows
C:\Projects\wireguard-windows> build
```

### Running

After you've built the application, run `amd64\wireguard.exe` or `x86\wireguard.exe` to install the manager service and show the UI.

```
C:\Projects\wireguard-windows> amd64\wireguard.exe
```

Since WireGuard requires the Wintun driver to be installed, and this generally requires a valid Microsoft signature, you may benefit from first installing a release of WireGuard for Windows from the official [wireguard.com](https://www.wireguard.com/install/) builds, which bundles a Microsoft-signed Wintun, and then subsequently run your own wireguard.exe.

### Optional: Creating the Installer

The installer build script will take care of downloading, verifying, and extracting the right versions of the various dependencies:

```
C:\Projects\wireguard-windows> cd installer
C:\Projects\wireguard-windows\installer> build
```

### Optional: Signing Binaries

Add a file called `sign.bat` in the root of this repository with these contents, or similar:

```
set SigningCertificate=DF98E075A012ED8C86FBCF14854B8F9555CB3D45
set TimestampServer=http://timestamp.digicert.com
```

After, run the above `build` commands as usual, from a shell that has [`signtool.exe`](https://docs.microsoft.com/sl-si/windows/desktop/SecCrypto/signtool) in its `PATH`, such as the Visual Studio 2017 command prompt.

### Alternative: Building from Linux

You must first have Go ≥1.12 and Mingw installed.

```
$ sudo apt install mingw-w64 golang-go
$ git clone https://git.zx2c4.com/wireguard-windows
$ cd wireguard-windows
$ make
```

You can deploy the 64-bit build to an SSH host specified by the `DEPLOYMENT_HOST` environment variable (default "winvm") to the remote directory specified by the `DEPLOYMENT_PATH` environment variable (default "Desktop") by using the `deploy` target:

```
$ make deploy
```
