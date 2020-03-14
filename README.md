# [WireGuard](https://www.wireguard.com/) for Windows

***If you've come here looking to simply run WireGuard for Windows, [you may download it here](https://www.wireguard.com/install/).***

This is a fully-featured WireGuard client for Windows that uses [Wintun](https://www.wintun.net/).

### Building

Windows 10 64-bit or Windows Server 2019, and Git for Windows is required. The build script will take care of downloading, verifying, and extracting the right versions of the various dependencies:

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

Since WireGuard requires the Wintun driver to be installed, and this generally requires a valid Microsoft signature, you may benefit from first installing a release of WireGuard for Windows from the official [wireguard.com](https://www.wireguard.com/install/) builds, which bundles a Microsoft-signed Wintun, and then subsequently run your own wireguard.exe. Alternatively, you can craft your own installer using the `quickinstall.bat` script.

### Optional: Localizing

To translate WireGuard UI to your language:

1. Upgrade `resources.rc` accordingly. Follow the pattern.

2. Add your language ID to the `//go:generate ... -lang=en,<langID>...` line in `gotext.go`.

3. Configure and run `build` to prepare initial `locales\<langID>\messages.gotext.json` file:

   ```
   C:\Projects\wireguard-windows> set GoGenerate=yes
   C:\Projects\wireguard-windows> build
   C:\Projects\wireguard-windows> copy locales\<langID>\out.gotext.json locales\<langID>\messages.gotext.json
   ```

4. Translate `locales\<langID>\messages.gotext.json`. See other language message files how to translate messages and how to tackle plural.

5. Run `build` from the step 3 again, and test.

6. Repeat from step 4.

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

After, run the above `build` commands as usual, from a shell that has [`signtool.exe`](https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/signtool) in its `PATH`, such as the Visual Studio 2017 command prompt.

### Alternative: Building from Linux

You must first have Go ≥1.12, Mingw, and ImageMagick installed.

```
$ sudo apt install mingw-w64 golang-go imagemagick
$ git clone https://git.zx2c4.com/wireguard-windows
$ cd wireguard-windows
$ make
```

You can deploy the 64-bit build to an SSH host specified by the `DEPLOYMENT_HOST` environment variable (default "winvm") to the remote directory specified by the `DEPLOYMENT_PATH` environment variable (default "Desktop") by using the `deploy` target:

```
$ make deploy
```

### [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) Support for Windows

The command line utility [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) works well on Windows. Being a Unix-centric project, it compiles with a Makefile and MingW:

```
$ git clone https://git.zx2c4.com/wireguard-tools
$ PLATFORM=windows make -C wireguard-tools/src
$ stat wireguard-tools/src/wg.exe
```

It interacts with WireGuard instances run by the main WireGuard for Windows program.

When building on Windows, the aforementioned `build.bat` script takes care of building this.
