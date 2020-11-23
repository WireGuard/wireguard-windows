# [WireGuard](https://www.wireguard.com/) for Windows

This is a fully-featured WireGuard client for Windows that uses [Wintun](https://www.wintun.net/). It is the only official and recommended way of using WireGuard on Windows.

## Download &amp; Install

If you've come here looking to simply run WireGuard for Windows, [the main download page has links](https://www.wireguard.com/install/). There you will find two things:

- [The WireGuard Installer](https://download.wireguard.com/windows-client/wireguard-installer.exe) &ndash; This selects the most recent version for your architecture, downloads it, checks signatures and hashes, and installs it.
- [Standalone MSIs](https://download.wireguard.com/windows-client/) &ndash; These are for system admins who wish to deploy the MSIs directly. For most end users, the ordinary installer takes care of downloading these automatically.

## Documentation

In addition to this [`README.md`](README.md), the following documents are also available:

- [`adminregistry.md`](docs/adminregistry.md) &ndash; A list of registry keys settable by the system administrator for changing the behavior of the application.
- [`attacksurface.md`](docs/attacksurface.md) &ndash; A discussion of the various components from a security perspective, so that future auditors of this code have a head start in assessing its security design.
- [`buildrun.md`](docs/buildrun.md) &ndash; Instructions on building, localizing, running, and developing for this repository.
- [`enterprise.md`](docs/enterprise.md) &ndash; A summary of various features and tips for making the application usable in enterprise settings.
- [`netquirk.md`](docs/netquirk.md) &ndash; A description of various networking quirks and "kill-switch" semantics.

## License

This repository is MIT-licensed.

```text
Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```
