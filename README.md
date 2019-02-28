# [WireGuard](https://www.wireguard.com/) for Windows

Nothing to see here yet. Come back later.

### Requirements

  - [Go ≥1.12](https://www.golang.org)
  - [Wintun](https://git.zx2c4.com/wintun)

### Clone

This has a few submodules at the moment, so you'll need to clone recursively. While building (below) uses WSL, it's recommended that you still clone into Windows per usual.

```
$ cd Projects
$ git clone --recursive https://git.zx2c4.com/wireguard-windows
```

### Building

Currently a mess while we transition a few things, so you'll actually need to use WSL. Here are instructions for [Ubuntu 18.04 from the Windows Store](https://www.microsoft.com/en-us/p/ubuntu-1804-lts/9n9tngvndl3q) on WSL:

```
$ sudo apt update
$ sudo apt install mingw-w64 make
$ curl https://dl.google.com/go/go1.12.linux-amd64.tar.gz | tar xzf -
$ export PATH="$PWD/go/bin:$PATH"
$ mkdir "$HOME/.go"
$ export GOPATH="$HOME/.go"
$ go get github.com/akavel/rsrc
$ cd /mnt/c/Users/YourUsername/Projects/wireguard-windows
$ make
```

### Running

After you've built the application, run `wireguard.exe` to install the manager service and show the UI.

```
$ ./wireguard.exe
```
