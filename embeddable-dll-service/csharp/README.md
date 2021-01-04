# Example WireGuard Demo Client for Windows

This is a simple client for demo.wireguard.com, which brings up WireGuard tunnels using the [embeddable-dll-service](https://git.zx2c4.com/wireguard-windows/about/embeddable-dll-service/README.md).

## Building

The code in this repository can be built in Visual Studio 2019 by opening the .sln and pressing build. However, it requires `tunnel.dll` to be present in the run directory. That can be built by:

```batch
> git clone https://git.zx2c4.com/wireguard-windows
> cd wireguard-windows\embeddable-dll-service
> .\build.bat
```

In addition, `tunnel.dll` requires `wintun.dll`, which can be downloaded from [wintun.net](https://www.wintun.net).
