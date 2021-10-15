## Embeddable WireGuard Tunnel Library

This allows embedding WireGuard as a service inside of another application. Build `tunnel.dll` by running `./build.bat` in this folder. The first time you run it, it will invoke `..\build.bat` simply for downloading dependencies. After, you should have `amd64/tunnel.dll`, `x86/tunnel.dll`, and `arm64/tunnel.dll`. In addition, `tunnel.dll` requires `wireguard.dll`, which can be downloaded from [the wireguard-nt download server](https://download.wireguard.com/wireguard-nt/).

The basic setup to use `tunnel.dll` is:

##### 1. Install a service with these parameters:

```text
Service Name:  "WireGuardTunnel$SomeTunnelName"
Display Name:  "Some Service Name"
Service Type:  SERVICE_WIN32_OWN_PROCESS
Start Type:    StartAutomatic
Error Control: ErrorNormal,
Dependencies:  [ "Nsi", "TcpIp" ]
Sid Type:      SERVICE_SID_TYPE_UNRESTRICTED
Executable:    "C:\path\to\example\vpnclient.exe /service configfile.conf"
```

Some of these may have to be changed with `ChangeServiceConfig2` after the
initial call to `CreateService` The `SERVICE_SID_TYPE_UNRESTRICTED` parameter
is absolutely essential; do not forget it.

##### 2. Have your program's main function handle the `/service` switch:

```c
if (!wcscmp(wargv[1], L"/service") && wargc == 3) {
    HMODULE tunnel_lib = LoadLibrary("tunnel.dll");
    if (!tunnel_lib)
        abort();
    tunnel_proc_t tunnel_proc = (tunnel_proc_t)GetProcAddress(tunnel_lib, "WireGuardTunnelService");
    if (!tunnel_proc)
        abort();
    return tunnel_proc(wargv[2]);
}
```

##### 3. Scoop up logs by implementing a ringlogger format reader.

There is a sample implementation of bits and pieces of this inside of the `csharp\` directory.
