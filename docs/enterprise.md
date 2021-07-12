# Enterprise Usage

WireGuard for Windows has been designed from the ground-up to make full use of standard Windows service, ACL, and CLI capabilities, making WireGuard deployable in enterprise scenarios or as part of Active Directory domains.

### Installation

While consumer users are generally directed toward [wireguard-installer.exe](https://download.wireguard.com/windows-client/wireguard-installer.exe), this installer simply takes care of selecting the correct MSI for the architecture, validating signatures, and executing it. Enterprise admins can instead [download MSIs directly](https://download.wireguard.com/windows-client/) and deploy these using [Group Policy Objects](https://docs.microsoft.com/en-us/troubleshoot/windows-server/group-policy/use-group-policy-to-install-software). The installer makes use of standard MSI features and should be easily automatable. The additional MSI property of `DO_NOT_LAUNCH` suppresses launching WireGuard after its installation, should that be required.

### Tunnel Service versus Manager Service and UI

The "manager service" is responsible for displaying a UI on select users' desktops (in the system tray), and responding to requests from the UI to do things like add, remove, start, or stop tunnels. The "tunnel service" is a separate Windows service for each tunnel. These two services may be used together, or separately, as described below. The various commands below will log errors and status to standard error, or, if standard error does not exist, to standard output.

### Tunnel Service

A tunnel service may be installed or uninstalled using the commands:

```text
> wireguard /installtunnelservice C:\path\to\some\myconfname.conf
> wireguard /uninstalltunnelservice myconfname
```

This creates a service called `WireGuardTunnel$myconfname`, which can be controlled using standard Windows service management utilites, such as `services.msc` or [`sc`](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query).

If the configuration filename ends in `.conf`, it is interpreted as a normal [`wg-quick(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8) configuration file. If it ends in `.conf.dpapi`, it is considered to be that same configuration file, but encrypted using [`CryptProtectData(bytes, "myconfname")`](https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).

The tunnel service may be queried and modified at runtime using the standard [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) command line utility. If the configuration file is a `.conf.dpapi` one, then Local System or Administrator permissions is required to interact with it using `wg(8)`; otherwise users of `wg(8)` must have Local System or Administrator permissions, or permissions the same as the owner of the `.conf` file. Invocation of `wg(8)` follows usual patterns on other platforms. For example:

```text
> wg show myconfname
interface: myconfname
  public key: lfTRXEWxt8mZc8cjSvOWN3tqnTpWw4v2Eg3qF6WTklw=
  private key: (hidden)
  listening port: 53488

peer: JRI8Xc0zKP9kXk8qP84NdUQA04h6DLfFbwJn4g+/PFs=
  endpoint: 163.172.161.0:12912
  allowed ips: 0.0.0.0/0
  latest handshake: 3 seconds ago
  transfer: 6.55 KiB received, 4.13 KiB sent
```

The `PreUp`, `PostUp`, `PreDown`, and `PostDown` configuration options may be specified to run custom commands at various points in the lifetime of a tunnel service, but only if the correct registry key is set. [See `adminregistry.md` for information.](adminregistry.md)

### Manager Service

The manager service may be installed or uninstalled using the commands:

```text
> wireguard /installmanagerservice
> wireguard /uninstallmanagerservice
```

This creates a service called `WireGuardManager`, which can be controlled using standard Windows service management utilites, such as `services.msc` or [`sc`](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query).

When executing `wireguard` with no arguments, the command first attempts to show the UI if the manager service is already running; otherwise it starts the manager service, waits for it to create a UI in the system tray, and then shows the main manager window. Therefore, `wireguard /installmanagerservice` is suitable for silent installation, whereas `wireguard` alone is suitable for interactive startup.

The manager service monitors `%ProgramFiles%\WireGuard\Data\Configurations\` for the addition of new `.conf` files. Upon seeing one, it encrypts the file to a `.conf.dpapi` file, makes it unreadable to users other than Local System, confers the administrator only the ability to remove it, and then deletes the original unencrypted file. (Configurations can always be _exported_ later using the export feature of the UI.) Using this, configurations can programmatically be added to the secure store of the manager service simply by copying them into that directory.

The UI is started in the system tray of all builtin Administrators when the manager service is running. A limited UI may also be started in the system tray of all builtin Network Configuration Operators, if the correct registry key is set. [See `adminregistry.md` for information.](adminregistry.md)

By default, the manager stops existing tunnels when starting new tunnels, so that only one tunnel service is running at a time. This behavior may be disabled if the correct registry key is set. [See `adminregistry.md` for information.](adminregistry.md)


### Diagnostic Logs

The manager and all tunnel services produce diagnostic logs in a shared ringbuffer-based log. This is shown in the UI, and also can be dumped to standard out using the command:

```text
> wireguard /dumplog > C:\path\to\diagnostic\log.txt
```

### Updates

Administrators are notified of updates within the UI and can update from within the UI, but updates can also be invoked at the command line using the command:

```text
> wireguard /update
```

Or, to log the status of that command:

```text
> wireguard /update 2> C:\path\to\update\log.txt
```

### Network Adapters

The tunnel service creates a network adapter at startup and destroys it at shutdown. It may be desirable, however, to remove all network adapters created in WireGuard's pool and uninstall the driver if no other applications are using our network adapters. This can be accomplished using the command:

```text
> wireguard /removealladapters
```

Or, to log the status of that command:

```text
> wireguard /removealladapters 2> C:\path\to\removal\log.txt
```
