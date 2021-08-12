# Registry Keys for Admins

These are advanced configuration knobs that admins can set to do unusual things
that are not recommended. There is no UI to enable these, and no such thing is
planned. These registry keys may also be removed at some point in the future.
The uninstaller will clean up the entirety of `HKLM\Software\WireGuard`. Use
at your own risk, and please make sure you know what you're doing.

#### `HKLM\Software\WireGuard\LimitedOperatorUI`

When this key is set to `DWORD(1)`, the UI will be launched on desktops of
users belonging to the Network Configuration Operators builtin group
(S-1-5-32-556), with the following limitations for members of that group:

  - Configurations are stripped of all public, private, and pre-shared keys;
  - No version update notifications are delivered;
  - Adding, removing, editing, importing, or exporting configurations is forbidden; and
  - Quitting the manager is forbidden.

However, basic functionality such as starting and stopping tunnels remains intact.

```
> reg add HKLM\Software\WireGuard /v LimitedOperatorUI /t REG_DWORD /d 1 /f
```

#### `HKLM\Software\WireGuard\DangerousScriptExecution`

When this key is set to `DWORD(1)`, the tunnel service will execute the commands
specified in the `PreUp`, `PostUp`, `PreDown`, and `PostDown` options of a
tunnel configuration. Note that this execution is done as the Local System user,
which runs with the highest permissions on the operating system, and is therefore
a real target of malware. Therefore, you should enable this option only with the
utmost trepidation. Rather than use `%i`, WireGuard for Windows instead sets the
environment variable `WIREGUARD_TUNNEL_NAME` to the name of the tunnel when
executing these scripts.

```
> reg add HKLM\Software\WireGuard /v DangerousScriptExecution /t REG_DWORD /d 1 /f
```

#### `HKLM\Software\WireGuard\ExperimentalKernelDriver`

When this key is set to `DWORD(1)`, an experimental kernel driver from the
[WireGuardNT](https://git.zx2c4.com/wireguard-nt/about/) project is used instead
of the much slower wireguard-go/Wintun implementation. There are significant
performance gains, but do note that this is _currently_ considered experimental,
and hence is not recommended.

```
> reg add HKLM\Software\WireGuard /v ExperimentalKernelDriver /t REG_DWORD /d 1 /f
```
