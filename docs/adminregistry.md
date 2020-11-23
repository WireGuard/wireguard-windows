## Registry Keys for Admins

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

#### `HKLM\Software\WireGuard\DangerousScriptExecution`

When this key is set to `DWORD(1)`, the tunnel service will execute the commands
specified in the `PreUp`, `PostUp`, `PreDown`, and `PostDown` options of a
tunnel configuration. Note that this execution is done as the Local System user,
which runs with the highest permissions on the operating system, and is therefore
a real target of malware. Therefore, you should enable this option only with the
utmost trepidation. Rather than use `%i`, WireGuard for Windows instead sets the
environment variable `WIREGUARD_TUNNEL_NAME` to the name of the tunnel when
executing these scripts.

#### `HKLM\Software\WireGuard\MultipleSimultaneousTunnels`

When this key is set to `DWORD(1)`, the UI may start multiple tunnels at the
same time; otherwise, an existing tunnel is stopped when a new one is started.
Note that it is always possible, regardless of this key, to start multiple
tunnels using `wireguard /installtunnelservice`; this controls only the semantics
of tunnel start requests coming from the UI. If all goes well, this key will be
removed and the logic of whether to stop existing tunnels will be based on
overlapping routes, but for now, this key provides a manual override.
