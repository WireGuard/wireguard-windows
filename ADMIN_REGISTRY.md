## Registry Keys for Admins

These are advanced configuration nobs that admins can set to do unusual things
that are not recommended. There is no UI to enable these, and no such thing is
planned. Use at your own risk, and please make sure you know what you're doing.


#### `HKLM\Software\WireGuard\SilentUpdate`

When this key is set to `DWORD(1)`, WireGuard will silently update itself when
an update is available. Note that this is not recommended, as all tunnels will
be disrupted during the update, during which time Windows will revert to its
ordinary routing rules.
