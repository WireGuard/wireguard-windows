### WireGuard for Windows Attack Surface

_This is an evolving document, describing currently known attack surface, a few mitigations, and several open questions. This is a work in progress. We document our current understanding with the intent of improving both our understanding and our security posture over time._

WireGuard for Windows consists of four components: a kernel driver, and three separate interacting userspace parts.

#### Wintun

Wintun is a kernel driver. It exposes:

  - A miniport driver to the ndis stack, meaning any process on the system that can access the network stack in a reasonable way can send and receive packets, hitting those related ndis handlers.
  - There are also various ndis OID calls, accessible to certain users, which hit further code.
  - A virtual file in `\\Device\WINTUN%d`, whose permissions are set to `SDDL_DEVOBJ_SYS_ALL`. Presumably this means only the "Local System" user can open the file and do things, but it might be worth double checking that. It sends and receives layer 3 packets, and does minimal parsing of the IP header in order to determine packet family. It also does more complex struct alignment pointer arithmetic, as it can send and receive several packets at a time in a single bundle.

### Tunnel Service

The tunnel service is a userspace service running as Local System, responsible for creating UDP sockets, creating Wintun adapters, and speaking the WireGuard protocol between the two. It exposes:

  - A listening pipe in `\\.\pipe\WireGuard\%s`, where `%s` is some basename of an already valid filename. Its permissions are set to `O:SYD:(A;;GA;;;SY)`, which presumably means only the "Local System" user can access it and do things, but it might be worth double checking that. This pipe gives access to private keys and allows for reconfiguration of the interface, as well as rebinding to different ports (below 1024, even).
  - It handles data from its two UDP sockets, accessible to the public Internet.
  - It handles data from Wintun, accessible to all users who can do anything with the network stack.
  - It does not yet drop privileges.

### Manager Service

The manager service is a userspace service running as Local System, responsible for starting and stopping tunnel services, and ensuring a UI program with certain handles is available to Administrators. It exposes:

  - Extensive IPC using unnamed pipes, inherited by the unprivileged UI process.
  - A writable `CreateFileMapping` handle to a binary ringlog shared by all services, inherited by the unprivileged UI process. It's unclear if this brings with it surprising hidden attack surface in the mm system.
  - It listens for service changes in tunnel services according to the string prefix "WireGuardTunnel$".
  - It manages DPAPI-encrypted configuration files in Local System's local appdata directory, and makes some effort to enforce good configuration filenames.
  - It uses `wtsEnumerateSessions` and `WTSSESSION_NOTIFICATION` to walk through each available session. It then uses `wtfQueryUserToken`, and then calls `GetTokenInformation(TokenGroups)` on it. If one of the returned group's SIDs matches `CreateWellKnownSid(WinBuiltinAdministratorsSid)`, then it spawns the unprivileged UI process as that user token, passing it three unnamed pipe handles for IPC and the log mapping handle, as descried above.

### UI

The UI is an unprivileged process running as the ordinary user for each user who is in the Administrators group (per the above). It exposes:

  - The manager service (above) calls `GetSecurityInfo(DACL_SECURITY_INFORMATION)` on itself, and passes the returned security attributes as the UI's process and thread attributes in the call to `CreateProcessAsUser`. This means that debugging the UI process (in order for another process to steal its handles and exfiltrate private keys) is only possible by processes that can debug the manager service.
  - We do not add `ATTRIBUTE_SECURITY_INFORMATION` into the requested information of `GetSecurityInfo`, which means the UI process only requires medium integrity to run it. Requiring greater integrity level access prevents the process from running properly, unfortunately (`ERROR_PRIVILEGE_NOT_HELD`). It would be nice to require high integrity to open the process, without having to increase the privileges that the process has in its own token.
  - Perhaps due to the above and other reasons, it appears that it is possible for other processes to write into the UI process's message loop, which is bad, and might defeat the purpose of the above.
  - It renders highlighted config files to a msftedit.dll control, which typically is capable of all sorts of OLE and RTF nastiness that we make some attempt to avoid.

### Updates

A server hosts the result of:

```
$ b2sum -l 256 *.msi > list
$ signify -S -e -s release.sec -m list
$ upload ./list.sec
```

The MSIs in that list are only the latest ones available, and filenames fit the form `wireguard-${arch}-${version}.msi`. The updater downloads this list over TLS and verifies the signify Ed25519 signature of it. If it validates, then it finds the first MSI in it for its architecture that has a greater version. It then downloads this MSI from a predefined URL, and verifies the BLAKE2b-256 signature. If it validates, then it calls `WinTrustVerify(WINTRUST_ACTION_GENERIC_VERIFY_V2, WTD_REVOKE_WHOLECHAIN)` on the MSI. If it validates, then it executes the installer with `msiexec.exe /qb- /i`.
