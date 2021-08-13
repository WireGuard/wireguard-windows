# Network Configuration Quirks

As part of setting up a WireGuard tunnel, the tunnel service also sets up various network configuration parameters that are in one way or another related to the original configuration.

### Routing

The tunnel service takes all the allowed IPs from each peer, deduplicates them, and adds them to the routes for the WireGuard interface. The service then monitors which interface on the system has a default route (a route with a `/0` CIDR) that is not the WireGuard interface itself, and, if no MTU has been specified in the configuration, it sets the MTU of the WireGuard interface to be 80 less than the MTU of that default route interface. WireGuardNT also monitors the routing table and determines the outgoing route that does not loopback to itself, and then sends each packet using `IP_PKTINFO`/`IPV6_PKTINFO`. It keeps track of the incoming interface and source address for received packets, and always replies to the sender in that way.

### Firewall Considerations for `/0` Allowed IPs

If an interface has only one peer, and that peer contains an Allowed IP in `/0`, then WireGuard enables a so-called "kill-switch", which adds firewall rules to do the following:

- Packets from the tunnel service itself are permitted, so that WireGuard packets can flow successfully.
- If the configuration specifies DNS servers, then packets sent to port `53` are only permitted if they are to one of those DNS servers. This is to prevent Windows' [ordinary multihomed DNS resolution behavior](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197552%28v%3Dws.10%29), so that DNS queries only go to the DNS server specified, rather than multiple DNS servers.
- Loopback packets are permitted, and packets actually going through the WireGuard tunnel are permitted.
- DHCP for IPv4 and IPv6 and NDP for IPv6 are permitted.
- All other packets are blocked.

This prevents traffic from leaking outside the tunnel.

If you'd like to use a default route _without_ having these restrictive kill-switch semantics, one may use the routes `0.0.0.0/1` and `128.0.0.0/1` in place of `0.0.0.0/0`, as well as `::/1` and `8000::/1` in place of `::/0`. This achieves nearly the same thing, but does not activate the above firewalling semantics. (The UI's editor has a checkbox that toggles this.)  And users without the need for a `/0` route at all do not have to worry about this, and instead fall back to ordinary Windows routing and DNS behavior.

### Considerations for non-`/0` Allowed IPs

When the above conditions do not apply, routing and DNS information is handed to Windows in the typical way for Windows to manage. This includes its [ordinary multihomed DNS resolution behavior](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197552%28v%3Dws.10%29) as well as its ordinary routing table resolution. Users may make use of the normal Windows firewalling and network configuration capabilities to firewall this as needed. One firewall rule is added, however, which allows the tunnel service to send and receive WireGuard packets.

### Network List Manager

Windows assigns a unique GUID to each new WireGuard adapter. The application takes pains to make this GUID deterministic, so that firewall policy (such as "public" vs "private" network categorization) can be consistently applied to the tunnel's network. This determinism is based on the configuration of the tunnel. Therefore, if the WireGuard configuration changes, so too will the unique GUID. Technical details are described in [a mailing list post](https://lists.zx2c4.com/pipermail/wireguard/2019-June/004259.html).

### Adapter Lifetime

WireGuard's network adapter is created dynamically when a tunnel is started and destroyed when a tunnel is stopped. This means that additional filters, address families, or protocols should be bound to the adapter programmatically, possibly through use of dangerous script execution in thet configuration file or by way of automatic NDIS layer binding.
