module golang.zx2c4.com/wireguard/windows

go 1.15

require (
	github.com/lxn/walk v0.0.0-20201125094449-2a61ddb5a2b8
	github.com/lxn/win v0.0.0-20201111105847-2a20daff6a55
	golang.org/x/crypto v0.0.0-20201124201722-c8d3bf9c5392
	golang.org/x/net v0.0.0-20201201195509-5d6afe98e0b7
	golang.org/x/sys v0.0.0-20201201145000-ef89a241ccb3
	golang.org/x/text v0.3.5-0.20201125200606-c27b9fd57aec
	golang.zx2c4.com/wireguard v0.0.20201119-0.20201127121345-b6303091fc8c
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20201130211600-76ef01985b1c
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20201107183008-659a4e955570
)
