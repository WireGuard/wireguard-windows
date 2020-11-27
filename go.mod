module golang.zx2c4.com/wireguard/windows

go 1.15

require (
	github.com/lxn/walk v0.0.0-20201125094449-2a61ddb5a2b8
	github.com/lxn/win v0.0.0-20201111105847-2a20daff6a55
	golang.org/x/crypto v0.0.0-20201124201722-c8d3bf9c5392
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sys v0.0.0-20201126233918-771906719818
	golang.org/x/text v0.3.5-0.20201125200606-c27b9fd57aec
	golang.zx2c4.com/wireguard v0.0.20201119-0.20201127121345-b6303091fc8c
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20201123164346-1fc068baa19b
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20201107183008-659a4e955570
)
