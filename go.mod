module golang.zx2c4.com/wireguard/windows

go 1.15

require (
	github.com/lxn/walk v0.0.0-20201110160827-18ea5e372cdb
	github.com/lxn/win v0.0.0-20201111105847-2a20daff6a55
	golang.org/x/crypto v0.0.0-20201112155050-0c6587e931a9
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sys v0.0.0-20201112073958-5cba982894dd
	golang.org/x/text v0.3.4
	golang.zx2c4.com/wireguard v0.0.20200321-0.20201111175144-60b3766b89b9
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20201113131926-392e51239a14
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20201107183008-659a4e955570
)
