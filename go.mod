module golang.zx2c4.com/wireguard/windows

go 1.15

require (
	github.com/lxn/walk v0.0.0-20201110160827-18ea5e372cdb
	github.com/lxn/win v0.0.0-20201105135849-85a11ff06ebc
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sys v0.0.0-20201109165425-215b40eba54c
	golang.org/x/text v0.3.4
	golang.zx2c4.com/wireguard v0.0.20200321-0.20201107205632-82128c47d90a
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20201110162739-c2882a58687c
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20201107183008-659a4e955570
)
