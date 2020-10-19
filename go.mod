module golang.zx2c4.com/wireguard/windows

go 1.14

require (
	github.com/lxn/walk v0.0.0-20191128110447-55ccb3a9f5c1
	github.com/lxn/win v0.0.0-20191128105842-2da648fda5b4
	golang.org/x/crypto v0.0.0-20200709230013-948cd5f35899
	golang.org/x/net v0.0.0-20200707034311-ab3426394381
	golang.org/x/sys v0.0.0-20201020230747-6e5568b54d1a
	golang.org/x/text v0.3.3
	golang.zx2c4.com/wireguard v0.0.20200321-0.20200715051853-507f148e1c42
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20200319192453-d35a18df246f
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20191128151145-b4e4933852d5
)
