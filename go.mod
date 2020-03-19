module golang.zx2c4.com/wireguard/windows

go 1.14

require (
	github.com/lxn/walk v0.0.0-20191128110447-55ccb3a9f5c1
	github.com/lxn/win v0.0.0-20191128105842-2da648fda5b4
	golang.org/x/crypto v0.0.0-20200320181102-891825fb96df
	golang.org/x/net v0.0.0-20200320220750-118fecf932d8
	golang.org/x/sys v0.0.0-20200320181252-af34d8274f85
	golang.org/x/text v0.3.3-0.20200306154105-06d492aade88
	golang.zx2c4.com/wireguard v0.0.20200320
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20200319192453-d35a18df246f
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20191128151145-b4e4933852d5
)
