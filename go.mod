module golang.zx2c4.com/wireguard/windows

go 1.18

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3
	golang.org/x/net v0.0.0-20211215060638-4ddde0e984e9
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e
	golang.org/x/text v0.3.8-0.20211105212822-18b340fc7af2
)

require (
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/tools v0.1.7 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
)
