module golang.zx2c4.com/wireguard/windows

go 1.17

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.0.0-20211108221036-ceb1ce70b4fa
	golang.org/x/net v0.0.0-20211111083644-e5c967477495
	golang.org/x/sys v0.0.0-20211110154304-99a53858aa08
	golang.org/x/text v0.3.8-0.20211105212822-18b340fc7af2
	golang.zx2c4.com/go118/netip v0.0.0-20211111135330-a4a02eeacf9d
)

require (
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/tools v0.1.7 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
	golang.org/x/sys => golang.zx2c4.com/wireguard/windows v0.0.0-20211029170807-5c05bdce0504
)
