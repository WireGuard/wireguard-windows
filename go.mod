module golang.zx2c4.com/wireguard/windows

go 1.16

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.0.0-20210503195802-e9a32991a82e
	golang.org/x/net v0.0.0-20210505024714-0287a6fb4125
	golang.org/x/sys v0.0.0-20210503173754-0981d6026fa6
	golang.org/x/text v0.3.7-0.20210503195748-5c7c50ebbd4f
	golang.zx2c4.com/wireguard v0.0.0-20210505094245-69a42a4eefc7
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
)
