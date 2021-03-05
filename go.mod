module golang.zx2c4.com/wireguard/windows

go 1.16

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	golang.org/x/sys v0.0.0-20210305230114-8fe3ee5dd75b
	golang.org/x/text v0.3.6-0.20210227105805-e3aa4adf54f6
	golang.zx2c4.com/wireguard v0.0.0-20210305220617-a00464b70712
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
)
