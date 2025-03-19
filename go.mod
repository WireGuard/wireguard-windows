module golang.zx2c4.com/wireguard/windows

go 1.20

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.33.0
	golang.org/x/sys v0.30.0
	golang.org/x/text v0.22.0
)

require (
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
)
