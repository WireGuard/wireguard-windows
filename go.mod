module golang.zx2c4.com/wireguard/windows

go 1.16

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/net v0.0.0-20210410081132-afb366fc7cd1
	golang.org/x/sys v0.0.0-20210403161142-5e06dd20ab57
	golang.org/x/text v0.3.7-0.20210411120140-c2d28a6ddf6c
	golang.zx2c4.com/wireguard v0.0.0-20210412171932-47966ded1f1e
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
)
