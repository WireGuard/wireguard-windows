module golang.zx2c4.com/wireguard/windows

go 1.16

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.0.0-20210506145944-38f3c27a63bf
	golang.org/x/net v0.0.0-20210505214959-0714010a04ed
	golang.org/x/sys v0.0.0-20210507014357-30e306a8bba5
	golang.org/x/text v0.3.7-0.20210503195748-5c7c50ebbd4f
	golang.zx2c4.com/wireguard v0.0.0-20210507110843-18ea215f0684
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
)
