module golang.zx2c4.com/wireguard/windows

go 1.16

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20201111105847-2a20daff6a55
	golang.org/x/crypto v0.0.0-20210218145215-b8e89b74b9df
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777 // indirect
	golang.org/x/sys v0.0.0-20210218145245-beda7e5e158e
	golang.org/x/text v0.3.5
	golang.zx2c4.com/wireguard v0.0.0-20210217211927-8bf4204d2ea3
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210203225805-358658953538
)
