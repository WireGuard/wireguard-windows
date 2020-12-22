module golang.zx2c4.com/wireguard/windows

go 1.15

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20201111105847-2a20daff6a55
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777
	golang.org/x/sys v0.0.0-20210123231150-1d476976d117
	golang.org/x/text v0.3.5
	golang.zx2c4.com/wireguard v0.0.20201119-0.20210120232502-fcc8ad05df75
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20201107183008-659a4e955570
)
