module golang.zx2c4.com/wireguard/windows

require (
	golang.zx2c4.com/winipcfg latest
	golang.zx2c4.com/wireguard v0.0.20190517

	golang.org/x/crypto latest
	golang.org/x/net latest
	golang.org/x/sys latest
	golang.org/x/text v0.3.0

	github.com/Microsoft/go-winio latest
	github.com/lxn/walk latest
	github.com/lxn/win latest
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows pkg/walk
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows pkg/walk-win
	github.com/Microsoft/go-winio => golang.zx2c4.com/wireguard/windows pkg/winio
)
