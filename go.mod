module golang.zx2c4.com/wireguard/windows

require (
	github.com/Microsoft/go-winio v0.4.11
	golang.org/x/crypto latest
	golang.org/x/net latest
	golang.org/x/sys latest
	golang.zx2c4.com/winipcfg latest
	golang.zx2c4.com/wireguard latest
)

replace (
	github.com/akavel/rsrc => golang.zx2c4.com/wireguard/windows pkg/rsrc
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows pkg/walk
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows pkg/walk-win
)
