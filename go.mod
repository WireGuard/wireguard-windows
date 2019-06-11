module golang.zx2c4.com/wireguard/windows

require (
	golang.zx2c4.com/wireguard 3371f8dac6fe6bbd7522a8316b50f6473012e302

	golang.org/x/crypto latest
	golang.org/x/net latest
	golang.org/x/sys latest
	golang.org/x/text v0.3.0

	github.com/lxn/walk latest
	github.com/lxn/win latest
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows pkg/walk
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows pkg/walk-win
)
