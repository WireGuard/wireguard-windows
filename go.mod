module golang.zx2c4.com/wireguard/windows

require (
	github.com/lxn/walk v0.0.0-20191001144247-31870cf268b0
	github.com/lxn/win v0.0.0-20190919090605-24c5960b03d8

	golang.org/x/crypto v0.0.0-20191002192127-34f69633bfdc
	golang.org/x/net v0.0.0-20191003171128-d98b1b443823
	golang.org/x/sys v0.0.0-20191003212358-c178f38b412c
	golang.org/x/text v0.3.2
	golang.zx2c4.com/wireguard v0.0.20190909-0.20191004094102-f2501aa6c8c0
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20191002091738-0f75593b0066
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20190919090605-24c5960b03d8
)

go 1.13
