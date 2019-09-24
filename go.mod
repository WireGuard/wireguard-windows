module golang.zx2c4.com/wireguard/windows

require (
	github.com/lxn/walk v0.0.0-20190923074432-2011aca68435
	github.com/lxn/win v0.0.0-20190919090605-24c5960b03d8

	golang.org/x/crypto v0.0.0-20190926180335-cea2066c6411
	golang.org/x/net v0.0.0-20190926025831-c00fd9afed17
	golang.org/x/sys v0.0.0-20190926180325-855e68c8590b
	golang.org/x/text v0.3.2
	golang.zx2c4.com/wireguard v0.0.20190909-0.20190926195357-e90ae94ff879
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20190923132714-5140ce15c7bb
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20190919090605-24c5960b03d8
)

go 1.13
