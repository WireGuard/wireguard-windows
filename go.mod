module golang.zx2c4.com/wireguard/windows

require (
	github.com/lxn/walk v0.0.0-20190923074432-2011aca68435
	github.com/lxn/win v0.0.0-20190919090605-24c5960b03d8

	golang.org/x/crypto v0.0.0-20190923035154-9ee001bba392
	golang.org/x/net v0.0.0-20190921015927-1a5e07d1ff72
	golang.org/x/sys v0.0.0-20190922100055-0a153f010e69
	golang.org/x/text v0.3.2
	golang.zx2c4.com/wireguard v0.0.20190909-0.20190922100135-5774e6be91d3
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20190923132714-5140ce15c7bb
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20190919090605-24c5960b03d8
)

go 1.13
