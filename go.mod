module golang.zx2c4.com/wireguard/windows

require (
	github.com/lxn/walk v0.0.0-20191024083542-9936f81d38c5
	github.com/lxn/win v0.0.0-20190919090605-24c5960b03d8
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	golang.org/x/net v0.0.0-20191021144547-ec77196f6094
	golang.org/x/sys v0.0.0-20191024073052-e66fe6eb8e0c
	golang.org/x/text v0.3.2
	golang.zx2c4.com/wireguard v0.0.20191013-0.20191022095125-f7d0edd2ecf5
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20191023132229-8067c573594d
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20191024091655-c5100a61d29c
)

go 1.13
