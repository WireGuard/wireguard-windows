module golang.zx2c4.com/wireguard/windows

require (
	github.com/lxn/walk v0.0.0-20191024161928-0ee7d2cded97
	github.com/lxn/win v0.0.0-20191024121223-cc00c7492fe1
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	golang.org/x/net v0.0.0-20191021144547-ec77196f6094
	golang.org/x/sys v0.0.0-20191025090151-53bf42e6b339
	golang.org/x/text v0.3.2
	golang.zx2c4.com/wireguard v0.0.20191013-0.20191022095125-f7d0edd2ecf5
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20191025111952-2ff558f9d96b
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20191024105342-d61b1af716ca
)

go 1.13
