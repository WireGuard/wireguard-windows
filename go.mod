module golang.zx2c4.com/wireguard/windows

require (
	github.com/lxn/walk v0.0.0-20191001144247-31870cf268b0
	github.com/lxn/win v0.0.0-20190919090605-24c5960b03d8
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	golang.org/x/net v0.0.0-20191014212845-da9a3fd4c582
	golang.org/x/sys v0.0.0-20191020212454-3e7259c5e7c2
	golang.org/x/text v0.3.2
	golang.zx2c4.com/wireguard v0.0.20191013-0.20191021112957-ffffbbcc8a33
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20191002091738-0f75593b0066
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20190919090605-24c5960b03d8
)

go 1.13
