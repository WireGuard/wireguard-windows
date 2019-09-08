module golang.zx2c4.com/wireguard/windows

require (

	github.com/lxn/walk v0.0.0-20190909123447-3b9dbc29e916
	github.com/lxn/win v0.0.0-20190910083938-ae3bd9765f46

	golang.org/x/crypto v0.0.0-20190911031432-227b76d455e7
	golang.org/x/net v0.0.0-20190912160710-24e19bdeb0f2
	golang.org/x/sys v0.0.0-20190913121621-c3b328c6e5a7
	golang.org/x/text v0.3.2
	golang.zx2c4.com/wireguard v0.0.20190909-0.20190908185244-bb0b2514c053
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20190913154401-8611d125746a
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20190910083938-ae3bd9765f46
)

go 1.13
