module golang.zx2c4.com/wireguard/windows

require (
	github.com/lxn/walk v0.0.0-20190905152318-015262c282d6
	github.com/lxn/win v0.0.0-20190905152257-9739bfe37f9b

	golang.org/x/crypto v0.0.0-20190829043050-9756ffdc2472
	golang.org/x/net v0.0.0-20190827160401-ba9fcec4b297
	golang.org/x/sys v0.0.0-20190904154756-749cb33beabd
	golang.org/x/text v0.3.2
	golang.zx2c4.com/wireguard v0.0.20190806-0.20190906034821-d12eb91f9a30
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20190905200702-9ca6b26cc0f5
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20190905152257-9739bfe37f9b
)

go 1.13
