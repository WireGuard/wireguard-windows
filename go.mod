module golang.zx2c4.com/wireguard/windows

go 1.16

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	golang.org/x/net v0.0.0-20210220033124-5f55cee0dc0d
	golang.org/x/sys v0.0.0-20210220050731-9a76102bfb43
	golang.org/x/text v0.3.6-0.20210220033129-8f690f22cf1c
	golang.zx2c4.com/wireguard v0.0.0-20210222142647-219296a1e787
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210203225805-358658953538
)
