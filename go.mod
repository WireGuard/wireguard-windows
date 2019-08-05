module golang.zx2c4.com/wireguard/windows

require (

	github.com/lxn/walk v0.0.0-20190619151032-86d8802c197a
	github.com/lxn/win v0.0.0-20190716185335-d1d36f0e4f48

	golang.org/x/crypto v0.0.0-20190701094942-4def268fd1a4
	golang.org/x/net v0.0.0-20190724013045-ca1201d0de80
	golang.org/x/sys v0.0.0-20190804053845-51ab0e2deafa
	golang.org/x/text v0.3.2
	golang.zx2c4.com/wireguard v0.0.20190518-0.20190803171121-b4010123f744
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20190805105226-f45fe1072ff1
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20190716185335-d1d36f0e4f48
)
