module golang.zx2c4.com/wireguard/windows

require (
	github.com/lxn/walk v0.0.0-20191031081659-c0bb82ae46cb
	github.com/lxn/win v0.0.0-20191024121223-cc00c7492fe1
	golang.org/x/crypto v0.0.0-20191029031824-8986dd9e96cf
	golang.org/x/net v0.0.0-20191028085509-fe3aa8a45271
	golang.org/x/sys v0.0.0-20191029155521-f43be2a4598c
	golang.org/x/text v0.3.2
	golang.zx2c4.com/wireguard v0.0.20191013-0.20191030132932-4cdf805b29b1
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20191031100706-2416ba6ab1a7
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20191024121223-cc00c7492fe1
)

go 1.13
