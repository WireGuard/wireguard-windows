module golang.zx2c4.com/wireguard/windows

require (
	github.com/lxn/walk v0.0.0-20190827160256-65fec213208b
	github.com/lxn/win v0.0.0-20190716185335-d1d36f0e4f48

	golang.org/x/crypto v0.0.0-20190820162420-60c769a6c586
	golang.org/x/net v0.0.0-20190827160401-ba9fcec4b297
	golang.org/x/sys v0.0.0-20190826190057-c7b8b68b1456
	golang.org/x/text v0.3.2
	golang.zx2c4.com/wireguard v0.0.20190806-0.20190827175915-26fb615b11a5
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20190827181001-94d38b5f1290
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20190716185335-d1d36f0e4f48
)

go 1.13
