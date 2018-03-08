package hikaricommon

import "errors"

var (
	// errors
	SocksVerNotSupported      = errors.New("socks version not supported")
	Socks5CmdNotSupported     = errors.New("socks5 command not supported")
	Socks5AdsTypeNotSupported = errors.New("socks5 address type not supported")
	BadSocks5AuthReq          = errors.New("bad socks5 auth request")
	BadSocks5Req              = errors.New("bad socks5 request")
	ConnectToServerFail       = errors.New("connect to server fail")
	HikariAdsTypeNotSupported = errors.New("hikari address type not supported")
	HikariVerNotSupported     = errors.New("hikari version not supported")
	AuthFail                  = errors.New("auth fail")
	DnsLookupFail             = errors.New("dns lookup fail")
	ConnectToTargetFail       = errors.New("connect to target fail")
	BadHikariReply            = errors.New("bad hikari replay")
	BadHikariReq              = errors.New("bad hikari request")
)
