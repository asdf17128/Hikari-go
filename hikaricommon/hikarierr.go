package hikaricommon

import "errors"

var (
	// socks errors
	SocksVerNotSupported      = errors.New("socks version not supported")
	Socks5CmdNotSupported     = errors.New("socks5 command not supported")
	Socks5AdsTypeNotSupported = errors.New("socks5 address type not supported")
	BadSocks5AuthReq          = errors.New("bad socks5 auth request")
	BadSocks5Req              = errors.New("bad socks5 request")

	// http errors
	BadHttpProxyReq = errors.New("bad HTTP proxy request")

	// hikari errors
	HikariVerNotSupported     = errors.New("hikari version not supported")
	HikariAuthFail            = errors.New("hikari auth fail")
	HikariAdsTypeNotSupported = errors.New("hikari address type not supported")
	BadHikariReply            = errors.New("bad hikari replay")
	BadHikariReq              = errors.New("bad hikari request")

	// other
	DnsLookupFail       = errors.New("dns lookup fail")
	ConnectToServerFail = errors.New("connect to server fail")
	ConnectToTargetFail = errors.New("connect to target fail")
)
