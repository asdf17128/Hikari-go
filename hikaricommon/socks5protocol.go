package hikaricommon

const (
	// version
	Socks5Ver byte = 5

	// auth method
	Socks5MethodNoAuth byte = 0

	// command
	Socks5CommandConnect      byte = 1
	Socks5CommandBind         byte = 2
	Socks5CommandUdpAssociate byte = 3

	// rsv
	Socks5Rsv byte = 0

	// address type
	Socks5AddressTypeIpv4       byte = 1
	Socks5AddressTypeDomainName byte = 3
	Socks5AddressTypeIpv6       byte = 4

	// reply
	Socks5ReplyOk                      byte = 0
	Socks5ReplyGeneralServerFailure    byte = 1
	Socks5ReplyConnectionNotAllowed    byte = 2
	Socks5ReplyNetworkUnreachable      byte = 3
	Socks5ReplyHostUnreachable         byte = 4
	Socks5ReplyConnectionRefused       byte = 5
	Socks5ReplyTtlExpired              byte = 6
	Socks5ReplyCommandNotSupported     byte = 7
	Socks5ReplyAddressTypeNotSupported byte = 8
)
