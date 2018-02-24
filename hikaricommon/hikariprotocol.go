package hikaricommon

const (
	// version
	HikariVer1 byte = 1

	// address type
	HikariAddressTypeIpv4       byte = 0
	HikariAddressTypeIpv6       byte = 1
	HikariAddressTypeDomainName byte = 2

	// address type
	HikariReplyOk                byte = 0
	HikariReplyVersionNotSupport byte = 1
	HikariReplyAuthFail          byte = 2
	HikariReplyDnsResolveFail    byte = 3
	HikariReplyConnectTargetFail byte = 4
)
