package hikariserver

import (
	"hikari-go/hikaricommon"
	"net"
)

type context struct {
	clientConn *net.Conn
	targetConn *net.Conn
	crypto     *hikaricommon.Crypto
}

func (c context) Close() {
	cc, tc := c.clientConn, c.targetConn

	if cc != nil {
		(*cc).Close()
	}

	if tc != nil {
		(*tc).Close()
	}
}
