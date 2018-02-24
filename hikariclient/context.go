package hikariclient

import (
	"hikari-go/hikaricommon"
	"net"
)

type context struct {
	localConn  *net.Conn
	serverConn *net.Conn
	crypto     *hikaricommon.Crypto
}

func (c context) Close() {
	lc, sc := c.localConn, c.serverConn

	if lc != nil {
		(*lc).Close()
	}

	if sc != nil {
		(*sc).Close()
	}
}
