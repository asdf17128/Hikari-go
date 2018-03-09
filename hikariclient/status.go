package hikariclient

import (
	"crypto/md5"
	"hikari-go/hikaricommon"
	"net"
	"strconv"
)

var (
	auth       []byte
	srvAddress string
	secretKey  []byte

	socksAuthRsp = []byte{hikaricommon.Socks5Ver, hikaricommon.Socks5MethodNoAuth}
	httpHeadTail = []byte("\r\n\r\n")
	httpProxyOK  = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
)

func initStatus() {
	// init auth
	authArray := md5.Sum([]byte(cfg.PrivateKey))
	auth = authArray[:]

	// init server address
	srvAds := cfg.ServerAddress
	srvPort := strconv.Itoa(int(cfg.ServerPort))
	srvAddress = net.JoinHostPort(srvAds, srvPort)

	// init secret key
	secretKeyArray := md5.Sum([]byte(cfg.Secret))
	secretKey = secretKeyArray[:]
}
