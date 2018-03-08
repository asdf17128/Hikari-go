package hikariserver

import (
	"crypto/aes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"hikari-go/hikaricommon"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	authMap   map[string]byte
	secretKey []byte
)

func initHandle() {
	// init auth
	authMap = make(map[string]byte, len(cfg.PrivateKeyList))

	for _, k := range cfg.PrivateKeyList {
		authArray := md5.Sum([]byte(k))
		s := hex.EncodeToString(authArray[:])
		authMap[s] = 0
	}

	// init secret key
	secretKeyArray := md5.Sum([]byte(cfg.Secret))
	secretKey = secretKeyArray[:]
}

func handleConnection(conn *net.Conn) {
	ctx := &context{conn, nil, nil}
	var hikariCtx hikaricommon.Context = ctx
	defer hikaricommon.CloseContext(&hikariCtx)

	// init buffer
	buffer := hikaricommon.NewBuffer()

	// process
	processHandshake(ctx, buffer)

	// switch
	hikaricommon.SwitchEncrypted(ctx.targetConn, ctx.clientConn, &hikariCtx, buffer, ctx.crypto)
}

func isValidAuth(auth *[]byte) bool {
	s := hex.EncodeToString(*auth)
	_, exits := authMap[s]

	return exits
}

func processHandshake(ctx *context, buffer *[]byte) {
	readHikariRequest(ctx, buffer)
}

func readHikariRequest(ctx *context, buffer *[]byte) {
	buf := *buffer

	// set client connection timeout
	timeout := time.Now().Add(time.Second * hikaricommon.HandshakeTimeoutSeconds)
	hikaricommon.SetDeadline(ctx.clientConn, &timeout)

	iv := make([]byte, aes.BlockSize)
	hikaricommon.ReadFull(ctx.clientConn, &iv)

	// init crypto
	var crypto hikaricommon.Crypto = hikaricommon.NewAESCrypto(&secretKey, &iv)
	ctx.crypto = &crypto

	n := hikaricommon.ReadEncryptedAtLeast(ctx.clientConn, buffer, 19, ctx.crypto)

	// ver
	ver := buf[0]
	if ver != hikaricommon.HikariVer1 {
		writeHikariFail(ctx.clientConn, buffer, hikaricommon.HikariReplyVersionNotSupport, ctx.crypto)
		panic(hikaricommon.HikariVerNotSupported)
	}

	// auth
	auth := buf[1:17]
	if !isValidAuth(&auth) {
		writeHikariFail(ctx.clientConn, buffer, hikaricommon.HikariReplyAuthFail, ctx.crypto)
		panic(hikaricommon.AuthFail)
	}

	// address type
	adsType := buf[17]
	var reqLen int
	var ads, port []byte

	switch adsType {
	case hikaricommon.HikariAddressTypeDomainName:
		adsLen := int(buf[18])
		reqLen = 20 + 1 + adsLen

		i := 19 + adsLen
		ads = buf[19:i]
		port = buf[i:reqLen]

	case hikaricommon.HikariAddressTypeIpv4:
		reqLen = 20 + net.IPv4len

		i := 18 + net.IPv4len
		ads = buf[18:i]
		port = buf[i:reqLen]

	case hikaricommon.HikariAddressTypeIpv6:
		reqLen = 20 + net.IPv6len

		i := 18 + net.IPv6len
		ads = buf[18:i]
		port = buf[i:reqLen]

	default:
		panic(hikaricommon.HikariAdsTypeNotSupported)
	}

	if n == reqLen {
	} else if n < reqLen {
		b := buf[n:reqLen]
		hikaricommon.ReadEncryptedFull(ctx.clientConn, &b, ctx.crypto)
	} else if n > reqLen {
		panic(hikaricommon.BadHikariReq)
	}

	// connect to target
	var ipList []net.IP
	if adsType == hikaricommon.HikariAddressTypeDomainName {
		// DNS lookup
		host := string(ads)
		ips, err := net.LookupIP(host)
		if err != nil {
			writeHikariFail(ctx.clientConn, buffer, hikaricommon.HikariReplyDnsLookupFail, ctx.crypto)
			log.Println("dns lookup fail:", err)
			panic(hikaricommon.DnsLookupFail)
		}
		ipList = ips
	} else {
		ipList = []net.IP{ads}
	}

	var tgtConn net.Conn
	portStr := strconv.Itoa(int(binary.BigEndian.Uint16(port)))
	for _, ip := range ipList {
		ipStr := ip.String()
		tgt := net.JoinHostPort(ipStr, portStr)

		conn, err := net.DialTimeout("tcp", tgt, time.Second*hikaricommon.DialTimeoutSeconds)
		if err != nil {
			log.Println("connect to target fail:", tgt)
			continue
		} else {
			tgtConn = conn
			break
		}
	}

	if tgtConn == nil {
		writeHikariFail(ctx.clientConn, buffer, hikaricommon.HikariReplyConnectTargetFail, ctx.crypto)
		panic(hikaricommon.ConnectToTargetFail)
	}

	// set context
	ctx.targetConn = &tgtConn

	// send hikari response
	bindAdsType, bindAds, bindPort := getBindInfo(ctx.targetConn)
	bindAdsLen := len(bindAds)
	i := 3 + bindAdsLen

	rspBuf := buf[0 : 5+bindAdsLen]
	rspBuf[0] = hikaricommon.HikariVer1
	rspBuf[1] = hikaricommon.HikariReplyOk
	rspBuf[2] = bindAdsType
	copy(rspBuf[3:i], bindAds)
	binary.BigEndian.PutUint16(rspBuf[i:], uint16(bindPort))

	hikaricommon.WriteEncrypted(ctx.clientConn, &rspBuf, ctx.crypto)
}

func getBindInfo(conn *net.Conn) (byte, []byte, int) {
	localAdsPortStr := (*conn).LocalAddr().String()
	i := strings.LastIndex(localAdsPortStr, ":")

	localAdsStr := localAdsPortStr[0:i]
	localPortStr := localAdsPortStr[i+1:]
	localPortInt, _ := strconv.Atoi(localPortStr)

	localIp := net.ParseIP(localAdsStr)
	tmpIp := localIp.To4()

	var bindAdsType byte
	var bindAds []byte

	if tmpIp != nil {
		// v4
		bindAdsType = hikaricommon.HikariAddressTypeIpv4
		bindAds = tmpIp
	} else {
		// v6
		bindAdsType = hikaricommon.HikariAddressTypeIpv6
		bindAds = localIp.To16()
	}

	return bindAdsType, bindAds, localPortInt
}

func writeHikariFail(conn *net.Conn, buffer *[]byte, rsp byte, crypto *hikaricommon.Crypto) {
	rspBuf := (*buffer)[:2]

	rspBuf[0] = hikaricommon.HikariVer1
	rspBuf[1] = rsp

	hikaricommon.WriteEncrypted(conn, &rspBuf, crypto)
}
