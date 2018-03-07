package hikariclient

import (
	"crypto/md5"
	"fmt"
	"hikari-go/hikaricommon"
	"net"
	"strconv"
	"time"
)

var auth []byte
var srvAddress string
var secretKey []byte

var socksAuthRsp = &[]byte{hikaricommon.Socks5Ver, hikaricommon.Socks5MethodNoAuth}

func initHandle() {
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

func handleConnection(conn *net.Conn) {
	ctx := &context{conn, nil, nil}
	var hikariCtx hikaricommon.Context = ctx
	defer hikaricommon.CloseContext(&hikariCtx)

	// init buffer
	buffer := hikaricommon.NewBuffer()

	// process
	processHandshake(ctx, buffer)

	// switch
	hikaricommon.SwitchEncrypted(ctx.localConn, ctx.serverConn, &hikariCtx, buffer, ctx.crypto)
}

func processHandshake(ctx *context, buffer *[]byte) {
	readSocksAuth(ctx, buffer)
	readSocksRequest(ctx, buffer)
	readHikariResponse(ctx, buffer)
}

func readSocksAuth(ctx *context, buffer *[]byte) {
	buf := *buffer

	// set local connection timeout
	timeout := time.Now().Add(time.Second * hikaricommon.HandshakeTimeoutSeconds)
	hikaricommon.SetDeadline(ctx.localConn, &timeout)

	// read
	n := hikaricommon.ReadAtLeast(ctx.localConn, buffer, 2)

	// ver
	ver := buf[0]
	if ver != hikaricommon.Socks5Ver {
		panic(fmt.Sprintf("socks version '%v' not supported", ver))
	}

	// method
	reqLen := int(buf[1]) + 2

	if n == reqLen {
	} else if n < reqLen {
		b := buf[n:reqLen]
		hikaricommon.ReadFull(ctx.localConn, &b)
	} else if n > reqLen {
		panic("bad socks auth request")
	}

	// response
	hikaricommon.Write(ctx.localConn, socksAuthRsp)
}

func readSocksRequest(ctx *context, buffer *[]byte) {
	buf := *buffer

	// read
	n := hikaricommon.ReadAtLeast(ctx.localConn, buffer, 5)

	// ver
	ver := buf[0]
	if ver != hikaricommon.Socks5Ver {
		panic(fmt.Sprintf("socks version '%v' not supported", ver))
	}

	// command
	cmd := buf[1]
	if cmd != hikaricommon.Socks5CommandConnect {
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyCommandNotSupported)
		panic(fmt.Sprintf("socks command '%v' not supported", cmd))
	}

	// ignore rsv

	// address type
	adsType := buf[3]
	var reqLen int
	var hikariAdsType byte

	switch adsType {
	case hikaricommon.Socks5AddressTypeDomainName:
		reqLen = 6 + 1 + int(buf[4])
		hikariAdsType = hikaricommon.HikariAddressTypeDomainName

	case hikaricommon.Socks5AddressTypeIpv4:
		reqLen = 6 + net.IPv4len
		hikariAdsType = hikaricommon.HikariAddressTypeIpv4

	case hikaricommon.Socks5AddressTypeIpv6:
		reqLen = 6 + net.IPv6len
		hikariAdsType = hikaricommon.HikariAddressTypeIpv6

	default:
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyAddressTypeNotSupported)
		panic(fmt.Sprintf("bad socks address type '%v'", adsType))
	}

	if n == reqLen {
	} else if n < reqLen {
		b := buf[n:reqLen]
		hikaricommon.ReadFull(ctx.localConn, &b)
	} else if n > reqLen {
		panic("bad socks request")
	}

	adsAndPortTmp := buf[4:reqLen]
	adsAndPortLen := len(adsAndPortTmp)
	adsAndPort := make([]byte, adsAndPortLen)
	copy(adsAndPort, adsAndPortTmp)

	// connect to server
	srvConn, err := net.DialTimeout("tcp", srvAddress, time.Second*hikaricommon.DialTimeoutSeconds)
	if err != nil {
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyGeneralServerFailure)
		panic(fmt.Sprintf("connect to server err, %v", err))
	}
	ctx.serverConn = &srvConn

	// set server connection timeout
	timeout := time.Now().Add(time.Second * hikaricommon.HandshakeTimeoutSeconds)
	hikaricommon.SetDeadline(ctx.serverConn, &timeout)

	// init crypto
	var crypto hikaricommon.Crypto = hikaricommon.NewAESCrypto(&secretKey, nil)
	ctx.crypto = &crypto

	// send iv
	hikaricommon.Write(ctx.serverConn, crypto.GetIV())

	// send hikari request
	rspBuf := buf[:18+adsAndPortLen]
	rspBuf[0] = hikaricommon.HikariVer1
	copy(rspBuf[1:17], auth)
	rspBuf[17] = hikariAdsType
	copy(rspBuf[18:], adsAndPort)

	hikaricommon.WriteEncrypted(ctx.serverConn, &rspBuf, ctx.crypto)
}

func readHikariResponse(ctx *context, buffer *[]byte) {
	buf := *buffer

	// read
	n := hikaricommon.ReadEncryptedAtLeast(ctx.serverConn, buffer, 2, ctx.crypto)

	// ver
	ver := buf[0]
	if ver != hikaricommon.HikariVer1 {
		panic(fmt.Sprintf("hikari version '%v' not supported", ver))
	}

	// reply
	reply := buf[1]

	switch reply {
	case hikaricommon.HikariReplyOk:
		if n < 4 {
			b := buf[n:]
			n += hikaricommon.ReadEncryptedAtLeast(ctx.serverConn, &b, 4-n, ctx.crypto)
		}

		// bind address type
		bindAdsType := buf[2]
		var reqLen int
		var socksAdsType byte

		switch bindAdsType {
		case hikaricommon.HikariAddressTypeIpv4:
			reqLen = 5 + net.IPv4len
			socksAdsType = hikaricommon.Socks5AddressTypeIpv4

		case hikaricommon.HikariAddressTypeIpv6:
			reqLen = 5 + net.IPv6len
			socksAdsType = hikaricommon.Socks5AddressTypeIpv6

		case hikaricommon.HikariAddressTypeDomainName:
			reqLen = 5 + 1 + int(buf[3])
			socksAdsType = hikaricommon.Socks5AddressTypeDomainName

		default:
			writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyGeneralServerFailure)
			panic(fmt.Sprintf("hikari address type '%v' not supported", bindAdsType))
		}

		var extraData []byte = nil

		if n == reqLen {
		} else if n < reqLen {
			b := buf[n:reqLen]
			hikaricommon.ReadEncryptedFull(ctx.serverConn, &b, ctx.crypto)
		} else if n > reqLen {
			extraDataTmp := buf[reqLen:n]
			extraData = make([]byte, len(extraDataTmp))
			copy(extraData, extraDataTmp)
		}

		bindAdsAndPortTmp := buf[3:reqLen]
		bindAdsAndPortLen := len(bindAdsAndPortTmp)
		bindAdsAndPort := make([]byte, bindAdsAndPortLen)
		copy(bindAdsAndPort, bindAdsAndPortTmp)

		// response
		rspBuf := buf[0 : 4+bindAdsAndPortLen]
		rspBuf[0] = hikaricommon.Socks5Ver
		rspBuf[1] = hikaricommon.Socks5ReplyOk
		rspBuf[2] = hikaricommon.Socks5Rsv
		rspBuf[3] = socksAdsType
		copy(rspBuf[4:], bindAdsAndPort)

		hikaricommon.Write(ctx.localConn, &rspBuf)

		if extraData != nil {
			hikaricommon.Write(ctx.localConn, &extraData)
		}

	case hikaricommon.HikariReplyVersionNotSupport:
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyGeneralServerFailure)
		panic("server: hikari version not supported")

	case hikaricommon.HikariReplyAuthFail:
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyGeneralServerFailure)
		panic("server: auth fail")

	case hikaricommon.HikariReplyDnsResolveFail:
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyHostUnreachable)
		panic("server: DNS resolve fail")

	case hikaricommon.HikariReplyConnectTargetFail:
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyHostUnreachable)
		panic("server: connect to target fail")

	default:
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyGeneralServerFailure)
		panic(fmt.Sprintf("bad hikari reply '%v'", reply))
	}
}

func writeSocksFail(conn *net.Conn, buffer *[]byte, rsp byte) {
	rspBuf := (*buffer)[:2]

	rspBuf[0] = hikaricommon.Socks5Ver
	rspBuf[1] = rsp

	hikaricommon.Write(conn, &rspBuf)
}
