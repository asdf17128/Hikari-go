package hikariclient

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"hikari-go/hikaricommon"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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
	// set local connection timeout
	timeout := time.Now().Add(time.Second * hikaricommon.HandshakeTimeoutSeconds)
	hikaricommon.SetDeadline(ctx.localConn, &timeout)

	buf := *buffer

	// read
	n := hikaricommon.ReadAtLeast(ctx.localConn, buffer, 1)

	protocol := buf[0]
	if protocol == 5 {
		// socks5
		readSocksAuth(ctx, buffer, n)
		readSocksRequest(ctx, buffer)
	} else {
		// HTTP proxy
		readHttpRequest(ctx, buffer, n)
	}
}

func readSocksAuth(ctx *context, buffer *[]byte, n int) {
	buf := *buffer

	if n < 2 {
		b := buf[n:]
		n += hikaricommon.ReadAtLeast(ctx.localConn, &b, 2-n)
	}

	// ver
	ver := buf[0]
	if ver != hikaricommon.Socks5Ver {
		panic(hikaricommon.SocksVerNotSupported)
	}

	// method
	reqLen := int(buf[1]) + 2

	if n == reqLen {
	} else if n < reqLen {
		b := buf[n:reqLen]
		hikaricommon.ReadFull(ctx.localConn, &b)
	} else if n > reqLen {
		panic(hikaricommon.BadSocks5AuthReq)
	}

	// response
	hikaricommon.Write(ctx.localConn, &socksAuthRsp)
}

func readSocksRequest(ctx *context, buffer *[]byte) {
	buf := *buffer

	// read
	n := hikaricommon.ReadAtLeast(ctx.localConn, buffer, 5)

	// ver
	ver := buf[0]
	if ver != hikaricommon.Socks5Ver {
		panic(hikaricommon.SocksVerNotSupported)
	}

	// command
	cmd := buf[1]
	if cmd != hikaricommon.Socks5CommandConnect {
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyCommandNotSupported)
		panic(hikaricommon.Socks5CmdNotSupported)
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
		panic(hikaricommon.Socks5AdsTypeNotSupported)
	}

	if n == reqLen {
	} else if n < reqLen {
		b := buf[n:reqLen]
		hikaricommon.ReadFull(ctx.localConn, &b)
	} else if n > reqLen {
		panic(hikaricommon.BadSocks5Req)
	}

	adsAndPortTmp := buf[4:reqLen]
	adsAndPort := make([]byte, len(adsAndPortTmp))
	copy(adsAndPort, adsAndPortTmp)

	// send hikari request
	err := sendHikariRequest(ctx, buffer, hikariAdsType, &adsAndPort)
	if err != nil {
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyGeneralServerFailure)
		panic(hikaricommon.ConnectToServerFail)
	}

	// read hikari response
	reply, bindAdsType, bindAdsAndPort, extraData := readHikariResponse(ctx, buffer)

	switch reply {
	case hikaricommon.HikariReplyOk:
		var socksAdsType byte
		switch bindAdsType {
		case hikaricommon.HikariAddressTypeIpv4:
			socksAdsType = hikaricommon.Socks5AddressTypeIpv4

		case hikaricommon.HikariAddressTypeIpv6:
			socksAdsType = hikaricommon.Socks5AddressTypeIpv6

		case hikaricommon.HikariAddressTypeDomainName:
			socksAdsType = hikaricommon.Socks5AddressTypeDomainName

		default:
			panic(hikaricommon.HikariAdsTypeNotSupported)
		}

		// response
		rspBuf := buf[0 : 4+len(*bindAdsAndPort)]
		rspBuf[0] = hikaricommon.Socks5Ver
		rspBuf[1] = hikaricommon.Socks5ReplyOk
		rspBuf[2] = hikaricommon.Socks5Rsv
		rspBuf[3] = socksAdsType
		copy(rspBuf[4:], *bindAdsAndPort)

		hikaricommon.Write(ctx.localConn, &rspBuf)

		if extraData != nil {
			hikaricommon.Write(ctx.localConn, extraData)
		}

	case hikaricommon.HikariReplyVersionNotSupport:
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyGeneralServerFailure)
		panic(hikaricommon.HikariVerNotSupported)

	case hikaricommon.HikariReplyAuthFail:
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyGeneralServerFailure)
		panic(hikaricommon.HikariAuthFail)

	case hikaricommon.HikariReplyDnsLookupFail:
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyHostUnreachable)
		panic(hikaricommon.DnsLookupFail)

	case hikaricommon.HikariReplyConnectTargetFail:
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyHostUnreachable)
		panic(hikaricommon.ConnectToTargetFail)

	default:
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyGeneralServerFailure)
		panic(hikaricommon.BadHikariReply)
	}
}

func readHttpRequest(ctx *context, buffer *[]byte, n int) {
	buf := *buffer

	// read until first HTTP request head is read
	bufLen := len(buf)
	for {
		if n > 4 && bytes.Equal(buf[n-4:n], httpHeadTail) {
			break
		}

		if n == bufLen {
			panic(hikaricommon.BadHttpProxyReq)
		}

		b := buf[n:]
		n += hikaricommon.Read(ctx.localConn, &b)
	}
	head := buf[:n]

	// parse HTTP request
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		panic(err)
	}

	// get address and port
	host := req.Host
	var tgtAds []byte
	var tgtPort int
	if i := strings.LastIndex(host, ":"); i != -1 {
		tgtAds = []byte(host[:i])
		tgtPort, _ = strconv.Atoi(host[i+1:])

	} else {
		tgtAds = []byte(host)
		tgtPort = 80 // default port 80
	}

	var adsAndPort []byte
	l := len(tgtAds)

	adsAndPort = make([]byte, l+3)
	adsAndPort[0] = byte(l)
	copy(adsAndPort[1:], tgtAds)
	binary.BigEndian.PutUint16(adsAndPort[l+1:], uint16(tgtPort))

	// process CONNECT or other HTTP request
	isConnectReq := req.Method == "CONNECT"
	var reqData []byte
	if !isConnectReq {
		reqData = make([]byte, len(head))
		copy(reqData, head)
	}

	// send hikari request
	err = sendHikariRequest(ctx, buffer, hikaricommon.HikariAddressTypeDomainName, &adsAndPort)
	if err != nil {
		panic(hikaricommon.ConnectToServerFail)
	}

	// read hikari response
	reply, _, _, extraData := readHikariResponse(ctx, buffer)

	switch reply {
	case hikaricommon.HikariReplyOk:
		if isConnectReq {
			// response
			hikaricommon.Write(ctx.localConn, &httpProxyOK)

		} else {
			// send request
			hikaricommon.WriteEncrypted(ctx.serverConn, &reqData, ctx.crypto)
		}

		if extraData != nil {
			hikaricommon.Write(ctx.localConn, extraData)
		}

	case hikaricommon.HikariReplyVersionNotSupport:
		panic(hikaricommon.HikariVerNotSupported)

	case hikaricommon.HikariReplyAuthFail:
		panic(hikaricommon.HikariAuthFail)

	case hikaricommon.HikariReplyDnsLookupFail:
		panic(hikaricommon.DnsLookupFail)

	case hikaricommon.HikariReplyConnectTargetFail:
		panic(hikaricommon.ConnectToTargetFail)

	default:
		panic(hikaricommon.BadHikariReply)
	}
}

func sendHikariRequest(ctx *context, buffer *[]byte, hikariAdsType byte, adsAndPort *[]byte) (connErr error) {
	buf := *buffer

	// connect to server
	srvConn, err := net.DialTimeout("tcp", srvAddress, time.Second*hikaricommon.DialTimeoutSeconds)
	if err != nil {
		return err
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
	rspBuf := buf[:18+len(*adsAndPort)]
	rspBuf[0] = hikaricommon.HikariVer1
	copy(rspBuf[1:17], auth)
	rspBuf[17] = hikariAdsType
	copy(rspBuf[18:], *adsAndPort)

	hikaricommon.WriteEncrypted(ctx.serverConn, &rspBuf, ctx.crypto)

	return nil
}

func readHikariResponse(ctx *context, buffer *[]byte) (reply byte, bindAdsType byte, bindAdsAndPort *[]byte, extraData *[]byte) {
	buf := *buffer

	// read
	n := hikaricommon.ReadEncryptedAtLeast(ctx.serverConn, buffer, 2, ctx.crypto)

	// ver
	ver := buf[0]
	if ver != hikaricommon.HikariVer1 {
		panic(hikaricommon.HikariVerNotSupported)
	}

	// reply
	reply = buf[1]

	switch reply {
	case hikaricommon.HikariReplyOk:
		if n < 4 {
			b := buf[n:]
			n += hikaricommon.ReadEncryptedAtLeast(ctx.serverConn, &b, 4-n, ctx.crypto)
		}

		// bind address type
		bindAdsType := buf[2]
		var reqLen int

		switch bindAdsType {
		case hikaricommon.HikariAddressTypeIpv4:
			reqLen = 5 + net.IPv4len

		case hikaricommon.HikariAddressTypeIpv6:
			reqLen = 5 + net.IPv6len

		case hikaricommon.HikariAddressTypeDomainName:
			reqLen = 5 + 1 + int(buf[3])

		default:
			panic(hikaricommon.HikariAdsTypeNotSupported)
		}

		var extraData []byte

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
		bindAdsAndPort := make([]byte, len(bindAdsAndPortTmp))
		copy(bindAdsAndPort, bindAdsAndPortTmp)

		return reply, bindAdsType, &bindAdsAndPort, &extraData

	case hikaricommon.HikariReplyVersionNotSupport:
		fallthrough

	case hikaricommon.HikariReplyAuthFail:
		fallthrough

	case hikaricommon.HikariReplyDnsLookupFail:
		fallthrough

	case hikaricommon.HikariReplyConnectTargetFail:
		return reply, 0, nil, nil

	default:
		panic(hikaricommon.BadHikariReply)
	}
}

func writeSocksFail(conn *net.Conn, buffer *[]byte, rsp byte) {
	rspBuf := (*buffer)[:2]

	rspBuf[0] = hikaricommon.Socks5Ver
	rspBuf[1] = rsp

	hikaricommon.Write(conn, &rspBuf)
}
