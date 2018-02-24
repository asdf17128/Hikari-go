package hikariclient

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"hikari-go/hikaricommon"
	"net"
	"strconv"
)

var auth []byte
var srvAddress string

func initHandle() {
	// init auth
	authArray := md5.Sum([]byte(cfg.PrivateKey))
	auth = authArray[:]

	// init server address
	srvAds := cfg.ServerAddress
	srvPort := strconv.Itoa(int(cfg.ServerPort))
	srvAddress = net.JoinHostPort(srvAds, srvPort)
}

func handleConnection(conn *net.Conn) {
	ctx := context{conn, nil, nil}
	var hikariCtx hikaricommon.Context = ctx
	defer hikaricommon.CloseContext(&hikariCtx)

	// init buffer
	buffer := hikaricommon.NewBuffer()

	// process
	processHandshake(&ctx, buffer)

	// switch
	hikaricommon.SwitchEncrypted(ctx.localConn, ctx.serverConn, &hikariCtx, buffer, ctx.crypto)
}

func processHandshake(ctx *context, buffer *[]byte) {
	readSocksAuth(ctx, buffer)
	readSocksRequest(ctx, buffer)
	readHikariResponse(ctx, buffer)
}

func readSocksAuth(ctx *context, buffer *[]byte) {
	// read
	buf := hikaricommon.ReadPlain(ctx.localConn, buffer)

	// ver
	ver, _ := buf.ReadByte()
	if ver != hikaricommon.Socks5Ver {
		panic(fmt.Sprintf("socks version '%v' not supported", ver))
	}

	// method
	mtdLen, _ := buf.ReadByte()
	if int(mtdLen) != buf.Len() {
		panic("bad socks auth request")
	}

	// response
	writeBuf := bytes.NewBuffer(*buffer)
	writeBuf.Reset()
	writeBuf.WriteByte(hikaricommon.Socks5Ver)
	writeBuf.WriteByte(hikaricommon.Socks5MethodNoAuth)

	hikaricommon.WritePlainBuffer(ctx.localConn, writeBuf)
}

func readSocksRequest(ctx *context, buffer *[]byte) {
	// read
	buf := hikaricommon.ReadPlain(ctx.localConn, buffer)

	// ver
	buf.ReadByte()

	// command
	cmd, _ := buf.ReadByte()
	if cmd != hikaricommon.Socks5CommandConnect {
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyCommandNotSupported)
		panic(fmt.Sprintf("socks command '%v' not supported", cmd))
	}

	// rsv
	buf.ReadByte()

	// address type
	adsType, _ := buf.ReadByte()

	var hikariAdsType byte
	var ads []byte
	var port = make([]byte, 2)

	switch adsType {
	case hikaricommon.Socks5AddressTypeDomainName:
		hikariAdsType = hikaricommon.HikariAddressTypeDomainName

		length, _ := buf.ReadByte()
		ads = make([]byte, length)
		buf.Read(ads)
		buf.Read(port)

	case hikaricommon.Socks5AddressTypeIpv4:
		hikariAdsType = hikaricommon.HikariAddressTypeIpv4

		ads = make([]byte, net.IPv4len)
		buf.Read(ads)
		buf.Read(port)

	case hikaricommon.Socks5AddressTypeIpv6:
		hikariAdsType = hikaricommon.HikariAddressTypeIpv6

		ads = make([]byte, net.IPv6len)
		buf.Read(ads)
		buf.Read(port)

	default:
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyAddressTypeNotSupported)
		panic(fmt.Sprintf("bad socks address type '%v'", adsType))
	}

	if buf.Len() != 0 {
		panic("bad socks request")
	}

	// connect to server
	srvConn, err := net.Dial("tcp", srvAddress)
	if err != nil {
		writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyGeneralServerFailure)
		panic(fmt.Sprintf("connect to server err, %v", err))
	}
	ctx.serverConn = &srvConn

	// init crypto
	var crypto hikaricommon.Crypto = hikaricommon.NewAESCrypto(&cfg.Secret, nil)
	ctx.crypto = &crypto

	// send iv
	hikaricommon.WritePlain(ctx.serverConn, crypto.GetIV())

	// send hikari request
	writeBuf := bytes.NewBuffer(*buffer)
	writeBuf.Reset()
	writeBuf.WriteByte(hikaricommon.HikariVer1)
	writeBuf.Write(auth[:])
	writeBuf.WriteByte(hikariAdsType)
	if hikariAdsType == hikaricommon.HikariAddressTypeDomainName {
		writeBuf.WriteByte(byte(len(ads)))
	}
	writeBuf.Write(ads)
	writeBuf.Write(port)

	hikaricommon.WriteEncryptedBuffer(ctx.serverConn, writeBuf, ctx.crypto)
}

func readHikariResponse(ctx *context, buffer *[]byte) {
	buf := hikaricommon.ReadEncrypted(ctx.serverConn, buffer, ctx.crypto)

	// ver
	buf.ReadByte()

	// reply
	reply, _ := buf.ReadByte()

	switch reply {
	case hikaricommon.HikariReplyOk:
		// bind address type
		bindAdsType, _ := buf.ReadByte()

		var socksAdsType byte
		var bindAds []byte
		var bindPort = make([]byte, 2)

		switch bindAdsType {
		case hikaricommon.HikariAddressTypeIpv4:
			socksAdsType = hikaricommon.Socks5AddressTypeIpv4

			bindAds = make([]byte, net.IPv4len)
			buf.Read(bindAds)
			buf.Read(bindPort)

		case hikaricommon.HikariAddressTypeIpv6:
			socksAdsType = hikaricommon.Socks5AddressTypeIpv6

			bindAds = make([]byte, net.IPv6len)
			buf.Read(bindAds)
			buf.Read(bindPort)

		case hikaricommon.HikariAddressTypeDomainName:
			socksAdsType = hikaricommon.Socks5AddressTypeDomainName

			bindAdsLen, _ := buf.ReadByte()
			bindAds = make([]byte, bindAdsLen)
			buf.Read(bindAds)
			buf.Read(bindPort)

		default:
			writeSocksFail(ctx.localConn, buffer, hikaricommon.Socks5ReplyGeneralServerFailure)
			panic(fmt.Sprintf("bad hikari address type '%v'", bindAdsType))
		}

		// left data
		var leftData *bytes.Buffer = nil
		if l := buf.Len(); l != 0 {
			leftDataSlice := make([]byte, l)
			buf.Read(leftDataSlice)

			leftData = bytes.NewBuffer(leftDataSlice)
		}

		// response
		writeBuf := bytes.NewBuffer(*buffer)
		writeBuf.Reset()
		writeBuf.WriteByte(hikaricommon.Socks5Ver)
		writeBuf.WriteByte(hikaricommon.Socks5ReplyOk)
		writeBuf.WriteByte(hikaricommon.Socks5Rsv)
		writeBuf.WriteByte(socksAdsType)
		if socksAdsType == hikaricommon.Socks5AddressTypeDomainName {
			writeBuf.WriteByte(byte(len(bindAds)))
		}
		writeBuf.Write(bindAds)
		writeBuf.Write(bindPort)

		hikaricommon.WritePlainBuffer(ctx.localConn, writeBuf)

		// write left data
		if leftData != nil {
			hikaricommon.WritePlainBuffer(ctx.localConn, leftData)
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
	writeBuf := bytes.NewBuffer(*buffer)
	writeBuf.Reset()
	writeBuf.WriteByte(hikaricommon.Socks5Ver)
	writeBuf.WriteByte(rsp)

	hikaricommon.WritePlainBuffer(conn, writeBuf)
}
