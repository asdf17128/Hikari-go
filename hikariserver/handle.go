package hikariserver

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hikari-go/hikaricommon"
	"net"
	"strconv"
	"strings"
)

var authMap map[string]byte

func initHandle() {
	// init auth
	authMap = make(map[string]byte, len(cfg.PrivateKeyList))

	for _, k := range cfg.PrivateKeyList {
		authArray := md5.Sum([]byte(k))
		s := hex.EncodeToString(authArray[:])
		authMap[s] = 0
	}
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
	iv := make([]byte, aes.BlockSize)
	hikaricommon.ReadFull(ctx.clientConn, &iv)

	// init crypto
	var crypto hikaricommon.Crypto = hikaricommon.NewAESCrypto(&cfg.Secret, &iv)
	ctx.crypto = &crypto

	buf := hikaricommon.ReadEncrypted(ctx.clientConn, buffer, ctx.crypto)

	// ver
	ver, _ := buf.ReadByte()
	if ver != hikaricommon.HikariVer1 {
		writeHikariFail(ctx.clientConn, buffer, hikaricommon.HikariReplyVersionNotSupport, ctx.crypto)
		panic(fmt.Sprintf("hikari version '%v' not supported", ver))
	}

	// auth
	auth := make([]byte, 16)
	buf.Read(auth)
	if !isValidAuth(&auth) {
		writeHikariFail(ctx.clientConn, buffer, hikaricommon.HikariReplyAuthFail, ctx.crypto)
		panic("auth fail")
	}

	// address type
	adsType, _ := buf.ReadByte()

	var tgtAds []byte
	var tgtPort = make([]byte, 2)
	var tgtIp net.IP

	switch adsType {
	case hikaricommon.HikariAddressTypeDomainName:
		length, _ := buf.ReadByte()

		tgtAds = make([]byte, length)
		buf.Read(tgtAds)
		buf.Read(tgtPort)

		// DNS lookup
		h := string(tgtAds)
		ips, err := net.LookupIP(h)
		if err != nil {
			writeHikariFail(ctx.clientConn, buffer, hikaricommon.HikariReplyDnsResolveFail, ctx.crypto)
			panic(fmt.Sprintf("DNS resolve fail '%v', %v", h, err))
		}
		tgtIp = ips[0]

	case hikaricommon.HikariAddressTypeIpv4:
		tgtAds = make([]byte, net.IPv4len)
		buf.Read(tgtAds)
		buf.Read(tgtPort)

		tgtIp = tgtAds

	case hikaricommon.HikariAddressTypeIpv6:
		tgtAds = make([]byte, net.IPv6len)
		buf.Read(tgtAds)
		buf.Read(tgtPort)

		tgtIp = tgtAds

	default:
		panic(fmt.Sprintf("bad hikari address type '%v'", adsType))
	}

	if buf.Len() != 0 {
		panic("bad hikari request")
	}

	// connect to target
	tgtAdsStr, tgtPortStr := tgtIp.String(), strconv.Itoa(int(binary.BigEndian.Uint16(tgtPort)))
	tgt := net.JoinHostPort(tgtAdsStr, tgtPortStr)
	tgtConn, err := net.Dial("tcp", tgt)
	if err != nil {
		writeHikariFail(ctx.clientConn, buffer, hikaricommon.HikariReplyConnectTargetFail, ctx.crypto)
		panic(fmt.Sprintf("connect to target err, %v", err))
	}
	ctx.targetConn = &tgtConn

	// send hikari response
	bindAdsType, bindAds, bindPort := getBindInfo(ctx.targetConn)

	writeBuf := bytes.NewBuffer(*buffer)
	writeBuf.Reset()
	writeBuf.WriteByte(hikaricommon.HikariVer1)
	writeBuf.WriteByte(hikaricommon.HikariReplyOk)
	writeBuf.WriteByte(bindAdsType)
	writeBuf.Write(bindAds)
	writeBuf.Write(bindPort)

	hikaricommon.WriteEncryptedBuffer(ctx.clientConn, writeBuf, ctx.crypto)
}

func getBindInfo(conn *net.Conn) (byte, []byte, []byte) {
	localAds := (*conn).LocalAddr()
	localAdsArray := strings.Split(localAds.String(), ":")
	l := len(localAdsArray)

	localAdsStr := strings.Join(localAdsArray[:l-1], "")
	localPortInt, _ := strconv.Atoi(localAdsArray[l-1 : l][0])

	localIp := net.ParseIP(localAdsStr)
	tmpIp := localIp.To4()

	var bindAdsType byte
	var bindAds []byte
	var bindPort = make([]byte, 2)

	if tmpIp != nil {
		// v4
		bindAdsType = hikaricommon.HikariAddressTypeIpv4
		bindAds = tmpIp
	} else {
		// v6
		bindAdsType = hikaricommon.HikariAddressTypeIpv6
		bindAds = localIp.To16()
	}

	binary.BigEndian.PutUint16(bindPort, uint16(localPortInt))

	return bindAdsType, bindAds, bindPort
}

func writeHikariFail(conn *net.Conn, buffer *[]byte, rsp byte, crypto *hikaricommon.Crypto) {
	writeBuf := bytes.NewBuffer(*buffer)
	writeBuf.Reset()
	writeBuf.WriteByte(hikaricommon.HikariVer1)
	writeBuf.WriteByte(rsp)

	hikaricommon.WriteEncryptedBuffer(conn, writeBuf, crypto)
}
