package hikaricommon

import (
	"bytes"
	"log"
	"net"
)

func NewBuffer() *[]byte {
	buffer := make([]byte, BufferSize)
	return &buffer
}

func CloseContext(ctx *Context) {
	if err := recover(); err != nil {
		log.Printf("err, %v\n", err)
	}

	(*ctx).Close()
}

func ReadFull(conn *net.Conn, buffer *[]byte) {
	n, err := (*conn).Read(*buffer)
	if err != nil {
		panic(err)
	}

	if n != len(*buffer) {
		panic("read err")
	}
}

func ReadPlain(conn *net.Conn, buffer *[]byte) *bytes.Buffer {
	n, err := (*conn).Read(*buffer)
	if err != nil {
		panic(err)
	}

	data := (*buffer)[:n]
	return bytes.NewBuffer(data)
}

func ReadEncrypted(conn *net.Conn, buffer *[]byte, crypto *Crypto) *bytes.Buffer {
	n, err := (*conn).Read(*buffer)
	if err != nil {
		panic(err)
	}

	data := (*buffer)[:n]
	(*crypto).Decrypt(&data)
	return bytes.NewBuffer(data)
}

func WritePlain(conn *net.Conn, data *[]byte) {
	n, err := (*conn).Write(*data)
	if err != nil {
		panic(err)
	}

	if n != len(*data) {
		panic("write err")
	}
}

func WritePlainBuffer(conn *net.Conn, buffer *bytes.Buffer) {
	data := buffer.Bytes()
	WritePlain(conn, &data)
}

func WriteEncrypted(conn *net.Conn, data *[]byte, crypto *Crypto) {
	(*crypto).Encrypt(data)
	WritePlain(conn, data)
}

func WriteEncryptedBuffer(conn *net.Conn, buffer *bytes.Buffer, crypto *Crypto) {
	data := buffer.Bytes()
	(*crypto).Encrypt(&data)
	WritePlain(conn, &data)
}

func SwitchEncrypted(plainConn *net.Conn, encryptedConn *net.Conn, ctx *Context, buffer *[]byte, crypto *Crypto) {
	go pipePlain(plainConn, encryptedConn, ctx, NewBuffer(), crypto)
	pipeEncrypted(encryptedConn, plainConn, ctx, buffer, crypto)
}

func pipePlain(src *net.Conn, dst *net.Conn, ctx *Context, buffer *[]byte, crypto *Crypto) {
	defer CloseContext(ctx)

	s := *src
	d := *dst
	buf := *buffer
	c := *crypto

	for {
		n, err := s.Read(buf)
		if err != nil {
			if n != 0 {
				data := buf[:n]
				c.Encrypt(&data)

				_, err = d.Write(data)
				if err != nil {
					break
				}
			}

			break
		}

		data := buf[:n]
		c.Encrypt(&data)

		_, err = d.Write(data)
		if err != nil {
			break
		}
	}
}

func pipeEncrypted(src *net.Conn, dst *net.Conn, ctx *Context, buffer *[]byte, crypto *Crypto) {
	defer CloseContext(ctx)

	s := *src
	d := *dst
	buf := *buffer
	c := *crypto

	for {
		n, err := s.Read(buf)
		if err != nil {
			if n != 0 {
				data := buf[:n]
				c.Decrypt(&data)

				_, err = d.Write(data)
				if err != nil {
					break
				}
			}

			break
		}

		data := buf[:n]
		c.Decrypt(&data)

		_, err = d.Write(data)
		if err != nil {
			break
		}
	}
}
