package hikaricommon

import (
	"io"
	"log"
	"net"
	"time"
)

func NewBuffer() *[]byte {
	buffer := make([]byte, BufferSize)
	return &buffer
}

func CloseContext(ctx *Context) {
	if err := recover(); err != nil && err != io.EOF {
		log.Printf("err, %v\n", err)
	}

	(*ctx).Close()
}

func SetDeadline(conn *net.Conn, time *time.Time) {
	err := (*conn).SetDeadline(*time)
	if err != nil {
		panic(err)
	}
}

func Read(conn *net.Conn, buffer *[]byte) int {
	n, err := (*conn).Read(*buffer)
	if err != nil {
		panic(err)
	}

	return n
}

func ReadAtLeast(conn *net.Conn, buffer *[]byte, min int) int {
	n, err := io.ReadAtLeast(*conn, *buffer, min)
	if err != nil {
		panic(err)
	}

	return n
}

func ReadEncryptedAtLeast(conn *net.Conn, buffer *[]byte, min int, crypto *Crypto) int {
	n := ReadAtLeast(conn, buffer, min)
	d := (*buffer)[:n]
	(*crypto).Decrypt(&d)

	return n
}

func ReadFull(conn *net.Conn, buffer *[]byte) {
	_, err := io.ReadFull(*conn, *buffer)
	if err != nil {
		panic(err)
	}
}

func ReadEncryptedFull(conn *net.Conn, buffer *[]byte, crypto *Crypto) {
	ReadFull(conn, buffer)
	(*crypto).Decrypt(buffer)
}

func Write(conn *net.Conn, buffer *[]byte) {
	_, err := (*conn).Write(*buffer)
	if err != nil {
		panic(err)
	}
}

func WriteEncrypted(conn *net.Conn, buffer *[]byte, crypto *Crypto) {
	(*crypto).Encrypt(buffer)
	Write(conn, buffer)
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

	var data []byte
	var t time.Time
	for {
		// set src timeout
		t = time.Now().Add(time.Minute * SwitchTimeoutMinutes)
		SetDeadline(src, &t)

		n, err := s.Read(buf)
		if err != nil {
			if n != 0 {
				data = buf[:n]
				c.Encrypt(&data)

				_, err = d.Write(data)
				if err != nil {
					break
				}
			}

			break
		}

		data = buf[:n]
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

	var data []byte
	var t time.Time
	for {
		// set src timeout
		t = time.Now().Add(time.Minute * SwitchTimeoutMinutes)
		SetDeadline(src, &t)

		n, err := s.Read(buf)
		if err != nil {
			if n != 0 {
				data = buf[:n]
				c.Decrypt(&data)

				_, err = d.Write(data)
				if err != nil {
					break
				}
			}

			break
		}

		data = buf[:n]
		c.Decrypt(&data)

		_, err = d.Write(data)
		if err != nil {
			break
		}
	}
}
