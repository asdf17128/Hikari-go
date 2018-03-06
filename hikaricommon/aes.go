package hikaricommon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type AESCrypto struct {
	iv        *[]byte
	encStream *cipher.Stream
	decStream *cipher.Stream
}

func NewAESCrypto(key *[]byte, iv *[]byte) *AESCrypto {
	if iv == nil {
		ivArray := make([]byte, aes.BlockSize)
		io.ReadFull(rand.Reader, ivArray)
		iv = &ivArray
	}

	block, _ := aes.NewCipher(*key)

	encStream := cipher.NewCFBEncrypter(block, *iv)
	decStream := cipher.NewCFBDecrypter(block, *iv)

	return &AESCrypto{iv, &encStream, &decStream}
}

func (c *AESCrypto) Encrypt(in *[]byte) {
	(*c.encStream).XORKeyStream(*in, *in)
}

func (c *AESCrypto) Decrypt(in *[]byte) {
	(*c.decStream).XORKeyStream(*in, *in)
}

func (c *AESCrypto) GetIV() *[]byte {
	return c.iv
}
