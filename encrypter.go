package crip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"io"
	"log"
	"math/rand"
)

// GenerateCommonIV generates an initialization vector based on
// the specified seed. Initialization vector is set to 16 bytes in size.
func GenerateCommonIV(seed int64) ([]byte, error) {
	bytes := make([]byte, 16)

	rand.Seed(seed)

	for i := 0; i < 16; i++ {
		bytes[i] = byte(rand.Int63() % 16)
	}

	return bytes, nil
}

// Encrypt takes the bytes specified and encrypts them using the key
// and initialization vector specified.  It returns the resulting slice.
func Encrypt(key string, iv []byte, bytes []byte) ([]byte, error) {
	block, err := NewCipher(key)

	if err != nil {
		return nil, err
	}

	encryptor := cipher.NewCFBEncrypter(block, iv)
	cipherText := make([]byte, len(bytes))
	encryptor.XORKeyStream(cipherText, bytes)

	return cipherText, nil
}

// Decrypt takes the bytes specified and decrypts them using the key
// and intialization vector specified.  It returns the resulting slice.
func Decrypt(key string, iv []byte, bytes []byte) ([]byte, error) {
	block, err := NewCipher(key)

	if err != nil {
		return nil, err
	}

	decryptor := cipher.NewCFBDecrypter(block, iv)
	plainText := make([]byte, len(bytes))
	decryptor.XORKeyStream(plainText, bytes)

	return plainText, nil
}

// NewCipher generates a cipher block using the specified key
// as the source.  The specified key is a string that is passed in
// to the function and used to generate a SHA-256 hash.  The hash
// is then used to generate the cipher block.
func NewCipher(key string) (cipher.Block, error) {

	if key == "" {
		return nil, errors.New("Cannot provide empty key")
	}

	hasher := sha256.New()
	io.WriteString(hasher, key)

	c, err := aes.NewCipher(hasher.Sum(nil))
	if err != nil {
		log.Printf("Got error: %v", err)
		return nil, err
	}
	return c, nil
}
