package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

var perror = func(err error) {
	fmt.Printf("Error: %v\n", err)
}

func GCMEncrypt(key, unencryptedData []byte) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write(key)
	hash := hasher.Sum(nil)

	c, err := aes.NewCipher(hash)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, unencryptedData, nil), nil
}

func GCMDecrypt(key, encryptedData []byte) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write(key)
	hash := hasher.Sum(nil)

	c, err := aes.NewCipher(hash)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)

	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	if len(encryptedData) < nonceSize {
		return nil, errors.New("Encrypted data size and nonce size mismatched")
	}

	nonce, encryptedData := encryptedData[:nonceSize], encryptedData[nonceSize:]

	return gcm.Open(nil, nonce, encryptedData, nil)
}
