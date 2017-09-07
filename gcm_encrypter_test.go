package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGCMEncryptDecrypt(t *testing.T) {
	data := []byte("My plaintext data.")
	key := []byte("keytoencrypt")

	encrypted, err := GCMEncrypt(key, data)
	assert.Nil(t, err)
	assert.NotNil(t, encrypted)

	decrypted, err := GCMDecrypt(key, encrypted)
	assert.Nil(t, err)
	assert.NotNil(t, decrypted)
	assert.Equal(t, data, decrypted)
}
