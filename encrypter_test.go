package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const TESTKEY = "testkey"
const TESTPAYLOAD = "Now is the time for all good men to come to the aid of their country."

func TestGenerateCommonIV(t *testing.T) {
	bytes, err := GenerateCommonIV(1)
	assert.Nil(t, err)
	assert.Equal(t, 16, len(bytes))
}

func TestEncryptDecrypt(t *testing.T) {
	iv, err := GenerateCommonIV(1)
	assert.Nil(t, err)
	encrypted, err := Encrypt(TESTKEY, iv, []byte(TESTPAYLOAD))
	assert.Nil(t, err)
	assert.NotNil(t, encrypted)
	decrypted, err := Decrypt(TESTKEY, iv, encrypted)
	assert.Nil(t, err)
	assert.NotNil(t, decrypted)
	assert.Equal(t, string(decrypted), TESTPAYLOAD)
}

func TestNewCipher(t *testing.T) {
	cipher, err := NewCipher(TESTKEY)
	assert.Nil(t, err)
	assert.NotNil(t, cipher)
}

func TestNewCipherEmptyKey(t *testing.T) {
	cipher, err := NewCipher("")
	assert.NotNil(t, err)
	assert.Nil(t, cipher)
}
