package crypt

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreatePrivateKey(t *testing.T) {
	store := setup("")
	store.Authenticate("password")
	newKey, newKeyErr := store.GeneratePrivateKey("test@test.com")
	assert.Nil(t, newKeyErr)
	key, keyErr := store.GetPrivateKey("test@test.com")
	assert.Nil(t, keyErr)
	assert.Equal(t, newKey, key)
	store.Close()
	teardown(store)
}

func TestPublicKey(t *testing.T) {
	store := setup("")
	store.Authenticate("password")
	_, keyErr := store.GeneratePrivateKey("test@test.com")
	assert.Nil(t, keyErr)
	data := []byte("This is a test.")
	encryptedData, signature, _ := store.Encrypt("test@test.com", data)
	decryptedData, _ := store.Decrypt("test@test.com", encryptedData)

	assert.Equal(t, data, decryptedData)
	assert.True(t, store.Verify("test@test.com", data, signature))
	teardown(store)
}

func setup(dir string) *KeyStore {
	store, _ := NewKeyStore(dir)
	return store
}

func teardown(store *KeyStore) {
	os.Remove(store.Dir + "/keystore.db")
}
