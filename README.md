# Crypt

## Summary
Crypt is a simple wrapper around the existing Go crypto libraries that
provides a set of encrypt/decrypt functions.  The library provides a
keyring data store that allows:

- Generation of new private keys
- Encryption/Decryption and Signing/Verification of messages
- Persistence of keys in a local datastore

## Quick Start
A simple example of the functionality this library provides.

For simple password encryption:

```
iv, err := GenerateCommonIV(1)
encrypted, err := Encrypt("mykey", iv, []byte("Secret stuff"))
decrypted, err := Decrypt("mykey", iv, encrypted)
```

For public key encryption:

```
store := NewKeyStore("")
store.Authenticate("password")
store.GeneratePrivateKey("test@test.com")
data := []byte("This is a test.")
encryptedData, signature, _ := store.Encrypt("test@test.com", data)
decryptedData, _ := store.Decrypt("test@test.com", encryptedData)
```
