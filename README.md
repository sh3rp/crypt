# Crypt

## Summary
Crypt is a simple wrapper around the existing Go crypto libraries that
provides simple set of encrypt/decrypt functions based on a key string 
and an intialization vector.

## Quick Start
A simple example of the functionality this library provides.

```
import "git.soma.salesforce.com/skendall/crypt"

iv, err := GenerateCommonIV(1)
encrypted, err := Encrypt("mykey", iv, []byte("Secret stuff"))
decrypted, err := Decrypt("mykey", iv, encrypted)
```