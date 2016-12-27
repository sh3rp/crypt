package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"time"

	"github.com/boltdb/bolt"
)

const PUBLIC_KEYSTORE = "public_keystore"
const PRIVATE_KEYSTORE = "private_keystore"
const IV_STORE = "iv_store"
const CURRENT_IV = "current_iv"

type KeyStore struct {
	Dir          string
	KeyDataStore *bolt.DB
	Key          []byte
}

func NewKeyStore(dirname string) (*KeyStore, error) {
	if dirname == "" {
		dirname = "/tmp"
	}
	db, err := bolt.Open(dirname+"/keystore.db", 0600, nil)
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		bucket, bucketErr := tx.CreateBucketIfNotExists([]byte(IV_STORE))

		if bucketErr != nil {
			return bucketErr
		}
		iv, ivErr := GenerateCommonIV(time.Now().UnixNano())

		if ivErr != nil {
			return ivErr
		}
		err := bucket.Put([]byte(CURRENT_IV), iv)
		return err
	})
	return &KeyStore{
		KeyDataStore: db,
		Dir:          dirname,
	}, nil
}

func (store *KeyStore) Close() error {
	return store.KeyDataStore.Close()
}

func (store *KeyStore) GetIV() ([]byte, error) {
	var iv []byte

	err := store.KeyDataStore.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(IV_STORE))

		iv = bucket.Get([]byte(CURRENT_IV))
		return nil
	})
	return iv, err
}

func (store *KeyStore) Authenticate(password string) {
	hash := sha256.New()
	hash.Write([]byte(password))
	store.Key = hash.Sum(nil)
}

func (store *KeyStore) GeneratePrivateKey(id string) (*rsa.PrivateKey, error) {
	key, _ := rsa.GenerateKey(rand.Reader, 4096)
	err := store.KeyDataStore.Update(func(tx *bolt.Tx) error {
		bucket, bucketErr := tx.CreateBucketIfNotExists([]byte(PRIVATE_KEYSTORE))
		if bucketErr != nil {
			return bucketErr
		}
		bytes := x509.MarshalPKCS1PrivateKey(key)

		iv, ivErr := store.GetIV()

		if ivErr != nil {
			return ivErr
		}

		encryptedJson, encryptErr := Encrypt(string(store.Key), iv, bytes)

		if encryptErr != nil {
			return encryptErr
		}

		putErr := bucket.Put([]byte(id), encryptedJson)

		bucket, bucketErr = tx.CreateBucketIfNotExists([]byte(PUBLIC_KEYSTORE))

		if bucketErr != nil {
			return bucketErr
		}

		bytes, err := x509.MarshalPKIXPublicKey(key.Public())

		if err != nil {
			return err
		}

		putErr = bucket.Put([]byte(id), bytes)

		return putErr
	})
	return key, err
}

func (store *KeyStore) GetPrivateKey(id string) (*rsa.PrivateKey, error) {
	var key *rsa.PrivateKey
	var bytes []byte
	err := store.KeyDataStore.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(PRIVATE_KEYSTORE))

		encryptedJson := bucket.Get([]byte(id))

		if encryptedJson == nil {
			return errors.New("No such key exists")
		}

		iv, ivErr := store.GetIV()

		if ivErr != nil {
			return ivErr
		}
		var decryptErr error
		bytes, decryptErr = Decrypt(string(store.Key), iv, encryptedJson)

		if decryptErr != nil {
			return decryptErr
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	key, marshalErr := x509.ParsePKCS1PrivateKey(bytes)

	return key, marshalErr
}

func (store *KeyStore) AddPublicKey(id string, key *rsa.PublicKey) error {
	err := store.KeyDataStore.Update(func(tx *bolt.Tx) error {
		bucket, bucketErr := tx.CreateBucketIfNotExists([]byte(PUBLIC_KEYSTORE))
		if bucketErr != nil {
			return bucketErr
		}
		bytes, marshalErr := x509.MarshalPKIXPublicKey(key)

		if marshalErr != nil {
			return marshalErr
		}

		putErr := bucket.Put([]byte(id), bytes)
		return putErr
	})
	return err
}

func (store *KeyStore) DeletePublicKey(id string) error {
	err := store.KeyDataStore.Update(func(tx *bolt.Tx) error {
		bucket, bucketErr := tx.CreateBucketIfNotExists([]byte(PUBLIC_KEYSTORE))
		if bucketErr != nil {
			return bucketErr
		}
		deleteErr := bucket.Delete([]byte(id))
		return deleteErr
	})
	return err
}

func (store *KeyStore) GetPublicKey(id string) (*rsa.PublicKey, error) {
	var key crypto.PublicKey
	err := store.KeyDataStore.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(PUBLIC_KEYSTORE))

		bytes := bucket.Get([]byte(id))

		if bytes == nil {
			return errors.New("Public key does not exist")
		}
		var err error
		key, err = x509.ParsePKIXPublicKey(bytes)

		return err
	})
	return key.(*rsa.PublicKey), err
}

func (store *KeyStore) Encrypt(publicKeyId string, data []byte) ([]byte, []byte, error) {
	key, err := store.GetPublicKey(publicKeyId)

	if err != nil {
		return nil, nil, err
	}

	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, key, data)

	if err != nil {
		return nil, nil, err
	}

	signature, err := store.Sign(publicKeyId, data)

	if err != nil {
		return nil, nil, err
	}

	return encryptedData, signature, nil
}

func (store *KeyStore) Decrypt(privateKeyId string, data []byte) ([]byte, error) {
	key, err := store.GetPrivateKey(privateKeyId)

	if err != nil {
		return nil, err
	}

	decryptedData, decryptErr := rsa.DecryptPKCS1v15(rand.Reader, key, data)

	return decryptedData, decryptErr
}

func (store *KeyStore) Sign(keyId string, data []byte) ([]byte, error) {
	key, err := store.GetPrivateKey(keyId)

	if err != nil {
		return nil, err
	}
	hashed := sha256.Sum256(data)

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])

	return signature, err
}

func (store *KeyStore) Verify(keyId string, data []byte, signature []byte) bool {
	key, err := store.GetPublicKey(keyId)

	if err != nil {
		return false
	}

	hashed := sha256.Sum256(data)

	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], signature)

	return true
}
