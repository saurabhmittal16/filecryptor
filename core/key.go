package core

import (
	"crypto/rand"
	"golang.org/x/crypto/scrypt"
)

// takes the password string as password and optional salt as input
// and returns the generated key, salt and error
func getKey(password string, salt []byte) ([]byte, []byte, error) {
	// if no salt is provided, generate random salt of 32 bytes
	if salt == nil {
		if salt == nil {
			salt = make([]byte, 32)
			if _, err := rand.Read(salt); err != nil {
				return nil, nil, err
			}
		}
	}

	// generate 32 byte key
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}
