package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
)

// Encrypt takes a password, input file path and output file path and
// encrpts the input file
func Encrypt(password string, inFilePath string, outFilePath string) (string, error) {
	if len(outFilePath) == 0 {
		return "", fmt.Errorf("Can't leave output filename path empty")
	}

	// get key and salt from given password
	key, salt, err := getKey(password, nil)
	if err != nil {
		return "", err
	}

	// read plaintext from the given file
	plaintext, err := ioutil.ReadFile(inFilePath)
	if err != nil {
		return "", err
	}

	// create the output file
	outFile, err := os.Create(outFilePath)
	if err != nil {
		return "", err
	}
	defer outFile.Close()

	// write size of original file to the encrypted file
	textSize := uint64(len(plaintext))
	if err = binary.Write(outFile, binary.LittleEndian, textSize); err != nil {
		return "", nil
	}

	// write the generated salt to the encrypted file (used for decryption)
	if _, err = outFile.Write(salt); err != nil {
		return "", nil
	}

	// generate random IV and write to encrypted file
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	if _, err = outFile.Write(iv); err != nil {
		return "", err
	}

	// pad the plaintext to a multiple of aes.Blocksize
	if len(plaintext)%aes.BlockSize != 0 {
		bytesDiff := aes.BlockSize - (len(plaintext) % aes.BlockSize)
		padding := make([]byte, bytesDiff)
		if _, err := rand.Read(padding); err != nil {
			return "", nil
		}
		plaintext = append(plaintext, padding...)
	}

	// ciphertext is of same size as plaintext
	ciphertext := make([]byte, len(plaintext))

	// Use AES implementation of the cipher.Block interface to
	// encrypt the whole file in CBC mode.
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	if _, err = outFile.Write(ciphertext); err != nil {
		return "", err
	}
	return outFilePath, nil
}
