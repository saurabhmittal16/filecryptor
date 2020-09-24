package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
)

// Decrypt takes the password, input file path and output file path and
// decrypts the input file
func Decrypt(password string, inFilePath string, outFilePath string) (string, error) {
	if len(outFilePath) == 0 {
		return "", fmt.Errorf("Can't leave output filename path empty")
	}

	ciphertext, err := ioutil.ReadFile(inFilePath)
	if err != nil {
		return "", err
	}

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return "", nil
	}
	defer outFile.Close()

	// ciphertext has the original plaintext size in the first 8 bytes,
	// then the salt in next 32 bytes, then IV in the next 16 bytes and then the
	// actual ciphertext

	buf := bytes.NewReader(ciphertext)

	// read the size of original plaintext from the encrypted file
	var textSize uint64
	if err = binary.Read(buf, binary.LittleEndian, &textSize); err != nil {
		return "", nil
	}

	// read the salt used for generating key from password
	salt := make([]byte, 32)
	if _, err = buf.Read(salt); err != nil {
		return "", err
	}

	// read the iv used while encryption
	iv := make([]byte, aes.BlockSize)
	if _, err = buf.Read(iv); err != nil {
		return "", err
	}

	// check if the text after removing size, salt and iv is aligned to block size
	paddedSize := len(ciphertext) - 8 - 32 - aes.BlockSize
	if paddedSize%aes.BlockSize != 0 {
		return "", fmt.Errorf("padded plaintext should have been aligned to block size")
	}
	plaintext := make([]byte, paddedSize)

	// generate key from the password and retrieved salt from the encrypted file
	key, _, err := getKey(password, salt)
	if err != nil {
		return "", nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext[8+32+aes.BlockSize:])

	if _, err := outFile.Write(plaintext[:textSize]); err != nil {
		return "", err
	}

	return outFilePath, nil
}
