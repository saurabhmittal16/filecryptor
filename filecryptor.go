package filecryptor

import (
	"github.com/saurabhmittal16/filecryptor/core"
)

// Encrypt takes the path of the input file, a password and the path of the
// output file as input and encrypts the input file using the provided password
func Encrypt(password string, inputFilePath string, outputFilePath string) error {
	_, err := core.Encrypt(password, inputFilePath, outputFilePath)

	return err
}

// Decrypt takes the path of the input file, a password and the path of the
// output file as input and decrypts the input file using the provided password
func Decrypt(password string, inputFilePath string, outputFilePath string) error {
	_, err := core.Decrypt(password, inputFilePath, outputFilePath)

	return err
}
