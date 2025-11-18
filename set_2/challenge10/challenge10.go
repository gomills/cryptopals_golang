package challenge10

import (
	"crypto/aes"
	"crypto/rand"
	"cryptopals/set_1/custombase64"
	pkcs7 "cryptopals/set_2/pkcs7"
	"fmt"
	"io"
	"os"
	"strings"
)

func challenge10() {

	file, err := os.Open("challenge10.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	base64EncodedContent, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}

	encryptedContent, err := custombase64.DecodeBase64(strings.TrimSpace(string(base64EncodedContent)))
	if err != nil {
		panic(err)
	}

	key := "YELLOW SUBMARINE"
	iv := make([]byte, aes.BlockSize)
	for x := range iv {
		iv[x] = 0
	}

	fullContent := append(iv, encryptedContent...)

	decryptedContent, _ := DecryptCBC(fullContent, []byte(key))

	fmt.Printf("Snippet of decrypted content:\n%s\n", string(decryptedContent[:100]))

	// message := "PLOPLOP"
	// key := "YELLOW SUBMARINE"

	// encryptedMess := EncryptCBC([]byte(message), []byte(key))
	// fmt.Println("Encrypted message:", string(customhex.EncodeHex(encryptedMess)))

	// decrypted, _ := DecryptCBC(encryptedMess, []byte(key))
	// fmt.Println("Decrypted message:", string(decrypted))

}

func EncryptECB(content []byte, key []byte) []byte {

	blockCipher, _ := aes.NewCipher(key)

	content, err := pkcs7.PadWithPKCS7(content, aes.BlockSize)
	if err != nil {
		panic(err)
	}

	encrypted := make([]byte, len(content))

	for i := 0; i+aes.BlockSize <= len(content); i += aes.BlockSize {

		blockCipher.Encrypt(encrypted[i:i+aes.BlockSize], content[i:i+aes.BlockSize])

	}

	return encrypted
}

func DecryptECB(content []byte, key []byte) ([]byte, error) {

	blockCipher, _ := aes.NewCipher(key)

	decrypted := make([]byte, len(content))

	for i := 0; i+aes.BlockSize <= len(content); i += aes.BlockSize {

		blockCipher.Decrypt(decrypted[i:i+aes.BlockSize], content[i:i+aes.BlockSize])

	}

	err := pkcs7.RemovePKCS7Padding(&decrypted, aes.BlockSize)
	if err != nil {
		return decrypted, err
	}

	return decrypted, nil
}

func EncryptCBC(content []byte, key []byte) []byte {

	blockCipher, _ := aes.NewCipher(key)

	// Do padding to content
	content, err := pkcs7.PadWithPKCS7(content, aes.BlockSize)
	if err != nil {
		panic(err)
	}

	// Generate iv
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	encrypted := make([]byte, len(content))

	// Iterate content in blocks and encrypt
	for i := 0; i+aes.BlockSize <= len(content); i += aes.BlockSize {

		// Xor plain text block against IV or last cipher block
		plainTextBlock := content[i : i+aes.BlockSize]

		xoredPlainText := make([]byte, len(plainTextBlock))

		if i == 0 {

			for j := range plainTextBlock {
				xoredPlainText[j] = iv[j] ^ plainTextBlock[j]
			}

		} else {

			for j := range plainTextBlock {
				xoredPlainText[j] = encrypted[i-aes.BlockSize+j] ^ plainTextBlock[j]
			}

		}

		blockCipher.Encrypt(encrypted[i:i+aes.BlockSize], xoredPlainText)

	}

	return append(iv, encrypted...)
}

func DecryptCBC(content []byte, key []byte) ([]byte, error) {

	blockCipher, _ := aes.NewCipher([]byte(key))

	// Get iv
	iv, content := content[:16], content[16:]

	if len(content)%16 != 0 {
		return nil, fmt.Errorf("corrupt content; not multiple of blocksize 16")
	}

	decrypted := make([]byte, len(content))

	// Iterate content in blocks and decrypt
	for i := 0; i+aes.BlockSize <= len(content); i += aes.BlockSize {

		// decrypt
		encryptedBlock := content[len(content)-(i+aes.BlockSize) : len(content)-i]

		decryptedBlock := make([]byte, len(encryptedBlock))

		blockCipher.Decrypt(decryptedBlock, encryptedBlock)

		// unxor
		unxoredDecryptedBlock := make([]byte, len(decryptedBlock))

		if i+aes.BlockSize == len(content) {

			for j := range decryptedBlock {
				unxoredDecryptedBlock[j] = decryptedBlock[j] ^ iv[j]
			}

		} else {

			for j := range decryptedBlock {
				unxoredDecryptedBlock[j] = decryptedBlock[j] ^ content[len(content)-(i+aes.BlockSize*2)+j]
			}

		}

		for k := range unxoredDecryptedBlock {
			decrypted[len(content)-(i+aes.BlockSize)+k] = unxoredDecryptedBlock[k]
		}

	}

	err := pkcs7.RemovePKCS7Padding(&decrypted, aes.BlockSize)
	if err != nil {
		return decrypted, err
	}

	return decrypted, nil
}
