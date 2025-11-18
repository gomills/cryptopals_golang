package challenge7

import (
	"bufio"
	"crypto/aes"
	"cryptopals/set_1/custombase64"
	"fmt"
	"os"
	"strings"
)

func challenge7() {
	// 1.- Open the file with Base64 encoded lines of the encrypted file
	input, err := os.OpenFile("challenge_7_file.txt", os.O_RDONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer input.Close()

	// 2.- Decode the content and dump it into a single slice
	decodedContent := []byte{}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {

		line := scanner.Text()

		if len(line) > 0 {

			decodedChunk, err := custombase64.DecodeBase64(strings.TrimSpace(line))
			if err != nil {
				panic(err)
			}

			decodedContent = append(decodedContent, decodedChunk...)

		}

	}

	cipherKey := "YELLOW SUBMARINE"

	decrypted, _ := DecryptECB(decodedContent, cipherKey)

	fmt.Printf("Sneek peak of the decrypted content:\n%s\n", string(decrypted[:100]))
}

func DecryptECB(content []byte, key string) ([]byte, error) {

	blockCipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	if len(content)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("plaintext is not a multiple of the block size %d", aes.BlockSize)
	}

	decrypted := make([]byte, len(content))

	for i := 0; i+16 <= len(content); i += 16 {
		blockCipher.Decrypt(decrypted[i:i+16], content[i:i+16])
	}

	return decrypted, nil
}
