package challenge12

import (
	"bytes"
	cryptorand "crypto/rand"
	"cryptopals/set_1/challenge8"
	"cryptopals/set_1/custombase64"
	"cryptopals/set_2/challenge10"
	"fmt"
	"log"
)

func challenge12() {

	// Get random but constant key for Oracle purposes
	key := make([]byte, 16)
	cryptorand.Read(key)

	// 1.- Discover block size of the cipher and appended text length
	blockSize := 0
	probeBlock := []byte{byte('A')}
	var appendedTextLength int

	for blockSize == 0 {

		lastEncryptedSize := len(EncryptionOracle(probeBlock, key))

		probeBlock = append(probeBlock, byte('A'))

		currentEncryptedSize := len(EncryptionOracle(probeBlock, key))

		if currentEncryptedSize != lastEncryptedSize {

			blockSize = currentEncryptedSize - lastEncryptedSize
			log.Println("Cipher is using blocksize of", blockSize)

			appendedTextLength = currentEncryptedSize - blockSize - len(probeBlock)
			log.Println("Oracle appended text length is of", appendedTextLength)

		}

	}

	placeholderBlock := make([]byte, blockSize)
	for x := range placeholderBlock {
		placeholderBlock[x] = 'A'
	}

	// 2.- Detect ECB
	duplicatedBlockSample := append(placeholderBlock, placeholderBlock...)
	encryptedDuplicatedBlock := EncryptionOracle(duplicatedBlockSample, key)

	blocks := challenge8.ExtractAES128Blocks(encryptedDuplicatedBlock)
	mappedBlocks := challenge8.MapBlocks(blocks)

	if len(mappedBlocks) != len(blocks) {
		log.Println("AES Cipher is using ECB mode")
	} else {
		panic("couldn't detect ECB")
	}

	// 3.- Bruteforce 1 byte at a time
	decryptedText := make([]byte, appendedTextLength)

	for x := range decryptedText {

		// Keep track of block and byte offsets
		nDBlock := x / blockSize
		nDByte := x % blockSize

		if nDByte == 0 {
			fmt.Println("Decrypting block", nDBlock+1)
		}

		fmt.Printf("Decrypting byte %d/%d...\n", x+1, appendedTextLength)

		// Modify prefix to have 1 unknown byte in studied block
		controlBlock := placeholderBlock[:blockSize-1-nDByte]

		// Get the expected ciphertext block for this target byte
		fullEnc := EncryptionOracle(controlBlock, key)
		start := nDBlock * blockSize
		expectedEncryption := fullEnc[start : start+blockSize]

		// Create the bruteforce block to match the studied block
		bruteforceBlock := placeholderBlock
		for i := 0; x-1-i >= 0 && blockSize-2-i >= 0; i++ {
			bruteforceBlock[blockSize-2-i] = decryptedText[x-1-i]
		}

		// Bruteforce with the whole ASCII space the last byte of the bruteforce block
		decryptSuccess := false
		for ch := range 256 {

			bruteforceBlock[blockSize-1] = byte(ch)
			resultEncryption := EncryptionOracle(bruteforceBlock, key)[:blockSize]

			if bytes.Equal(resultEncryption, expectedEncryption) {
				// write into the correct position in decryptedText
				decryptedText[x] = byte(ch)
				decryptSuccess = true
				break
			}

		}

		if !decryptSuccess {
			log.Fatalf("Failed to decrypt %d/%d...\n", x+1, appendedTextLength)
		}

	}

	fmt.Println("Decryption completed, Oracle defeated. Decrypted text is:\n", string(decryptedText))

}

func EncryptionOracle(input []byte, key []byte) []byte {

	appendeStr, _ := custombase64.DecodeBase64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	input = append(input, []byte(appendeStr)...)

	return challenge10.EncryptECB(input, key)
}
