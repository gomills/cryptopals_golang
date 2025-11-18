package challenge18

import (
	"crypto/aes"
	"cryptopals/set_1/custombase64"
	"cryptopals/set_2/challenge10"
	"encoding/binary"
	"fmt"
	"log"
)

const str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

func challenge18() {
	// 0. Get string and decode it
	decodedStr, err := custombase64.DecodeBase64(str)
	if err != nil {
		log.Fatalln("Failed to decode:", err)
	}

	// 1. Define CTR settings
	key := "YELLOW SUBMARINE"
	nonce := 0

	// 2. Decrypt
	decrypted := CtrCipher([]byte(key), nonce, decodedStr)

	fmt.Println(string(decrypted))
}

func CtrCipher(key []byte, nonce int, stream []byte) []byte {

	// 0. Create recipient for de/encryptions
	result := make([]byte, len(stream))

	// 1. Craft the template for the counter block
	countBlock := make([]byte, aes.BlockSize)
	binary.LittleEndian.PutUint64(countBlock[:aes.BlockSize/2], uint64(nonce))

	// debug it
	// for _, i := range countBlock {
	// 	fmt.Print(i)
	// }
	// return []byte{}

	// 2. Start a loop with a counter.
	// n is the index for the current byte (streaming).
	// lastBlock is the index for the block of the keystream we're consuming, which will determine the counter
	lastBlock := 0
	for n := range stream {

		// 2.1 Update the current count block if we consumed it already
		currentBlock := n / aes.BlockSize
		if currentBlock > lastBlock {
			lastBlock = currentBlock
			binary.LittleEndian.PutUint64(countBlock[aes.BlockSize/2:], uint64(currentBlock))
		}

		// 2.2 Get the keystream
		keyStream := challenge10.EncryptECB(countBlock, key)

		// 2.3 Encrypt / decrypt
		result[n] = stream[n] ^ keyStream[n%aes.BlockSize]
	}

	return result
}
