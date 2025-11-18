package challenge16

import (
	"crypto/aes"
	cryptorand "crypto/rand"
	"cryptopals/set_2/challenge10"
	"fmt"
	"log"
	"strings"
)

func challenge16() {

	randKey := make([]byte, aes.BlockSize)
	cryptorand.Read(randKey)

	input := []byte("zadminqtruelccccc")
	semicolonInd := strings.Index(string(input), "z")
	percentInd := strings.Index(string(input), "q")
	endingInd := strings.Index(string(input), "l")

	encrypted := appendPreppendEncrypt(input, randKey)

	success := false
	counter := 0
all:
	for i := range 256 {
		counter++
		encrypted[aes.BlockSize*2+semicolonInd] = byte(i)

		for j := range 256 {
			counter++
			encrypted[aes.BlockSize*2+percentInd] = byte(j)

			for k := range 256 {
				counter++
				encrypted[aes.BlockSize*2+endingInd] = byte(k)
				success = findAdmin(encrypted, randKey)
				if success {
					break all
				}
			}

		}

	}

	if !success {
		log.Fatalf("No bit attack success with %d", counter)
	}

	decrypted, err := challenge10.DecryptCBC(encrypted, randKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("N iters: %d, Decrypted content is:\n\n", counter, string(decrypted))
}

func appendPreppendEncrypt(input []byte, key []byte) []byte {
	var preppended = []byte("comment1=cooking%20MCs;userdata=")
	var appended = []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	for x := range input {
		if byte('=') == input[x] {
			input[x] = byte('%')
		}
		if byte(';') == input[x] {
			input[x] = byte('&')
		}
	}

	result := append(preppended, input...)
	result = append(result, appended...)

	return challenge10.EncryptCBC(result, key)

}

func findAdmin(encrypted []byte, key []byte) bool {
	decrypted, err := challenge10.DecryptCBC(encrypted, key)
	if err != nil {
		panic(err)
	}
	ind := strings.Index(string(decrypted), ";admin=true;")
	if ind == -1 {
		return false
	} else {
		return true
	}
}
