package challenge6

import (
	"bufio"
	challenge4 "cryptopals/set_1/challenge4"
	"cryptopals/set_1/custombase64"
	"fmt"
	"math"
	"math/bits"
	"os"
	"strings"
)

func challenge6() {

	// 1.- Open the file with Base64 encoded lines of the encrypted file
	input, err := os.OpenFile("challenge_6_file.txt", os.O_RDONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer input.Close()

	// 2.- Decode the content and dump it into a single slice
	// (memory safe in this case, and simplifies work)
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

	fmt.Printf("Decoded content length is %d bytes\n", len(decodedContent))

	// 3.- Bruteforce the size of the XOR key
	optimizedKeySize := BruteForceRptKeySize(decodedContent, 40)

	if optimizedKeySize == 0 {
		panic("Optimized key size is 0.")
	}

	fmt.Printf("Optimized key size is %d\n", optimizedKeySize)

	// 4.- Bruteforce each character of the xorkey individually with a divide and conquer approach
	// (group all the same-character-xored bytes of the encrypted content to a single slice and
	// optimize the char with character frequency from challenge 4)
	xorKey := make([]byte, optimizedKeySize)

	// iterate over each character of the future xorkey (i is for xorkey)
	for i := range optimizedKeySize {

		// iterate over the decoded content to gather same-key-xored bytes (j is for decodedContent)
		sameByteBlock := []byte{}
		for j := 0; j*optimizedKeySize+i < len(decodedContent); j++ {

			ch := decodedContent[j*optimizedKeySize+i]
			sameByteBlock = append(sameByteBlock, ch)

		}

		// decrypt with bruteforce the same single-key-xored bytes
		_, k := challenge4.BruteforceSingleByteXor(sameByteBlock)
		xorKey[i] = byte(k)

	}

	fmt.Printf("XorKey is: '%s'\n", string(xorKey))
	decryptedKey := DecryptRepeatingKeyXor(decodedContent, xorKey)

	fmt.Printf("Decrypted content sneek peak:\n%s\n", string(decryptedKey)[:100])

}

func BruteForceRptKeySize(rptKeyXorEncrypted []byte, sizesSpace int) int {

	var optimizedNormalHd float64
	firstIter := true
	optimizedKeySize := 0

	for i := 1; i <= sizesSpace; i++ {

		// Floor the number of pairs for keysize i. The last one is useless
		// to calculate HD if it's not complete, we need 2!
		numberOfPairs := (len(rptKeyXorEncrypted)) / (2 * i)

		cumulatedHammingDist := float64(0)
		for n := range numberOfPairs {
			chunk1 := rptKeyXorEncrypted[n*i : (n+1)*i]
			chunk2 := rptKeyXorEncrypted[(n+1)*i : (n+2)*i]

			x, _ := CalculateNormalHd(chunk1, chunk2)

			cumulatedHammingDist += x

		}

		meanNormalizedHammingDist := cumulatedHammingDist / float64(numberOfPairs)

		if firstIter {
			optimizedNormalHd = meanNormalizedHammingDist
			firstIter = false
		}

		if meanNormalizedHammingDist < optimizedNormalHd {
			optimizedNormalHd = meanNormalizedHammingDist
			optimizedKeySize = i
		}

	}

	return optimizedKeySize

}

func CalculateNormalHd(string1 []byte, string2 []byte) (float64, error) {

	if len(string1) != len(string2) {
		return 0, fmt.Errorf("differing lengths: %d vs %d", len(string1), len(string2))
	}

	hammingDistance := 0
	for i := range string1 {
		hammingDistance += bits.OnesCount8(string1[i] ^ string2[i])
	}

	normalHammingDistance := math.Round(float64(hammingDistance)*10) / float64(len(string1)) / 10

	return normalHammingDistance, nil
}

func DecryptRepeatingKeyXor(content []byte, key []byte) []byte {

	decryptedContent := make([]byte, len(content))

	for i, j := 0, 0; i < len(content); i, j = i+1, j+1 {

		if j == len(key) {
			j = 0
		}

		decryptedContent[i] = content[i] ^ key[j]

	}

	return decryptedContent
}
