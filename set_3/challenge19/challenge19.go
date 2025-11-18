package challenge19

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"cryptopals/set_1/charfrequency"
	"cryptopals/set_1/custombase64"
	"cryptopals/set_3/challenge18"
	"fmt"
	"os"
)

func challenge19() {

	// 0. Define CTR settings
	key := make([]byte, aes.BlockSize)
	rand.Read(key)
	nonce := 0

	// 1. Encrypt line per line and keep shortest one to truncate
	file, err := os.Open("challenge19_text.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	shortestLength := 99999 // we fake it with a value large enough that fits the logic
	encrypted := [][]byte{} // here we'll store the encrypted lines as byte slices

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		// 1.1 get current line
		line := scanner.Text()

		// 1.2 decode it
		decodedLine, err := custombase64.DecodeBase64(line)
		if err != nil {
			panic(err)
		}

		// 1.3 encrypt and store it
		lineResult := challenge18.CtrCipher(key, nonce, decodedLine)
		encrypted = append(encrypted, lineResult)

		// 1.4 keep the shortest [string length] found
		if len(decodedLine) < shortestLength {
			shortestLength = len(decodedLine)
		}

	}

	// 2. Visit char per char and bruteforce keystream with char frequency as if it was a single byte XOR decryption
	keystream := make([]byte, shortestLength)

	// 2.1 Current character from the keystream
	for char := range keystream {

		// 2.2 Current keystream's [highest scoring] bruteforced char
		highestScore := 0.0
		var optimizedChar byte

		// 2.3 In the current character's index from the keystream, visit each corresponding cipher char,
		// [encrypted line] per line, and compute its unXOR'ing score for all the uint8 space to finally
		// get the bruteforced char for keystream
		for x := range 256 {

			individualScore := 0.0 // for this x
			// here we visit every encrypted line, one by one, and get the unXOR'ing score with this x
			for _, i := range encrypted {
				unXored := i[char] ^ byte(x)
				individualScore += charfrequency.EnglishCharFreqMap[rune(unXored)]
			}

			// update the optimized char if it has highest score than the max
			if individualScore > highestScore {
				highestScore = individualScore
				optimizedChar = byte(x)
			}

		}

		// finally, we can define this keystream's byte optimized character, that yields the best frequency score for all the encryptions
		keystream[char] = optimizedChar

	}

	// Print decrypted strings
	for _, enc := range encrypted {
		fmt.Println("\n")
		for ind := range keystream {

			fmt.Print(string(enc[ind] ^ keystream[ind]))
		}
	}

}
