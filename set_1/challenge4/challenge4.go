package challenge4

import (
	"bufio"
	"cryptopals/set_1/charfrequency"
	"cryptopals/set_1/customhex"
	"fmt"
	"os"
	"strings"
)

func challenge4() {

	file, err := os.OpenFile("challenge_4_text.txt", os.O_RDONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	maxScore := float64(-1)
	optimizedChar := 0
	var chosenString string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		line := scanner.Text()

		encryptedStr, err := customhex.DecodeHex(strings.TrimSpace(line))
		if err != nil {
			panic(err)
		}

		unXoredScore, bruteByte := BruteforceSingleByteXor(encryptedStr)

		if unXoredScore > maxScore {
			maxScore = unXoredScore
			chosenString = line
			optimizedChar = bruteByte
		}

	}

	fmt.Println(maxScore)
	fmt.Println(chosenString)
	fmt.Println(optimizedChar)

	fmt.Println("After unXOR'ing:")
	for _, b := range chosenString {
		fmt.Print(string(byte(b) ^ byte(optimizedChar)))
	}

}

// BruteforceSingleByteXor from this package is an upgrade to the challenge3 function with the same name. It
// uses character frequency as well as all ASCII space. It returns the optimized character for the
// decryption
func BruteforceSingleByteXor(encryptedStr []byte) (float64, int) {

	var maxScore float64
	maxScore = -10

	var optimizedChar int

	for ch := range 256 {

		unencryptedStr := make([]byte, len(encryptedStr))

		for ind, bt := range encryptedStr {
			unencryptedStr[ind] = bt ^ byte(ch)
		}

		unencryptedStrScore := AssignScoreToString(string(unencryptedStr))

		if unencryptedStrScore > maxScore {

			maxScore = unencryptedStrScore
			optimizedChar = ch

		}

	}

	return maxScore, optimizedChar

}

func AssignScoreToString(text string) float64 {

	var score float64

	for _, ch := range text {

		chScore, ok := charfrequency.EnglishCharFreqMap[ch]
		if ok {
			score += chScore
		} else {
			score -= 1
		}

	}

	return score / float64(len(text))

}

func EncryptSingleByteXor(text string, ch int) []byte {

	xoredStr := make([]byte, len(text))

	xorByte := byte(ch)

	for ind := range text {
		xoredStr[ind] = text[ind] ^ xorByte
	}

	return xoredStr

}
