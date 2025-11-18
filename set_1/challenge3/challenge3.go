package challenge3

import (
	"cryptopals/set_1/customhex"
)

func main() {
	xoredString := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

	rawXored, err := customhex.DecodeHex(xoredString)
	if err != nil {
		panic(err)
	}

	bruteForceChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ "

	for j := range bruteForceChars {

		ch := bruteForceChars[j]

		unxoredString := make([]byte, len(rawXored))

		for ind, rw := range rawXored {
			unxoredString[ind] = rw ^ ch
		}

		println("%v gives %v", string(ch), string(unxoredString))
	}
}
