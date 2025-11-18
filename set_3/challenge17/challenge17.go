package challenge17

import (
	"crypto/aes"
	cryptorand "crypto/rand"
	"cryptopals/set_1/custombase64"
	challenge10 "cryptopals/set_2/challenge10"
	"fmt"
	mathrand "math/rand"
)

var possibleStrings = []string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

func challenge17() {
	// 0. Generate a random but constant encryption key
	key := make([]byte, 16)
	cryptorand.Read(key)

	// 1. Get the encrypted string
	encryptedString := encryption(key)

	// 2. Bruteforce padding length
	originalPadding := 0

	// Start index is the first byte of the previous-to-last cipher block. Iterate to right until incorrect padding detected
	// Don't drop IV, because we could have the case nBlocks = 1, where we just have 1 block besides IV
	// visualize with:
	// VVVVVVVVVVVVVVVV AAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBB,
	// where blocks are [IV, previous BLOCK, BLOCK(with padding)],
	// start index would be the X:
	// VVVVVVVVVVVVVVVV XAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBB
	startIndex := len(encryptedString) - aes.BlockSize*2
	for i := range aes.BlockSize {
		// 2.1 allocate a copy of the encrypted string
		modifiedString := make([]byte, len(encryptedString))
		copy(modifiedString, encryptedString)

		// 2.2 corrupt the byte position for this iteration
		modifiedString[startIndex+i] = ^modifiedString[startIndex+i]

		// 2.3 if padding is incorrect, this index already interferes with padding. We can infere padding now
		_, correctPadding := paddedOracle(key, modifiedString)
		if !correctPadding {
			originalPadding = aes.BlockSize - i
			break
		}
	}

	// check if iteration was a success or not (debugging)
	if originalPadding == 0 {
		panic("2. couldn't bruteforce padding value")
	} else if originalPadding > aes.BlockSize {
		panic("2. deduced bigger than block padding") // just used for debugging when writing the algo...
	} else {
		fmt.Printf("2. Original padding is %d\n", originalPadding)
	}

	// 3. Allocate a slice in memory for storing the decryption. This is of importance for both collecting the result
	// as well as to later create the custom paddings for bruteforce (see formulas in README.md or section 4.4 here).
	// Yes, we store the IV as well because we need to index this one in coordination with the encrypted one;
	// if we got rid of the IV indexes wouldn't match
	// visualize with: VVVVVVVVVVVVVVVV AAAAAAAAAAAAAAAA BBBBBBBBBBB55555
	// would yield the initialized decrypted:
	//                 VVVVVVVVVVVVVVVV 0000000000000000 0000000000055555
	decrypted := make([]byte, len(encryptedString))

	// 3.1 we have the padding already so push it as decrypted
	startPadding := len(decrypted) - originalPadding
	for n := range originalPadding {
		decrypted[startPadding+n] = byte(originalPadding)
	}

	fmt.Printf("3. Decrypted content has length of %d\n", len(encryptedString))

	// 4. Iterate over all the ciphertext to solve it. We have to iterate left <-- right because this is how the attack works.
	// x is the index in decrypted (as well as encrypted, since both have same structure, we didn't drop IV) that
	// we're trying to populate, and we start from the byte before padding until the byte before IV.
	// visualize with:
	// first x: 	VVVVVVVVVVVVVVVV AAAAAAAAAAAAAAAA BBBBBBBX88888888. xº = 39
	// last x: 	 	VVVVVVVVVVVVVVVV XAAAAAAAAAAAAAAA BBBBBBBB88888888. xf = 16
	fmt.Println("4.")
	for x := startPadding - 1; x >= aes.BlockSize; x-- {

		fmt.Println("\n\n**********")
		fmt.Println(">>> x =", x)

		// 4.1 Learn on which block of the ciphertext we're in, starting from the last one as nBlock = 0
		// visualize with:
		// VVVVVVVVVVVVVVVV AAAAAAAAAAAAAAAA BXBBBBBB88888888. x = 33 ; nBlock = 0
		// VVVVVVVVVVVVVVVV AAAAAAAAAAXAAAAA BBBBBBBB88888888. x = 26 ; nBlock = 1
		nBlock := (len(decrypted) - (x + 1)) / aes.BlockSize

		fmt.Println(">>> nBlock =", nBlock)

		// 4.2 Get the ciphertext we'll be working with accordingly. E.g: if nBlock = 1, the last block has already
		// been decrypted so we'll get rid of it (consult README.md, step 7 of the written algorithm)
		// visualize with:
		// VVVVVVVVVVVVVVVV AAAAAAAAAAAAAAAA BBBBBBBB88888888. nBlock = 0
		// VVVVVVVVVVVVVVVV AAAAAAAAAAAAAAAA                 . nBlock = 1
		cipherText := make([]byte, len(encryptedString)-aes.BlockSize*nBlock)
		copy(cipherText, encryptedString[:len(encryptedString)-aes.BlockSize*nBlock])

		fmt.Println(">>> len(cipherText) =", len(cipherText))

		// 4.2 Artificial padding, the one we'll set up to be able to bruteforce the current byte in index "x"
		// visualize with:
		// VVVVVVVVVVVVVVVV AAAAAAAAAAAAAAAA BXFFFFFFFFFFFFFF. x = 33 ; artificialPadding = 15 = F
		artificialPadding := len(cipherText) - x

		fmt.Println(">>> artificialPadding =", artificialPadding)

		// Starter for modifying padding from the previous cipher block
		// visualize with:
		// VVVVVVVVVVVVVVVV AASAAAAAAAAAAAAA BXFFFFFFFFFFFFFF. x = 33 ; artificialPadding = 15 = F ; startArtPadding = 18
		startArtPadding := len(cipherText) - 1 - aes.BlockSize - (artificialPadding - 2)

		if artificialPadding == 1 {
			fmt.Println(">>> no need to set up art padding")
		} else {
			fmt.Println(">>> startArtPadding =", startArtPadding)
		}

		// 4.4 Create the padding, with the known underlying plaintext values
		// visualize with:
		// plaintext:  VVVVVVVVVVVVVVVV AASAAAAAAAAAAAAA BXFFFFFFFFFFFFFF. x = 33 ; artificialPadding = 15 = F ; startArtPadding = 18
		// would yield a cipherText of
		// mod cipher: VVVVVVVVVVVVVVVV AACCCCCCCCCCCCCC BXFFFFFFFFFFFFFF, where C is each C_n corresponding cipherbyte
		// (see README.md formula)
		for j := range artificialPadding - 1 {
			plainVal := decrypted[startArtPadding+aes.BlockSize+j]
			encryptedVal := encryptedString[startArtPadding+j]
			cipherText[startArtPadding+j] = (plainVal ^ encryptedVal) ^ byte(artificialPadding)
		}

		// 4.5 Bruteforce bitflipping until getting a correct padding signal, which will allow us to recover the plaintext with formula.
		// For last 4.4 example, studiedByte T would be VVVVVVVVVVVVVVVV ATCCCCCCCCCCCCCC BXFFFFFFFFFFFFFF
		studiedByte := startArtPadding - 1

		fmt.Println(">>> studiedByte =", studiedByte)

		fmt.Println("\n>>>BRUTEFORCE<<<")
		var correct bool
		for j := range 256 {
			// fmt.Println("j =", j)
			ciphertxt := make([]byte, len(cipherText))
			copy(ciphertxt, cipherText)
			ciphertxt[studiedByte] = byte(j)
			_, correct = paddedOracle(key, ciphertxt)
			if correct {
				// 4.6 Check it's not a false positive for when we're targeting padding 1
				if artificialPadding == 1 {
					ciphertxt[studiedByte-1] = ^ciphertxt[studiedByte-1]
					_, correct = paddedOracle(key, ciphertxt)
					if !correct {
						fmt.Println(" gave false positive")
						continue
					}
				}
				decrypted[x] = (byte(artificialPadding) ^ byte(j)) ^ encryptedString[studiedByte]
				fmt.Println(" gave success decrypt")
				break
			}
		}
		if !correct {
			panic(fmt.Sprintf("failed to bruteforce byte %d/%d", x-originalPadding, len(decrypted)-1))
		}

	}

	decryptedStr := string(decrypted[aes.BlockSize : len(decrypted)-originalPadding])
	fmt.Println(decryptedStr)
}

// encryption picks a random string from the possibleStrings slice, base64 decodes it
// and encrypts it with CBC mode using challenge10 encrypting functions.
// returns (iv+encrypted)
func encryption(key []byte) []byte {

	pickedString := possibleStrings[mathrand.Intn(len(possibleStrings)-1)]

	plainText, err := custombase64.DecodeBase64(pickedString)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plainText))

	encrypted := challenge10.EncryptCBC(plainText, key)

	return encrypted
}

// paddedOracle decrypts and tells us if it was a success or not. **we'll suppose that the only error can come from padding;
// the other error could be multiplicity of blocksize and we'll suppose that never happens**
func paddedOracle(key []byte, encrypted []byte) ([]byte, bool) {

	decrypted, err := challenge10.DecryptCBC(encrypted, key)
	if err != nil {
		// fmt.Printf("❗ORACLE: %s\n", err)
		return decrypted, false
	} else {
		return decrypted, true
	}

}
