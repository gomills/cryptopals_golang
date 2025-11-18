package challenge14

import (
	"bytes"
	cryptorand "crypto/rand"
	"cryptopals/set_1/challenge8"
	"cryptopals/set_1/custombase64"
	"cryptopals/set_2/challenge10"
	"fmt"
	"log"
	mathrand "math/rand"
)

func challenge14() {

	// 0.- Get random but constant key for Oracle purposes. This key CAN'T be used!
	key := make([]byte, 16)
	cryptorand.Read(key)

	// 1.- Discover block size of the cipher
	fmt.Println("\n1.- Discover cipher blocksize\n")
	blockSize := bruteforceBlocksize(key)
	fmt.Printf("\nBlocksize happened to be %d\n", blockSize)

	// This block's cipher will be always used as the go-to sentinel to be detected as the duplicated block
	probe := make([]byte, blockSize)
	cryptorand.Read(probe)
	sentinelDup := append(probe, probe...)
	sentinelCipher := getSentinelCipher(key, sentinelDup, blockSize)

	// 2.- Discover target text length
	fmt.Println("\n2.- Discover target text length\n")
	textLength := bruteforceTextLength(blockSize, key, sentinelDup, sentinelCipher)
	fmt.Printf("Target text length happens to be %d\n", textLength)

	// 3.- Begin bruteforcing. Here on is where it gets tricky
	fmt.Println("\n3.- Bruteforce each byte of the text\n")

	// Here we'll store the decrypted bytes
	decryptedText := make([]byte, textLength)

	// This block will be used as the one to contain the studied byte
	placeholderBlock := make([]byte, blockSize)
	cryptorand.Read(placeholderBlock)

	// Here starts the loop to bruteforce one byte at a time
	for x := range decryptedText {

		// Keep track of block and byte offsets
		nDBlock := x / blockSize
		nDBytes := x % blockSize

		if nDBytes == 0 {
			fmt.Printf("Decrypting block %d/%d\n", nDBlock, textLength/blockSize)
		}

		// A) Get expected cipher text for the studied byte in the studied block.
		// Modify input to have 1 unknown byte in studied block (studied block
		// can be either post sentinel or any of the following blocks, depending on nDBlock)
		controlBlock := placeholderBlock[:blockSize-1-nDBytes]

		// This function encrypts, detects the sentinel value and returns us the clean cipher after it
		encryp := getPostSentinelText(key, append(sentinelDup, controlBlock...), blockSize, sentinelCipher)
		start := nDBlock * blockSize
		expectedCipherBlock := encryp[start : start+blockSize]

		// B) Bruteforce with a bruteforceblock by substituting its last byte with bruteforcing bytes, from
		// ASCII space.
		// Create the bruteforce block to match the studied block by substituting deciphered bytes if necessary
		bruteforceBlock := make([]byte, blockSize)
		copy(bruteforceBlock, placeholderBlock)

		for i := 0; x-1-i >= 0 && blockSize-2-i >= 0; i++ {
			bruteforceBlock[blockSize-2-i] = decryptedText[x-1-i]
		}

		// Bruteforce of the byte, again using the helper function that abstracts from the random preppend by yielding us always clean text
		// after the sentinel
		decryptedSuccess := false
		for ch := range 256 {

			// Substitute the last byte of the bruteforce block with the current character being tested
			bruteforceBlock[len(bruteforceBlock)-1] = byte(ch)

			// Send it to encrypt
			encryp := getPostSentinelText(key, append(sentinelDup, bruteforceBlock...), blockSize, sentinelCipher)

			// Get the encrypted block. Note that we get the first block from the cipher, for any block that we're decrypting, wether it's the
			// first, second or last, because we're bruteforcing here with a custom block that goes post sentinel ALWAYS, not
			// studying middle blocks in the unknown text.
			resultEncryption := encryp[:blockSize]

			// If we found a match with the current character, mark it as success
			if bytes.Equal(resultEncryption, expectedCipherBlock) {
				decryptedSuccess = true
				decryptedText[x] = byte(ch)
				break
			}

		}

		if !decryptedSuccess {
			log.Fatalf("Failed to decrypt %d/%d...\n", x+1, textLength)

		}

	}

	fmt.Println("\nDecryption completed, Oracle defeated. Decrypted text is:\n\n", string(decryptedText))

}

// EncryptionOracle is the hell Oracle that preppends a random string of length of up to 1000 characters to
// the input
func EncryptionOracle(input []byte, key []byte) []byte {

	randomPreppend := make([]byte, mathrand.Intn(1000))
	cryptorand.Read(randomPreppend)

	input = append(randomPreppend, input...)
	appendeStr, _ := custombase64.DecodeBase64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	input = append(input, []byte(appendeStr)...)

	return challenge10.EncryptECB(input, key)

}

// // bruteforceBlocksize uses the following strategy:
// // 1. Gather divisors of a single, random ciphertext. We'll use all the possibilities to infer with statistics the most probable one
// // 2. Statistics study to choose most adequate blocksize
// // As I commented in the duplicated block detection in the last step of the function... I think the problem of false signals is in
// // using the same block for every block in the sequence. I think it gets solved by using different blocks for each pair
func bruteforceBlocksize(key []byte) int {
	var blockSize int
	// 1. Also, store them in a blocksize:score map for statistics of bruteforcing
	forDivisorsEncryption := EncryptionOracle([]byte("holaprueba"), key)
	possibleBs := []int{}

	bSizesScore := map[int]int{}
	for i := 5; i < 41; i++ {
		if len(forDivisorsEncryption)%i == 0 {
			bSizesScore[i] = 0
			possibleBs = append(possibleBs, i)
		}
	}

	// 2. It consists, for each possible blocksize, in crafting a sequence of blocks that is ensured to yield one duplicate set of blocks that we'd be able to detect
	// if the blocksize was the correct one.
	// This sequence was deduced on paper... it consists in blocksize number of contiguous, same-block-pairs, separated by a random offset of bs-1 bytes.
	for range 100 {
		for _, bs := range possibleBs {

			// Get a random probeblock of the length of testing blocksize
			probeBlock := make([]byte, bs)
			cryptorand.Read(probeBlock)

			// Duplicate it
			bsDupedBlock := append(probeBlock, probeBlock...)

			// Save a clean copy that will serve as the first block in the special sequence
			bsBruteForceBlock := bsDupedBlock

			// Create a block with the special offset for the sequence
			offsettedDup := append(make([]byte, bs-1), bsDupedBlock...)

			// Append it to the first block in the special sequence enough times (enough are determined by math rules, not invented...).
			// I just draw it a couple of times in paper and determined it has to be like this, no secret. DIY
			for range bs - 1 {
				// randomize the offset to avoid false patterns with different blocksizes...
				cryptorand.Read(offsettedDup[:bs-1])
				bsBruteForceBlock = append(bsBruteForceBlock, offsettedDup...)
			}

			// Attack with the special sequence as the chosen plaintext
			bsBruteForceEncryption := EncryptionOracle(bsBruteForceBlock, key)

			// Skip it if not even multiple of blocksize...
			if len(bsBruteForceEncryption)%bs != 0 {
				continue
			}

			// Search for duplicates and if any, sum score for the blocksize. Note that this can yield false signals for various blocksizes.
			// That's why the statistics bruteforce. Maybe we could save ourselves the hassle of bruteforcing
			// if we used different blocks as duplicated for each pair in the sequence? I think yes, but I
			// have no time to implement it.
			nBlocks := len(bsBruteForceEncryption) / bs
			blocks := make([][]byte, nBlocks)
			for n := range nBlocks {
				blocks[n] = bsBruteForceEncryption[n*bs : n*bs+bs]
			}
			mappedBlocks := challenge8.MapBlocks(blocks)
			if len(mappedBlocks) != len(blocks) {
				bSizesScore[bs]++
			}

		}
	}

	maxScore := 0
	for bs, score := range bSizesScore {

		if score > maxScore {
			maxScore = score
			blockSize = bs
		}
		// fmt.Printf("Size: %d, yielded: %d\n", bs, score)

	}

	return blockSize
}

func bruteforceTextLength(blockSize int, key []byte, sentinelDup []byte, sentinelCipher []byte) int {

	var lastLength int
	n := 0
	initLength := len(getPostSentinelText(key, sentinelDup, blockSize, sentinelCipher))
	// fmt.Println("Init length is", initLength)
	for {

		sentinelDup = append(sentinelDup, byte('S'))
		n++

		lastLength = len(getPostSentinelText(key, sentinelDup, blockSize, sentinelCipher))

		if lastLength > initLength {
			// fmt.Printf("Length %d vs %d, had to add %d", lastLength, initLength, n)
			break
		}

	}

	return initLength - n
}

// getPostSentinelText encrypts the input the necessary times to detect the sentinel. When detecting it, it returns the text after
// it without including any byte of the sentinel at all, to the end of the encryption.
// It's an abstraction that gets rid of the random preppend.
func getPostSentinelText(key []byte, input []byte, blockSize int, sentinelCipher []byte) []byte {
	for {

		encryp := EncryptionOracle(input, key)

		for i := 0; i+2*blockSize <= len(encryp); i += blockSize {

			if bytes.Equal(encryp[i:i+blockSize], sentinelCipher) {

				// fmt.Printf("Sentinel: (%s)|(%s)\n", string(customhex.EncodeHex(encryp[i:i+blockSize])), string(customhex.EncodeHex(encryp[i+blockSize:i+2*blockSize])))
				// fmt.Printf("Post sentinel: %s\n", string(customhex.EncodeHex(encryp[i+2*blockSize:])))
				return encryp[i+2*blockSize:]
			}
		}

	}
}

func getSentinelCipher(key []byte, sentinelDup []byte, blockSize int) []byte {
	for {

		encryp := EncryptionOracle(sentinelDup, key)

		for i := 0; i+2*blockSize <= len(encryp); i += blockSize {

			if bytes.Equal(encryp[i:i+blockSize], encryp[i+blockSize:i+2*blockSize]) {

				// fmt.Printf("Sentinel: (%s)|(%s)\n", string(customhex.EncodeHex(encryp[i:i+blockSize])), string(customhex.EncodeHex(encryp[i+blockSize:i+2*blockSize])))
				// fmt.Printf("Post sentinel: %s\n", string(customhex.EncodeHex(encryp[i+2*blockSize:])))
				return encryp[i+blockSize : i+2*blockSize]
			}
		}

	}
}
