package challenge24

import (
	"bytes"
	"cryptopals/set_3/mt19937"
	"encoding/binary"
	"fmt"
	"time"
)

func challenge24b() {

	// 0. Define PRNG seed as current UNIX timestamp
	seed := time.Now().Unix()
	fmt.Println(">> Shhhh, seed is", seed)

	// 1. Generate passwordToken from the MT19937 seeded with the timestamp. Literally just generate enough random numbers to populate the pass token
	// with bytes.
	passwordToken := passToken(int(seed), 14)
	fmt.Print("\n*************************************************************\n")
	fmt.Println("Dear user, your one time password token is\n", passwordToken)
	fmt.Println("*************************************************************")
	fmt.Println()
	fmt.Println("Zzz...\n\n")
	time.Sleep(5 * time.Second)

	// 2. Here study if it was generated with an MT19937 seeded with timestamp. Look up to 20s in the past
	// 2.1 Craft timestamps array to cover the 20s window
	nSecondsWin := 20
	timeStamps := make([]int64, nSecondsWin+1) // add +1 offset to include current time
	timeStamps[0] = time.Now().Unix() - int64(nSecondsWin)

	for n := 1; n < len(timeStamps); n++ {
		timeStamps[n] = timeStamps[n-1] + 1
	}

	// 2.3 Iterate over timestamps and test the password token obtained
	for _, x := range timeStamps {

		// 2.4 Instantiate new PRNG with the current timestamp as seed
		gen := mt19937.NewPRNG(int(x))

		// 2.5 Preallocate the password obtained
		passwordTest := make([]byte, len(passwordToken))

		// 2.6 Populate passwordTest. We'll have buffer, a slice where we store in bytes each generated number
		buffer := make([]byte, 4)

		// 2.7 We'll iterate over the necessary numbers needed to populate passwordTest. This is a ceiling division:
		// AAAA AAAA AA -> we need 3 numbers even though we'll use half of the last one's bytes
		necessaryNums := (len(passwordTest) + 4 - 1) / 4
		for i := range necessaryNums {

			// 2.8 Get the current one and populate the buffer
			binary.BigEndian.PutUint32(buffer, gen.Rand())

			// 2.9 Indexes:
			// 	j is for passwordTest
			// 	k is for buffer
			// Fill, using the buffer, the corresponding passwordTest bytes
			for j, k := i*4, 0; j < len(passwordTest) && k < len(buffer); j, k = j+1, k+1 {
				passwordTest[j] = buffer[k]
			}

		}

		if bytes.Equal(passwordTest, passwordToken) {
			fmt.Println("Success: Timestamp used for gen is", x)
			break
		}

	}

}

// passToken generates a password token of length length using a MT19937 to generate enough bytes, from each uint32
func passToken(seed int, length int) []byte {
	// 0. Create recipient for password
	result := make([]byte, length)

	// 1. Instantiate PRNG
	gen := mt19937.NewPRNG(seed)

	// 2. Start a loop to populate result.
	// n is the index for the current number bytes
	keystreamBytes := make([]byte, 4)
	for n := range result {

		// 2.1 Update keystream once it was consumed or when starting out
		r := n % 4
		if r == 0 {
			binary.BigEndian.PutUint32(keystreamBytes, gen.Rand())
		}

		// 2.2 Populate password
		result[n] = keystreamBytes[r]
	}

	return result
}
