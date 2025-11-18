package challenge23

import (
	"cryptopals/set_3/mt19937"
	"fmt"
)

func challenge23() {

	// 0. Instantiate MT19937 generator to attack
	gen := mt19937.NewPRNG(24322)

	// fmt.Println("Checking original state values...")
	// for l := range 5 {
	// 	fmt.Println(gen.State[l])
	// }
	// fmt.Println("\n")

	// 1. Store the first state, which is the first 624 values
	storage := make([]uint32, len(gen.State))
	for i := range storage {
		storage[i] = gen.Rand()
	}

	// 2. Untamper them in place
	for i := range storage {
		storage[i] = untamperMT19937(storage[i])
	}

	// 4. Now we have the duplicated PRNG, we have to manually instantiate the generator
	dupped := mt19937.MTPRNG{Seed: 238293, Index: 0, State: storage}
	dupped.TwistState()

	// 4. Print some checking values
	fmt.Println("Let's see if randomizations equal...")
	for range 20 {
		fmt.Printf("Dup: %d, Orig: %d\n", dupped.Rand(), gen.Rand())
	}

	// x := uint32(41414141)
	// x = tamper(x)
	// x = untamperMT19937(x)

}

// untamperMT19937 performs the exact inverse operations of the method MTPRNG.Rand()
// in order to recover the underlying state. Each inline comment is the operation being inversed,
// exactly as is in the method
func untamperMT19937(rand uint32) uint32 {

	// d. randNum = randNum ^ (randNum >> 18)
	rand = rand ^ (rand >> 18)

	// c. randNum = randNum ^ ((randNum << 15) & 0xEFC60000)
	rand = rand ^ ((rand << 15) & 0xEFC60000)

	// b. randNum = randNum ^ ((randNum << 7) & 0x9D2C5680)
	rand = undoB(rand)

	// a. randNum = randNum ^ (randNum >> 11)
	rand = undoA(rand)

	return rand
}

// undoB is the inverse operation of step b)
func undoB(xp uint32) uint32 {
	tmp := xp
	for range 32 {
		tmp = xp ^ ((tmp << 7) & 0x9D2C5680)
	}
	return tmp
}

// undoA is the inverse operation of step a)
func undoA(randPrime uint32) uint32 {
	rand := randPrime
	for shift := 20; shift >= 0; shift-- {
		if (rand>>(shift+11))&1 != 0 {
			rand ^= 1 << shift
		}
	}
	return rand
}
