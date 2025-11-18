package mt19937

// All the constants, including masks and magic numbers, as well as the tampering operations, were obtained empirically to maximize period
// length and equitative statistical distribution and properties.
// All operations are in modulo 2^32 arithmetic, whatever that means

const n = 624                     // size of the internal State array. It's the number of generated randoms per state
const width = 32                  // state's values size in bits
const initMultiplier = 1812433253 // initialization multiplier, used to generate state from the seed

type MTPRNG struct {
	Seed  int      // initial value, used to populate the seed state. It's a user input
	Index int      // position of the next value to extract from the State (0 ≤ Index < n
	State []uint32 // array of length n (624), type uint32. Evolves deterministically. Each call to the generator either consumes one output or regenerates the whole
}

// NewPRNG instantiates a new MT19937 PRNG, of type MTPRNG, and returns it
func NewPRNG(seed int) MTPRNG {
	// 1. Instantiate new MTPRNG
	MT := MTPRNG{Seed: seed, Index: 0, State: []uint32{}}
	// 2. Seed it. This automatically twistes the seed state.
	MT.seedMt()
	return MT
}

// seedMt processes the initial seed. It expands it by populating an array of n (624) values (uint32),
// in an algorithm where each comes from the previous value only.
// The first value is the seed. Afterwards it performs these steps, on the previous value:
//	a. XOR'ing: shifts and xors itself
//	b. Multiplication with empiric multiplier
//	c. Add the loop Index
// This yields a seeded array. Note that we can't use it straight away because it doesn't have the operations needed for random
// number generation, we'll have to perform an initial twist anyway.
func (mt *MTPRNG) seedMt() {

	// 1. Truncate seed: keep only the first 32 bits from the seed.
	// The binary 0XFFFFFFFF is equivalent to 32 bits of value 1 and they'll help us mask just the first 32 from the seed.
	truncatedSeed := uint32(mt.Seed & 0xFFFFFFFF)

	// 2. Craft the state and set the seed as the first value. This is the only direct use of the external seed.
	firstState := make([]uint32, n)
	firstState[0] = truncatedSeed

	// 3. Populate the entire array.
	// Take into account all operations are modulo 2^32. This means that the arithmetic mustn't yield more than 32 bits
	// per operation. However, we're covered since Go's arithmetic automatically discards overcrowded bits.
	for i := 1; i < n; i++ {

		// a. Get previous value
		previousVal := firstState[i-1]
		// b. Right shift it by 30 bits (keep only the 2 first bits)
		previousValShifted := previousVal >> (width - 2)
		// c. XOR with the original itself
		xored := (previousVal ^ previousValShifted)
		// d. Multiply to spread uniformily (empirically tested value)
		multiplied := xored * initMultiplier
		// e. Add the loop index to improve results in case of repetitions, breaking symmetry
		indexed := multiplied + uint32(i)

		firstState[i] = indexed

	}

	// 4. Store it as the MT's state and twist it to get the first usable state
	mt.State = firstState
	mt.TwistState()
	mt.Index = 0

}

// TwistState refreshes the entire state array once all n values have been consumed.
// Each new element i on the new state depends, from the old State, on:
// 		- current element
// 		- immediate next element
// 		- next one 397 indexes ahead.
// The process uses wraparound indexing for that purpose (first value after last one is 0). That's why for index we use (i+X)%n
func (mt *MTPRNG) TwistState() {

	// 1. Get a copy of the current state to get values from
	oldState := make([]uint32, n)
	copy(oldState, mt.State)

	// 2. Update the state in place by looking up values in its copy
	for i := range mt.State {
		// 2.1 Combine the highest bit of the current word with the lowest 31 bits of the immediate next word
		current := oldState[i]
		next := oldState[(i+1)%n]

		x := current&0x80000000 | next&0x7FFFFFFF

		// 2.2 Right shift by 1 (which is the same as divide by 2) and if it's odd (last bit is 1), mix in a constant to break symmetry.
		xA := x >> 1
		if (x & 1) != 0 {
			xA ^= 0x9908B0DF
		}

		// 2.3 New state value is 2.2 result XOR'ed with the value 397 positions ahead
		mt.State[i] = oldState[(i+397)%n] ^ xA
	}

}

// extractRand applies several tempering transformations — bit-shifts and masks — to improve the statistical quality of the raw state.
// If state is consumed already (index = n), it will perform twisting.
func (mt *MTPRNG) Rand() uint32 {

	if mt.Index == n {
		mt.TwistState()
		mt.Index = 0
	}

	randNum := mt.State[mt.Index]

	randNum = randNum ^ (randNum >> 11)

	randNum = randNum ^ ((randNum << 7) & 0x9D2C5680)

	randNum = randNum ^ ((randNum << 15) & 0xEFC60000)

	randNum = randNum ^ (randNum >> 18)

	mt.Index++

	return randNum

}
