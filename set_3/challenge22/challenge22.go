package challenge22

import (
	"cryptopals/set_3/mt19937"
	"log"
	"math/rand"
	"time"
)

func challenge22() {

	log.Println("Initialized app!")

	// 1. Wait a random duration
	wait := time.Duration(rand.Intn(15)+5) * time.Second // time.Second does NOT convert duration (in ns) to s, it replaces ns with s. time.Second is a constant that scales ns to s
	log.Printf("Sleeping %s...\n", wait)
	time.Sleep(wait)

	// 2. Populate the seed with timestamp
	seed := time.Now().Unix()
	log.Println(">>> Shhh, seed is", seed)

	// 3. Get the MTPRNG and its first value
	gen := mt19937.NewPRNG(int(seed))
	firstVal := gen.Rand()
	log.Println("First value is", firstVal)
	time.Sleep(5)

	// 4. Bruteforce the seed by looking up to 100 seconds in the past and generating numbers
	log.Println("I'll try to hack it 🛠️")

	instant := time.Now().Unix()
	discovered := false
	for i := instant - 100; i <= instant+100; i++ {

		genTest := mt19937.NewPRNG(int(i))

		firstValTest := genTest.Rand()

		if firstValTest == firstVal {
			log.Println("I discovered, the seed is", i)
			discovered = true
			break
		}
	}
	if !discovered {
		log.Println("I just couldn't :(")
	}
}
