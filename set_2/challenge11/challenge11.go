package challenge11

import (
	cryptorand "crypto/rand"
	"cryptopals/set_1/challenge8"
	"cryptopals/set_2/challenge10"
	"log"
	mathrand "math/rand/v2"
)

func challenge11() {
	input := make([]byte, 16*3)

	for range 10 {
		log.Println()
		encryption := EncryptionOracle(input)

		if len(encryption)%16 != 0 {
			panic("%16!=0")
		}

		blocks := challenge8.ExtractAES128Blocks(encryption)

		mapedBlocks := challenge8.MapBlocks(blocks)

		if len(mapedBlocks) != len(blocks) {
			log.Println("2.-ANALYSIS SAYS: ECB")
		} else {
			log.Println("2.-ANALYSIS SAYS: CBC")
		}
	}
}

func EncryptionOracle(input []byte) []byte {

	key := make([]byte, 16)
	cryptorand.Read(key)

	preppend := make([]byte, mathrand.IntN(6)+5)
	appende := make([]byte, mathrand.IntN(6)+5)
	cryptorand.Read(preppend)
	cryptorand.Read(appende)

	input = append(input, appende...)
	input = append(preppend, input...)

	rndChoice := mathrand.IntN(2)

	var encrypted []byte
	if rndChoice == 0 {
		encrypted = challenge10.EncryptCBC(input, key)
		encrypted = encrypted[16:]
		log.Println("1- ORACLE SAYS  : CBC")
	} else {
		encrypted = challenge10.EncryptECB(input, key)
		log.Println("1- ORACLE SAYS  : ECB")
	}

	return encrypted
}
