package challenge8

import (
	"bufio"
	"crypto/aes"
	"fmt"
	"os"
)

func challenge8() {

	file, err := os.OpenFile("challenge8.txt", os.O_RDONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	possiblyECBEncoded := []int{}

	i := 0
	for scanner.Scan() {
		i++
		line := scanner.Text()
		blocks := ExtractAES128Blocks([]byte(line))
		mappedBlocks := MapBlocks(blocks)
		if len(blocks) != len(mappedBlocks) {
			possiblyECBEncoded = append(possiblyECBEncoded, i)
		}
	}
	fmt.Println("Possibly AES-ECB encoded:")

	for _, l := range possiblyECBEncoded {
		fmt.Printf("Line number %d\n", l)
	}
}

func ExtractAES128Blocks(line []byte) [][]byte {
	if len(line)%16 != 0 {
		panic("Not divisible by 16")
	}

	nBlocks := len(line) / 16
	blocks := make([][]byte, nBlocks)
	for n := range nBlocks {
		blocks[n] = line[n*aes.BlockSize : n*aes.BlockSize+aes.BlockSize]
	}

	return blocks
}

func MapBlocks(blocks [][]byte) map[string]struct{} {
	dict := map[string]struct{}{}
	for _, i := range blocks {
		dict[string(i)] = struct{}{}
	}
	return dict
}
