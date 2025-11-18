package pkcs7

import "fmt"

// func main() {
// 	testString := "YELLOW SUBMARIN"
// 	blockSize := 20

// 	slice := []byte(testString)

// 	for _, b := range slice {
// 		fmt.Printf("%d,", b)
// 	}

// 	fmt.Println()

// 	Pkcs7Padding(&slice, blockSize)

// 	for _, b := range slice {
// 		fmt.Printf("%d,", b)
// 	}

// }

func PadWithPKCS7(plainText []byte, blockSize int) ([]byte, error) {

	if blockSize > 255 {
		return nil, fmt.Errorf("blocksize must be less than 256")
	}

	nPaddingBytes := blockSize - (len(plainText) % blockSize)

	// fmt.Println("Padding bytes needed: %d", nPaddingBytes)

	padding := make([]byte, nPaddingBytes)

	for i := range padding {
		padding[i] = byte(nPaddingBytes) // nPaddingBytes is max 255 so this operation is safe
	}

	// fmt.Println("Padding is \n")
	// for x := range padding {
	// 	fmt.Printf("%d,", uint8(padding[x]))
	// }

	paddedText := append(plainText, padding...)

	return paddedText, nil

}

func RemovePKCS7Padding(plainText *[]byte, blockSize int) error {

	if blockSize > 255 {
		return fmt.Errorf("block size must be less than 256")
	}

	if len(*plainText) == 0 || len(*plainText)%blockSize != 0 {
		return fmt.Errorf("invalid plaintext length")
	}

	lastByte := (*plainText)[len(*plainText)-1]
	if lastByte == 0 || lastByte > byte(blockSize) {
		return fmt.Errorf("corrupt padding")
	}

	firstPaddingByteIndex := len(*plainText) - int(uint8(lastByte))

	for i := firstPaddingByteIndex; i < len(*plainText); i++ {

		if (*plainText)[i] != lastByte {
			return fmt.Errorf("corrupt padding")
		}

	}

	*plainText = (*plainText)[:firstPaddingByteIndex]

	return nil
}
