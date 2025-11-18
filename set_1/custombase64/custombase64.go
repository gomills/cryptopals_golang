package custombase64

import (
	"fmt"
	"strings"
)

var base64Map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func EncodeBase64(originalBytes []byte) string {

	numBytes := len(originalBytes)

	base64String := make([]byte, 4*((numBytes+2)/3))

	if numBytes < 3 {
		handleLeftOverBytes(base64String, originalBytes, numBytes, 0, 0)
		return string(base64String)
	}

	i, j := 0, 0
	for ; i+2 < numBytes; i, j = i+3, j+4 {

		base64String[j] = base64Map[originalBytes[i]>>2]
		base64String[j+1] = base64Map[((originalBytes[i]&0b00000011)<<4)|(originalBytes[i+1]>>4)]
		base64String[j+2] = base64Map[((originalBytes[i+1]&0b00001111)<<2)|(originalBytes[i+2]>>6)]
		base64String[j+3] = base64Map[originalBytes[i+2]&0b00111111]
	}

	if numBytes-i > 0 {

		handleLeftOverBytes(base64String, originalBytes, numBytes, i, j)

	}

	return string(base64String)
}

func handleLeftOverBytes(base64String []byte, originalBytes []byte, numBytes int, oi int, j int) {

	placeHolders := make([]byte, 3)

	leftOverBytes := numBytes - oi

	for i := 0; oi+i < numBytes; i++ {
		placeHolders[i] = originalBytes[oi+i]
	}

	switch leftOverBytes {

	case 1:

		base64String[j] = base64Map[placeHolders[0]>>2]
		base64String[j+1] = base64Map[((placeHolders[0]&0b00000011)<<4)|(placeHolders[1]>>4)]
		base64String[j+2] = '='
		base64String[j+3] = '='

	case 2:

		base64String[j] = base64Map[placeHolders[0]>>2]
		base64String[j+1] = base64Map[((placeHolders[0]&0b00000011)<<4)|(placeHolders[1]>>4)]
		base64String[j+2] = base64Map[((placeHolders[1]&0b00001111)<<2)|(placeHolders[2]>>6)]
		base64String[j+3] = '='

	}

}

func DecodeBase64(text string) ([]byte, error) {
	if len(text)%4 != 0 {
		return nil, fmt.Errorf("base64 corrupt; not multiple of 4")
	}

	paddingCount := 0
	if text[len(text)-2] == '=' {
		paddingCount = 2
	} else if text[len(text)-1] == '=' {
		paddingCount = 1
	}

	decodedString := make([]byte, (len(text)/4)*3-paddingCount)

	for i, j := 0, 0; i < len(text); i, j = i+4, j+3 {

		ch1 := byte(strings.IndexByte(base64Map, text[i]))
		ch2 := byte(strings.IndexByte(base64Map, text[i+1]))
		ch3, ch4 := byte(0), byte(0)
		if text[i+2] != '=' {
			ch3 = byte(strings.IndexByte(base64Map, text[i+2]))
		}
		if text[i+3] != '=' {
			ch4 = byte(strings.IndexByte(base64Map, text[i+3]))
		}

		decodedString[j] = (ch1 << 2) | (ch2 >> 4)

		if j+1 < len(decodedString) {
			decodedString[j+1] = ((ch2 & 0b00001111) << 4) | (ch3 >> 2)
		}
		if j+2 < len(decodedString) {
			decodedString[j+2] = ((ch3 & 0b00000011) << 6) | ch4
		}
	}

	return decodedString, nil

}
