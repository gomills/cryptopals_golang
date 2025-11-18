package customhex

import (
	"fmt"
	"strings"
)

// Hexadecimal map
var hexMap = "0123456789abcdef"

// Decode Hexadecimal string to binary as []byte.
func DecodeHex(hexString string) ([]byte, error) {

	hexString = strings.ToLower(hexString)

	// Encoding is corrupt if not multiple of 2
	if len(hexString)%2 != 0 {
		return nil, fmt.Errorf("missing bits")
	}

	// Precompute the decoded array
	decoded := make([]byte, len(hexString)/2)

	for i := 0; i < len(hexString); i += 2 {

		ind1 := strings.IndexByte(hexMap, hexString[i])
		ind2 := strings.IndexByte(hexMap, hexString[i+1])

		// If a character can't be mapped it's not hex encoded
		if ind1 == -1 || ind2 == -1 {
			return nil, fmt.Errorf("not encoded in hex")
		}

		// Bitwise operations to get the decoded byte
		result := (ind1 << 4) | ind2

		decoded[i/2] = byte(result)
	}

	// This is the raw binary
	return decoded, nil

}

func EncodeHex(bytes []byte) string {

	// Precompute the encoded array
	encoded := make([]byte, len(bytes)*2)

	for i, b := range bytes {

		encoded[i*2] = hexMap[b>>4]
		encoded[i*2+1] = hexMap[b&0x0F]

	}

	return string(encoded)
}
