package challenge5

// const (
// 	encryptKey    = "ICE"
// 	secretMessage = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
// )

func EncryptRepKeyXor(rawText []byte, cipherKey []byte) []byte {

	encryptedMessage := make([]byte, len(rawText))

	for i, j := 0, 0; i < len(rawText); i, j = i+1, j+1 {

		if j == len(cipherKey) {
			j = 0
		}

		encryptedMessage[i] = rawText[i] ^ cipherKey[j]

	}

	return encryptedMessage

}
