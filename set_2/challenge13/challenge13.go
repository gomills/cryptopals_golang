package challenge13

import (
	"crypto/aes"
	"crypto/rand"
	"cryptopals/set_2/challenge10"
	"cryptopals/set_2/pkcs7"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

func challenge13() {

	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	// We want to bruteforce what the last encrypted block for an admin user would look like, conveniently considering that it would
	// start with "a" (admin/pad/pad...)
	adminBlock, _ := pkcs7.PadWithPKCS7([]byte("admin"), aes.BlockSize)

	// This dummy is necessary to make of adminBlock a standalone block in the encryption (take into account oracle returns email=, so
	// if we don't perform this step we would get the admin block mixed with email= as a starting string)
	dummy := make([]byte, aes.BlockSize-len("email="))

	firstBruteForceBlock := append(dummy, adminBlock...)
	encryptedAdminBlock := OracleEncryption(firstBruteForceBlock, key)[aes.BlockSize : aes.BlockSize*2]

	// Let's craft an email the exact length so that "user" gets pushed to the last block with padding
	emailLengthForNoPadding := 0
	lastSize := 0
	currentSize := 0
	firstRound := true
	for {

		if lastSize > currentSize {
			break
		}

		if !firstRound {
			emailLengthForNoPadding++
		}

		artificialEmail := make([]byte, emailLengthForNoPadding)
		for x := range emailLengthForNoPadding {
			artificialEmail[x] = 0
		}

		lastSize = len(OracleEncryption(artificialEmail, key))
		if firstRound {
			currentSize = lastSize
			firstRound = false
		}
	}

	fmt.Printf("Necessary email length is %d (%d > %d)", emailLengthForNoPadding, lastSize, currentSize)
	offsetToPushUser := emailLengthForNoPadding + len("user")

	adminEmail := make([]byte, offsetToPushUser)
	for x := range adminEmail {
		adminEmail[x] = byte('l')
	}

	encryption := OracleEncryption(adminEmail, key)

	n := copy(encryption[len(encryption)-aes.BlockSize:], encryptedAdminBlock)
	if n != aes.BlockSize {
		panic("error when substituting last block")
	}

	decryptedAdminProfile := DecryptUser(encryption, key)

	fmt.Println(string(decryptedAdminProfile))

}

func ParseKV(input string) map[string]string {

	parsed := map[string]string{}

	kvs := strings.SplitSeq(input, "&")

	for kv := range kvs {

		sep := strings.Split(kv, "=")
		parsed[sep[0]] = sep[1]

	}

	return parsed
}

func OracleEncryption(email []byte, key []byte) []byte {
	encodedProfile := CreateProfile(string(email))
	encryptedUser := challenge10.EncryptECB([]byte(encodedProfile), key)
	return encryptedUser
}

func CreateProfile(email string) string {

	// Avoid client-side injection!
	prohibitedIndex := strings.IndexAny(email, "&=")
	if prohibitedIndex != -1 {
		email = email[:prohibitedIndex]
	}

	uid, _ := uuid.NewUUID()

	return fmt.Sprintf("%s=%s&%s=%s&%s=%s", "email", email, "user", uid.String(), "role", "user")
}

func DecryptUser(encrypted []byte, key []byte) []byte {
	decrypted, err := challenge10.DecryptECB(encrypted, key)
	if err != nil {
		panic(err)
	}
	return decrypted
}
