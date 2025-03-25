package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

func newPassword(password string) string {
	salt := generateSalt()
	hash := hashPassword(password, salt)
	return fmt.Sprintf("%s.%s", hash, salt)
}

func hashPassword(password, salt string) string {
	saltBytes, _ := base64.StdEncoding.DecodeString(salt)
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(hash)
}

func validatePassword(password, master string) bool {
	parts := strings.Split(master, ".")
	hash := hashPassword(password, parts[1])
	return hash == parts[0]
}

func generateSalt() string {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(fmt.Errorf("error generating salt: %v", err.Error()))
	}
	return base64.StdEncoding.EncodeToString(salt)
}
