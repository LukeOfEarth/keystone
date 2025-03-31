package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"keystone/lib/db"
	"log"
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
		log.Fatalf("Error generating salt: %v", err.Error())
	}
	return base64.StdEncoding.EncodeToString(salt)
}

func GetEncryptionKey() string {
	master := db.Get("$MASTER$")
	parts := strings.Split(string(master), ".")
	return string(deriveKey(parts[0], parts[1], 10, 32))
}

func deriveKey(password, salt string, iterations, keyLen int) []byte {
	key, err := pbkdf2.Key(sha256.New, password, []byte(salt), iterations, keyLen)
	if err != nil {
		log.Fatalf("Error deriving key: %v", err)
	}
	return key
}

func Encrypt(plaintext, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(encrypted, key string) (string, error) {
	if encrypted == "" {
		return "", errors.New("encrypted string cannot be empty")
	}

	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce, ciphertext := data[:12], data[12:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func GeneratePassword(length int) string {
	if length < 8 {
		log.Fatal("Password length should be at least 8 characters")
	}

	bytes := make([]byte, length)

	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatalf("Error generating password: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes)[:length]
}
