package handlers

import (
	"fmt"
	"keystone/lib/auth"
	"keystone/lib/db"
	"log"

	"github.com/atotto/clipboard"
)

func CreatePassword(handle string) {
	password := auth.GeneratePassword(16)
	key := auth.GetEncryptionKey()

	encrypted, err := auth.Encrypt(password, string(key))
	if err != nil {
		log.Fatalf("Failed to encrypt new password: %s", err.Error())
	}

	// TODO: Confirm if key clash

	db.Put(handle, encrypted)

	fmt.Printf("Password for %s created and copied to clipboard", handle)

	clipboard.WriteAll(password)
}

func ListPasswords() {
	passwordKeys := db.List(0)
	if len(passwordKeys) == 0 {
		fmt.Println("No passwords stored")
		return
	}

	fmt.Println("Stored Passwords:")
	for _, p := range passwordKeys {
		str := string(p)
		if str != "$MASTER$" {
			fmt.Printf("%s\n", str)
		}
	}
}

func GetPassword(handle string) {
	password := db.Get(handle)
	if password == nil {
		log.Fatalf("\nNo password at handle %s", handle)
	}

	key := auth.GetEncryptionKey()
	decrypted, err := auth.Decrypt(string(password), key)
	if err != nil {
		log.Fatalf("Failed to decrypt new password: %s", err.Error())
	}

	fmt.Printf("Password for %s copied to clipboard", handle)

	clipboard.WriteAll(string(decrypted))
}

func DeletePassword(handle string) {
	// TODO: confirmation
}
