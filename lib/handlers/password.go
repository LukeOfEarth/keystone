package handlers

import (
	"fmt"
	"keystone/lib/auth"
	"keystone/lib/db"
	"log"
	"strings"

	"github.com/atotto/clipboard"
)

func CreatePassword(handle string) {
	if handle == "$MASTER$" {
		log.Fatalln("Identifier $MASTER$ is invalid")
	}

	existing := db.Get(handle)
	if existing != nil {
		fmt.Printf("A password is already saved for identifier %s\n", handle)
		confirmed := ConfirmAction()
		if !confirmed {
			return
		}
	}

	password := auth.GeneratePassword(16)
	key := auth.GetEncryptionKey()

	encrypted, err := auth.Encrypt(password, string(key))
	if err != nil {
		log.Fatalf("Failed to encrypt new password: %s", err.Error())
	}

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
	if handle == "$MASTER$" {
		log.Fatalln("Identifier $MASTER$ is invalid")
	}

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
	if handle == "$MASTER$" {
		log.Fatalln("Identifier $MASTER$ is invalid")
	}

	existing := db.Get(handle)
	if existing == nil {
		log.Fatalf("No password found for identifier %s", handle)
	}

	fmt.Printf("You are trying to delete the password for identifier %s\n", handle)
	fmt.Println("If you continue with this action, you will not be able to retrieve the password in the future")
	confirmed := ConfirmAction()

	if !confirmed {
		return
	}

	err := db.Delete(handle)
	if err != nil {
		log.Fatalf("Failed to delete password for identifier %s: %s", handle, err.Error())
	}

	fmt.Printf("Password for identifier %s successfully deleted", handle)
}

func ConfirmAction() bool {
	fmt.Println("Do you want to continue? (y/n)")

	var text string
	_, err := fmt.Scanf("%s", &text)
	if err != nil {
		log.Fatal(err)
	}

	s := strings.ToLower(text)
	return s == "y"
}
