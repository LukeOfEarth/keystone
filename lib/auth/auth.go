package auth

import (
	"fmt"
	"keystone/lib/db"
	"log"
	"syscall"

	"golang.org/x/term"
)

func CreateMasterPassword() {
	exists := checkPasswordInit()
	if exists {
		log.Fatalln("Master key is already set for this account")
	}

	fmt.Println("Your master key is not set!")
	fmt.Println("Create master key: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password input: %s", err.Error())
	}

	fmt.Println("Confirm master key: ")
	confirm, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password input: %s", err.Error())
	}

	if string(confirm) != string(password) {
		log.Fatalln("Passwords do not match")
	}

	hashed := newPassword(string(password))
	db.Put("$MASTER$", hashed)
	fmt.Println("Master key set!")
}

func CheckPassword() string {
	master := db.Get("$MASTER$")
	password := requestPassword()
	valid := validatePassword(password, string(master))

	if !valid {
		log.Fatalln("Invalid master key")
	}

	return password
}

func checkPasswordInit() bool {
	exists := db.Get("$MASTER$")
	return exists != nil
}

func requestPassword() string {
	fmt.Println("Enter master key: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password input: %s", err.Error())
	}

	return string(password)
}
