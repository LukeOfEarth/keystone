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
		fmt.Println("Master key is already set for this account")
		return
	}

	fmt.Println("Your master key is not set!")
	fmt.Println("Create master key: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("Confirm master key: ")
	confirm, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err.Error())
	}

	if string(confirm) != string(password) {
		fmt.Println("Passwords do not match")
		return
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
		log.Fatal("Invalid master key")
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
		panic(err.Error())
	}

	return string(password)
}
