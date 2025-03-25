package cmd

import (
	"fmt"
	"os"

	"keystone/lib/auth"
	"keystone/lib/db"
	"keystone/lib/handlers"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ks",
	Short: "Keystone is a secure local password management tool",
	Long:  `A password manager for the engineer who doesn't like leaving their terminal`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		db.InitDB()
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		db.CloseDB()
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Keystone",
	Long:  `All software has versions. This is Keystone's`,
	Run: func(cmd *cobra.Command, args []string) {
		auth.CheckPassword()
		handlers.PrintVersion()
	},
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the master key",
	Long:  `Confirms the password used to encrypt/decrypt the vault`,
	Run: func(cmd *cobra.Command, args []string) {
		auth.CreateMasterPassword()
	},
}

var generatePasswordCmd = &cobra.Command{
	Use:   "new [password handle]",
	Short: "Generate a new password",
	Long:  `Generates, encrypts and stores a new password at the given handle, copying it to clipboard for use`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		auth.CheckPassword()
		handlers.CreatePassword(args[0])
	},
}

var getCmd = &cobra.Command{
	Use:   "get [identifier]",
	Short: "Retrieve a password",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		auth.CheckPassword()
		handlers.GetPassword(args[0])
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all stored identifiers",
	Run: func(cmd *cobra.Command, args []string) {
		auth.CheckPassword()
		handlers.ListPasswords()
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete [identifier]",
	Short: "Delete a stored password",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		auth.CheckPassword()
	},
}

func InitCobra() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(generatePasswordCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(deleteCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
