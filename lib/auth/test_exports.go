package auth

type export struct {
	NewPassword      func(string) string
	HashPassword     func(string, string) string
	ValidatePassword func(string, string) bool
	GenerateSalt     func() string
	DeriveKey        func(string, string, int, int) ([]byte, error)
}

var TestExport = export{newPassword, hashPassword, validatePassword, generateSalt, deriveKey}
