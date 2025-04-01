package tests

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"keystone/lib/auth"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestEncrypt(t *testing.T) {
	t.Run("Valid encryption", func(t *testing.T) {
		key := "thisis32bytekeythisis32bytekey1!" // 32 bytes for AES-256
		plaintext := "Hello, world!"
		ciphertext, err := auth.Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		if ciphertext == "" {
			t.Fatal("Ciphertext should not be empty")
		}
	})

	t.Run("Invalid key length", func(t *testing.T) {
		key := "shortkey"
		plaintext := "Hello, world!"
		_, err := auth.Encrypt(plaintext, key)
		if err == nil {
			t.Fatal("Expected error for invalid key length, but got nil")
		}
	})

	t.Run("Empty plaintext", func(t *testing.T) {
		key := "thisis32bytekeythisis32bytekey1!" // 32 bytes
		ciphertext, err := auth.Encrypt("", key)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		if ciphertext == "" {
			t.Fatal("Ciphertext should not be empty for empty plaintext")
		}
	})

	t.Run("Unique ciphertexts", func(t *testing.T) {
		key := "thisis32bytekeythisis32bytekey1!" // 32 bytes
		plaintext := "Hello, world!"

		ciphertext1, err1 := auth.Encrypt(plaintext, key)
		ciphertext2, err2 := auth.Encrypt(plaintext, key)

		if err1 != nil || err2 != nil {
			t.Fatalf("Encryption failed: err1=%v, err2=%v", err1, err2)
		}
		if ciphertext1 == ciphertext2 {
			t.Fatal("Ciphertexts should be unique due to random nonce")
		}
	})

	t.Run("Maximum key size (AES-256)", func(t *testing.T) {
		key := "thisis32bytekeythisis32bytekey1!" // 32 bytes
		plaintext := "Some long text for testing."
		ciphertext, err := auth.Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		if ciphertext == "" {
			t.Fatal("Ciphertext should not be empty")
		}
	})

	t.Run("Minimum key size (AES-128)", func(t *testing.T) {
		key := "thisis16bytekey!" // 16 bytes
		plaintext := "Short text."
		ciphertext, err := auth.Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		if ciphertext == "" {
			t.Fatal("Ciphertext should not be empty")
		}
	})

	t.Run("Different plaintexts produce different ciphertexts", func(t *testing.T) {
		key := "thisis32bytekeythisis32bytekey1!" // 32 bytes
		plaintext1 := "Message One"
		plaintext2 := "Message Two"
		ciphertext1, _ := auth.Encrypt(plaintext1, key)
		ciphertext2, _ := auth.Encrypt(plaintext2, key)

		if ciphertext1 == ciphertext2 {
			t.Fatal("Different plaintexts should produce different ciphertexts")
		}
	})

	t.Run("Very long plaintext", func(t *testing.T) {
		key := "thisis32bytekeythisis32bytekey1!" // 32 bytes
		plaintext := string(make([]byte, 10000))  // 10KB of zero bytes
		ciphertext, err := auth.Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		if ciphertext == "" {
			t.Fatal("Ciphertext should not be empty for large plaintext")
		}
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("Valid decryption", func(t *testing.T) {
		key := "thisis32bytekeythisis32bytekey!1"
		plaintext := "Hello, world!"
		ciphertext, _ := auth.Encrypt(plaintext, key)
		decrypted, err := auth.Decrypt(ciphertext, key)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if decrypted != plaintext {
			t.Fatalf("Expected %q, got %q", plaintext, decrypted)
		}
	})

	t.Run("Incorrect key", func(t *testing.T) {
		key := "thisis32bytekeythisis32bytekey1!"
		wrongKey := "wrong32bytekeywrong32bytekey!!"
		plaintext := "Sensitive data"
		ciphertext, _ := auth.Encrypt(plaintext, key)
		_, err := auth.Decrypt(ciphertext, wrongKey)
		if err == nil {
			t.Fatal("Expected error for incorrect key, but got nil")
		}
	})

	t.Run("Corrupted ciphertext", func(t *testing.T) {
		key := "thisis32bytekeythisis32bytekey1!"
		plaintext := "Valid message"
		ciphertext, _ := auth.Encrypt(plaintext, key)
		corrupted := ciphertext[:len(ciphertext)-4] + "abcd"
		_, err := auth.Decrypt(corrupted, key)
		if err == nil {
			t.Fatal("Expected error for corrupted ciphertext, but got nil")
		}
	})

	t.Run("Invalid base64 input", func(t *testing.T) {
		key := "thisis32bytekeythisis32bytekey1!"
		_, err := auth.Decrypt("notbase64!!", key)
		if err == nil {
			t.Fatal("Expected error for invalid base64 input, but got nil")
		}
	})

	t.Run("Empty ciphertext", func(t *testing.T) {
		key := "thisis32bytekeythisis32bytekey1!"
		_, err := auth.Decrypt("", key)
		if err == nil {
			t.Fatal("Expected error for empty ciphertext, but got nil")
		}
	})
}

func TestGenerateSalt(t *testing.T) {
	// Access the exported function through TestExport
	generateSaltFunc := auth.TestExport.GenerateSalt

	t.Run("Salt format validation", func(t *testing.T) {
		salt := generateSaltFunc()

		// Check that salt is valid base64 encoded string
		_, err := base64.StdEncoding.DecodeString(salt)
		if err != nil {
			t.Errorf("Generated salt is not a valid base64 string: %s", salt)
		}

		// Check that salt matches base64 pattern
		base64Pattern := "^[A-Za-z0-9+/]*={0,2}$"
		matched, _ := regexp.MatchString(base64Pattern, salt)
		if !matched {
			t.Errorf("Salt does not match expected base64 pattern: %s", salt)
		}
	})

	t.Run("Salt length validation", func(t *testing.T) {
		salt := generateSaltFunc()

		// Decode salt to check original length
		decoded, err := base64.StdEncoding.DecodeString(salt)
		if err != nil {
			t.Fatalf("Failed to decode salt: %v", err)
		}

		// Check that original salt is 16 bytes as defined in the function
		expectedLength := 16
		if len(decoded) != expectedLength {
			t.Errorf("Decoded salt length is %d, expected %d bytes", len(decoded), expectedLength)
		}

		// Base64 encoding of 16 bytes should be 24 characters (including padding)
		// This is because base64 encodes 3 bytes into 4 characters
		// So 16 bytes -> ceil(16/3)*4 = ceil(5.33)*4 = 6*4 = 24 characters
		expectedEncodedLength := 24
		if len(salt) != expectedEncodedLength {
			t.Errorf("Encoded salt length is %d, expected %d characters", len(salt), expectedEncodedLength)
		}
	})

	t.Run("Salt uniqueness", func(t *testing.T) {
		// Generate multiple salts and verify they're unique
		saltMap := make(map[string]bool)
		iterations := 100

		for i := 0; i < iterations; i++ {
			salt := generateSaltFunc()
			if saltMap[salt] {
				t.Errorf("Duplicate salt generated: %s", salt)
			}
			saltMap[salt] = true
		}

		// Verify we have the expected number of unique salts
		if len(saltMap) != iterations {
			t.Errorf("Expected %d unique salts, got %d", iterations, len(saltMap))
		}
	})

	t.Run("Salt randomness check", func(t *testing.T) {
		// Basic randomness check by character frequency analysis
		// This is not a comprehensive randomness test, but can catch obvious issues
		iterations := 1000
		charFreq := make(map[byte]int)
		totalChars := 0

		for i := 0; i < iterations; i++ {
			salt := generateSaltFunc()
			for j := 0; j < len(salt); j++ {
				charFreq[salt[j]]++
				totalChars++
			}
		}

		// Check if any character appears with extreme frequency
		// For a random distribution, we expect roughly even distribution
		avgFreq := float64(totalChars) / float64(len(charFreq))
		for char, freq := range charFreq {
			// Allow for some statistical variation, but catch major deviations
			// (this is a simplified check, not a rigorous statistical test)
			ratio := float64(freq) / avgFreq
			if ratio < 0.5 || ratio > 2.0 {
				t.Logf("Character %c (%d) has unusual frequency: %d occurrences (%.2f of expected)", char, char, freq, ratio)
				// Not failing the test because randomness can have natural variations
				// Just logging for investigation if needed
			}
		}

		// Verify we have a reasonable character set size for base64
		// We expect to see most of the 64 possible base64 characters + padding
		expectedMinChars := 40 // Reasonable lower bound for 1000 iterations
		if len(charFreq) < expectedMinChars {
			t.Errorf("Only %d unique characters observed in %d salts, expected at least %d",
				len(charFreq), iterations, expectedMinChars)
		}
	})

	t.Run("Consistent salt size across calls", func(t *testing.T) {
		// Verify that each generated salt has the same length
		firstSalt := generateSaltFunc()
		firstLength := len(firstSalt)

		for i := 0; i < 50; i++ {
			salt := generateSaltFunc()
			if len(salt) != firstLength {
				t.Errorf("Inconsistent salt length: got %d, expected %d", len(salt), firstLength)
			}
		}
	})
}

func TestHashPassword(t *testing.T) {
	// Access the exported function through TestExport
	hashPasswordFunc := auth.TestExport.HashPassword

	t.Run("Basic functionality", func(t *testing.T) {
		password := "testpassword"
		salt := "MTIzNDU2Nzg5MDEyMzQ1Ng==" // Base64 encoded fixed salt for testing

		hash := hashPasswordFunc(password, salt)

		// Verify the hash is not empty
		if hash == "" {
			t.Error("hashPassword returned an empty string")
		}

		// Verify the hash is valid base64
		_, err := base64.StdEncoding.DecodeString(hash)
		if err != nil {
			t.Errorf("Generated hash is not a valid base64 string: %s", hash)
		}

		// Check base64 pattern
		base64Pattern := "^[A-Za-z0-9+/]*={0,2}$"
		matched, _ := regexp.MatchString(base64Pattern, hash)
		if !matched {
			t.Errorf("Hash does not match expected base64 pattern: %s", hash)
		}
	})

	t.Run("Consistency with same inputs", func(t *testing.T) {
		password := "mysecretpassword"
		salt := "c29tZXJhbmRvbXNhbHQ=" // Some fixed salt for testing

		// Generate hash twice with same inputs
		hash1 := hashPasswordFunc(password, salt)
		hash2 := hashPasswordFunc(password, salt)

		// Hashes should be identical for same inputs
		if hash1 != hash2 {
			t.Errorf("hashPassword produced different results for same inputs: %s vs %s", hash1, hash2)
		}
	})

	t.Run("Different passwords produce different hashes", func(t *testing.T) {
		salt := "c29tZXJhbmRvbXNhbHQ=" // Same salt for both

		hash1 := hashPasswordFunc("password1", salt)
		hash2 := hashPasswordFunc("password2", salt)

		if hash1 == hash2 {
			t.Error("Different passwords produced the same hash")
		}
	})

	t.Run("Different salts produce different hashes", func(t *testing.T) {
		password := "samepassword" // Same password for both

		hash1 := hashPasswordFunc(password, "c29tZXJhbmRvbXNhbHQx") // salt1
		hash2 := hashPasswordFunc(password, "c29tZXJhbmRvbXNhbHQy") // salt2

		if hash1 == hash2 {
			t.Error("Different salts produced the same hash")
		}
	})

	t.Run("Hash length verification", func(t *testing.T) {
		password := "testpassword"
		salt := "c29tZXJhbmRvbXNhbHQ="

		hash := hashPasswordFunc(password, salt)
		decoded, _ := base64.StdEncoding.DecodeString(hash)

		// Argon2 with 32-byte output should result in 32 bytes
		expectedBytes := 32
		if len(decoded) != expectedBytes {
			t.Errorf("Hash length is %d bytes, expected %d bytes", len(decoded), expectedBytes)
		}

		// Base64 encoding of 32 bytes should be 44 characters (including padding)
		// 32 bytes -> ceil(32/3)*4 = ceil(10.67)*4 = 11*4 = 44 characters
		expectedEncodedLength := 44
		if len(hash) != expectedEncodedLength {
			t.Errorf("Encoded hash length is %d, expected %d characters", len(hash), expectedEncodedLength)
		}
	})

	t.Run("Direct comparison with argon2.IDKey", func(t *testing.T) {
		password := "directcomparisontest"
		saltString := "ZGlyZWN0Y29tcGFyaXNvbg==" // "directcomparison" in base64
		saltBytes, _ := base64.StdEncoding.DecodeString(saltString)

		// Get hash from our function
		hash := hashPasswordFunc(password, saltString)
		decodedHash, _ := base64.StdEncoding.DecodeString(hash)

		// Compute the expected hash directly
		expectedHash := argon2.IDKey([]byte(password), saltBytes, 1, 64*1024, 4, 32)

		// Compare the raw hash bytes
		if !reflect.DeepEqual(decodedHash, expectedHash) {
			t.Error("hashPassword result doesn't match direct argon2.IDKey calculation")
		}
	})

	t.Run("Empty password handling", func(t *testing.T) {
		salt := "c29tZXJhbmRvbXNhbHQ="
		emptyHash := hashPasswordFunc("", salt)

		// Should produce a valid hash even with empty password
		if emptyHash == "" {
			t.Error("Empty password resulted in empty hash")
		}

		// Empty password should produce different hash than non-empty password
		nonEmptyHash := hashPasswordFunc("somepassword", salt)
		if emptyHash == nonEmptyHash {
			t.Error("Empty and non-empty passwords produced the same hash")
		}
	})

	t.Run("Special character handling", func(t *testing.T) {
		salt := "c29tZXJhbmRvbXNhbHQ="
		specialChars := "!@#$%^&*()_+{}:\"|<>?~`-=[]\\;',./䨻"

		hash := hashPasswordFunc(specialChars, salt)

		// Should produce a valid hash
		if hash == "" {
			t.Error("Special characters resulted in empty hash")
		}

		// Verify consistency
		hash2 := hashPasswordFunc(specialChars, salt)
		if hash != hash2 {
			t.Error("Inconsistent hashing with special characters")
		}
	})

	t.Run("Unicode character handling", func(t *testing.T) {
		salt := "c29tZXJhbmRvbXNhbHQ="
		unicodePassword := "пароль密码パスワードكلمة المرور"

		hash := hashPasswordFunc(unicodePassword, salt)

		// Should produce a valid hash
		if hash == "" {
			t.Error("Unicode characters resulted in empty hash")
		}

		// Verify consistency
		hash2 := hashPasswordFunc(unicodePassword, salt)
		if hash != hash2 {
			t.Error("Inconsistent hashing with Unicode characters")
		}
	})
}

func TestNewPassword(t *testing.T) {
	newPasswordFunc := auth.TestExport.NewPassword
	validatePasswordFunc := auth.TestExport.ValidatePassword

	t.Run("Basic functionality", func(t *testing.T) {
		password := "mysecretpassword"
		result := newPasswordFunc(password)

		// Check format: should be "hash.salt"
		parts := strings.Split(result, ".")
		if len(parts) != 2 {
			t.Errorf("Expected result format 'hash.salt', got: %s", result)
		}

		// Verify the created password hash validates correctly
		if !validatePasswordFunc(password, result) {
			t.Errorf("Password validation failed for newly created hash: %s", result)
		}
	})

	t.Run("Consistent hash format", func(t *testing.T) {
		for _, password := range []string{"simple", "Complex123!", "超級密碼", "verylongpasswordthatexceedstypicalrequirements"} {
			result := newPasswordFunc(password)

			parts := strings.Split(result, ".")
			if len(parts) != 2 {
				t.Errorf("Invalid hash format for password %q, got: %s", password, result)
			}

			// Hash and salt should both be non-empty
			if parts[0] == "" || parts[1] == "" {
				t.Errorf("Empty hash or salt for password %q: %s", password, result)
			}
		}
	})

	t.Run("Unique salts", func(t *testing.T) {
		// Same password should produce different hashes due to different salts
		password := "samepassword"
		results := make(map[string]bool)

		for i := 0; i < 10; i++ {
			result := newPasswordFunc(password)
			parts := strings.Split(result, ".")
			if len(parts) != 2 {
				t.Errorf("Invalid hash format: %s", result)
				continue
			}

			salt := parts[1]
			if results[salt] {
				t.Errorf("Salt reused: %s", salt)
			}
			results[salt] = true
		}
	})

	t.Run("Unique hashes for same password", func(t *testing.T) {
		// Same password should generate different hashes due to different salts
		password := "testpassword"
		hashes := make(map[string]bool)

		for i := 0; i < 5; i++ {
			result := newPasswordFunc(password)
			if hashes[result] {
				t.Errorf("Generated identical hash: %s", result)
			}
			hashes[result] = true
		}
	})

	t.Run("Empty password handling", func(t *testing.T) {
		result := newPasswordFunc("")

		// Should still produce a valid format
		parts := strings.Split(result, ".")
		if len(parts) != 2 {
			t.Errorf("Invalid hash format for empty password: %s", result)
		}

		// Should validate with empty string
		if !validatePasswordFunc("", result) {
			t.Errorf("Validation failed for empty password hash: %s", result)
		}
	})

	t.Run("Different passwords produce different hashes", func(t *testing.T) {
		password1 := "password1"
		password2 := "password2"

		// Force same salt to test that different passwords give different hashes
		// We'll need to mock the generateSalt function for this test
		generateSaltFunc := auth.TestExport.GenerateSalt
		salt := generateSaltFunc()

		hashPasswordFunc := auth.TestExport.HashPassword
		hash1 := hashPasswordFunc(password1, salt)
		hash2 := hashPasswordFunc(password2, salt)

		if hash1 == hash2 {
			t.Errorf("Different passwords produced same hash with same salt")
		}
	})

	t.Run("Edge case: special characters", func(t *testing.T) {
		specialChars := "!@#$%^&*()_+{}:\"|<>?~`-=[]\\;',./䨻"
		result := newPasswordFunc(specialChars)

		// Should produce a valid format
		parts := strings.Split(result, ".")
		if len(parts) != 2 {
			t.Errorf("Invalid hash format for password with special chars: %s", result)
		}

		// Should validate correctly
		if !validatePasswordFunc(specialChars, result) {
			t.Errorf("Validation failed for password with special chars: %s", result)
		}
	})

	t.Run("Consistency check", func(t *testing.T) {
		// Mock fixed salt generation to test hash consistency
		originalSalt := auth.TestExport.GenerateSalt()
		originalHash := auth.TestExport.HashPassword("testpassword", originalSalt)
		formattedResult := originalHash + "." + originalSalt

		// Should validate with the original password
		if !validatePasswordFunc("testpassword", formattedResult) {
			t.Errorf("Validation failed for consistent hash/salt combination")
		}

		// Should not validate with a different password
		if validatePasswordFunc("wrongpassword", formattedResult) {
			t.Errorf("Validation incorrectly passed with wrong password")
		}
	})
}

func TestDeriveKey(t *testing.T) {
	// Access the exported function through TestExport
	deriveKeyFunc := auth.TestExport.DeriveKey

	t.Run("Basic functionality", func(t *testing.T) {
		password := "testpassword"
		salt := "testsalt"
		iterations := 1000
		keyLen := 32

		key, err := deriveKeyFunc(password, salt, iterations, keyLen)
		if err != nil {
			t.Error(err.Error())
		}

		// Check that the key is not nil and has the expected length
		if key == nil {
			t.Error("deriveKey returned nil")
		}

		if len(key) != keyLen {
			t.Errorf("Key length is %d, expected %d", len(key), keyLen)
		}
	})

	t.Run("Consistency with same inputs", func(t *testing.T) {
		password := "mysecretpassword"
		salt := "somesalt"
		iterations := 1000
		keyLen := 32

		// Generate key twice with same inputs
		key1, err1 := deriveKeyFunc(password, salt, iterations, keyLen)
		if err1 != nil {
			t.Error(err1.Error())
		}

		key2, err2 := deriveKeyFunc(password, salt, iterations, keyLen)
		if err2 != nil {
			t.Error(err2.Error())
		}

		// Keys should be identical for same inputs
		if !bytes.Equal(key1, key2) {
			t.Error("deriveKey produced different results for same inputs")
		}
	})

	t.Run("Different passwords produce different keys", func(t *testing.T) {
		salt := "fixedsalt"
		iterations := 1000
		keyLen := 32

		key1, err1 := deriveKeyFunc("password1", salt, iterations, keyLen)
		if err1 != nil {
			t.Error(err1.Error())
		}

		key2, err2 := deriveKeyFunc("password2", salt, iterations, keyLen)
		if err2 != nil {
			t.Error(err2.Error())
		}

		if bytes.Equal(key1, key2) {
			t.Error("Different passwords produced the same key")
		}
	})

	t.Run("Different salts produce different keys", func(t *testing.T) {
		password := "samepassword"
		iterations := 1000
		keyLen := 32

		key1, err1 := deriveKeyFunc(password, "salt1", iterations, keyLen)
		if err1 != nil {
			t.Error(err1.Error())
		}

		key2, err2 := deriveKeyFunc(password, "salt2", iterations, keyLen)
		if err2 != nil {
			t.Error(err2.Error())
		}

		if bytes.Equal(key1, key2) {
			t.Error("Different salts produced the same key")
		}
	})

	t.Run("Different iterations produce different keys", func(t *testing.T) {
		password := "testpassword"
		salt := "testsalt"
		keyLen := 32

		key1, err1 := deriveKeyFunc(password, salt, 1000, keyLen)
		if err1 != nil {
			t.Error(err1.Error())
		}

		key2, err2 := deriveKeyFunc(password, salt, 2000, keyLen)
		if err2 != nil {
			t.Error(err2.Error())
		}

		if bytes.Equal(key1, key2) {
			t.Error("Different iterations produced the same key")
		}
	})

	t.Run("Different key lengths", func(t *testing.T) {
		password := "testpassword"
		salt := "testsalt"
		iterations := 1000

		key16, err1 := deriveKeyFunc(password, salt, iterations, 16)
		if err1 != nil {
			t.Error(err1.Error())
		}

		key32, err2 := deriveKeyFunc(password, salt, iterations, 32)
		if err2 != nil {
			t.Error(err2.Error())
		}

		key64, err3 := deriveKeyFunc(password, salt, iterations, 64)
		if err3 != nil {
			t.Error(err3.Error())
		}

		// Check correct lengths
		if len(key16) != 16 {
			t.Errorf("Key length is %d, expected 16", len(key16))
		}
		if len(key32) != 32 {
			t.Errorf("Key length is %d, expected 32", len(key32))
		}
		if len(key64) != 64 {
			t.Errorf("Key length is %d, expected 64", len(key64))
		}

		// Check that larger keys start with smaller keys
		// This is a property of PBKDF2
		if !bytes.Equal(key16, key32[:16]) {
			t.Error("32-byte key doesn't start with the same bytes as 16-byte key")
		}
		if !bytes.Equal(key32, key64[:32]) {
			t.Error("64-byte key doesn't start with the same bytes as 32-byte key")
		}
	})

	t.Run("Direct comparison with pbkdf2.Key", func(t *testing.T) {
		password := "comparisontest"
		salt := "comparisonsalt"
		iterations := 1000
		keyLen := 32

		// Get key from our function
		key, err := deriveKeyFunc(password, salt, iterations, keyLen)
		if err != nil {
			t.Error(err.Error())
		}

		// Compute the expected key directly
		expectedKey, err := pbkdf2.Key(sha256.New, password, []byte(salt), iterations, keyLen)
		if err != nil {
			t.Error(err.Error())
		}

		// Compare the keys
		if !bytes.Equal(key, expectedKey) {
			t.Error("deriveKey result doesn't match direct pbkdf2.Key calculation")
		}
	})

	t.Run("Empty password handling", func(t *testing.T) {
		salt := "testsalt"
		iterations := 1000
		keyLen := 32

		emptyKey, err := deriveKeyFunc("", salt, iterations, keyLen)
		if err != nil {
			t.Error(err.Error())
		}

		// Should produce a valid key even with empty password
		if emptyKey == nil || len(emptyKey) != keyLen {
			t.Error("Empty password resulted in invalid key")
		}

		// Empty password should produce different key than non-empty password
		nonEmptyKey, err := deriveKeyFunc("somepassword", salt, iterations, keyLen)
		if err != nil {
			t.Error(err.Error())
		}

		if bytes.Equal(emptyKey, nonEmptyKey) {
			t.Error("Empty and non-empty passwords produced the same key")
		}
	})

	t.Run("Empty salt handling", func(t *testing.T) {
		password := "testpassword"
		iterations := 1000
		keyLen := 32

		emptyKey, err := deriveKeyFunc(password, "", iterations, keyLen)
		if err != nil {
			t.Error(err.Error())
		}

		// Should produce a valid key even with empty salt
		if emptyKey == nil || len(emptyKey) != keyLen {
			t.Error("Empty salt resulted in invalid key")
		}

		// Empty salt should produce different key than non-empty salt
		nonEmptyKey, err := deriveKeyFunc(password, "somesalt", iterations, keyLen)
		if err != nil {
			t.Error(err.Error())
		}

		if bytes.Equal(emptyKey, nonEmptyKey) {
			t.Error("Empty and non-empty salts produced the same key")
		}
	})

	t.Run("Zero iterations handling", func(t *testing.T) {
		password := "testpassword"
		salt := "testsalt"
		keyLen := 32

		// Zero iterations should still work in PBKDF2
		_, err := deriveKeyFunc(password, salt, 0, keyLen)
		if err == nil {
			t.Error("Zero iterations should have failed")
		}
	})

	t.Run("Special character handling", func(t *testing.T) {
		specialChars := "!@#$%^&*()_+{}:\"|<>?~`-=[]\\;',./䨻"
		salt := "normalsalt"
		iterations := 1000
		keyLen := 32

		key, err1 := deriveKeyFunc(specialChars, salt, iterations, keyLen)
		if err1 != nil {
			t.Error(err1.Error())
		}

		// Should produce a valid key
		if key == nil || len(key) != keyLen {
			t.Error("Special characters resulted in invalid key")
		}

		// Verify consistency
		key2, err2 := deriveKeyFunc(specialChars, salt, iterations, keyLen)
		if err2 != nil {
			t.Error(err2.Error())
		}

		if !bytes.Equal(key, key2) {
			t.Error("Inconsistent key derivation with special characters")
		}
	})

	t.Run("Unicode character handling", func(t *testing.T) {
		unicodePassword := "пароль密码パスワードكلمة المرور"
		salt := "normalsalt"
		iterations := 1000
		keyLen := 32

		key, err1 := deriveKeyFunc(unicodePassword, salt, iterations, keyLen)
		if err1 != nil {
			t.Error(err1.Error())
		}

		// Should produce a valid key
		if key == nil || len(key) != keyLen {
			t.Error("Unicode characters resulted in invalid key")
		}

		// Verify consistency
		key2, err2 := deriveKeyFunc(unicodePassword, salt, iterations, keyLen)
		if err2 != nil {
			t.Error(err2.Error())
		}

		if !bytes.Equal(key, key2) {
			t.Error("Inconsistent key derivation with Unicode characters")
		}
	})

	t.Run("Performance with high iterations", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping performance test in short mode")
		}

		password := "testpassword"
		salt := "testsalt"
		keyLen := 32
		highIterations := 100000 // High but reasonable for PBKDF2

		// This should complete without timing out
		key, err := deriveKeyFunc(password, salt, highIterations, keyLen)
		if err != nil {
			t.Error(err.Error())
		}

		if key == nil || len(key) != keyLen {
			t.Error("High iterations resulted in invalid key")
		}
	})
}
