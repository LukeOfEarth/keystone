package tests

import (
	"keystone/lib/auth"
	"testing"
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
