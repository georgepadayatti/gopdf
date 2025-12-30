package crypt

import (
	"bytes"
	"testing"
)

func TestRC4EncryptDecrypt(t *testing.T) {
	key := []byte("testkey123")
	plaintext := []byte("Hello, World!")

	encrypted, err := RC4Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("RC4Encrypt failed: %v", err)
	}

	decrypted, err := RC4Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("RC4Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestAESCBCEncryptDecrypt(t *testing.T) {
	key := make([]byte, 16) // AES-128
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("This is a test message for AES encryption")

	encrypted, err := AESCBCEncrypt(key, plaintext, nil)
	if err != nil {
		t.Fatalf("AESCBCEncrypt failed: %v", err)
	}

	// Encrypted should be longer than plaintext (IV + padding)
	if len(encrypted) <= len(plaintext) {
		t.Errorf("Encrypted length = %d, should be > %d", len(encrypted), len(plaintext))
	}

	decrypted, err := AESCBCDecrypt(key, encrypted)
	if err != nil {
		t.Fatalf("AESCBCDecrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestAESCBCDecryptWithIV(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	plaintext := []byte("0123456789abcdef") // Exactly one block

	// Encrypt manually
	encrypted, err := AESCBCEncrypt(key, plaintext, iv)
	if err != nil {
		t.Fatalf("AESCBCEncrypt failed: %v", err)
	}

	// Remove IV from encrypted (it was prepended)
	ciphertext := encrypted[16:]

	decrypted, err := AESCBCDecryptWithIV(key, ciphertext, iv, true)
	if err != nil {
		t.Fatalf("AESCBCDecryptWithIV failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestTripleDESDecrypt(t *testing.T) {
	// 24-byte key for 3DES
	key := []byte("123456789012345678901234")
	iv := make([]byte, 8)
	data := make([]byte, 16) // Must be multiple of 8

	// This is a basic test - just ensure no panics
	_, err := TripleDESDecrypt(key, data, iv)
	// Error expected due to invalid padding in test data
	if err == nil {
		t.Log("TripleDESDecrypt completed (padding may be invalid)")
	}
}

func TestTripleDESDecrypt_InvalidKey(t *testing.T) {
	key := []byte("short") // Too short
	iv := make([]byte, 8)
	data := make([]byte, 16)

	_, err := TripleDESDecrypt(key, data, iv)
	if err != ErrInvalidKeyLength {
		t.Errorf("Expected ErrInvalidKeyLength, got %v", err)
	}
}

func TestPKCS7Pad(t *testing.T) {
	testCases := []struct {
		input     []byte
		blockSize int
		expected  int // expected output length
	}{
		{[]byte(""), 16, 16},
		{[]byte("x"), 16, 16},
		{[]byte("0123456789abcde"), 16, 16},
		{[]byte("0123456789abcdef"), 16, 32}, // Full block adds another block
		{[]byte("test"), 8, 8},
	}

	for _, tc := range testCases {
		result := PKCS7Pad(tc.input, tc.blockSize)
		if len(result) != tc.expected {
			t.Errorf("PKCS7Pad(%q, %d) length = %d, want %d", tc.input, tc.blockSize, len(result), tc.expected)
		}
		if len(result)%tc.blockSize != 0 {
			t.Errorf("PKCS7Pad result not multiple of block size")
		}
	}
}

func TestPKCS7Unpad(t *testing.T) {
	// Create properly padded data
	data := append([]byte("test"), 4, 4, 4, 4)
	result, err := PKCS7Unpad(data)
	if err != nil {
		t.Fatalf("PKCS7Unpad failed: %v", err)
	}
	if !bytes.Equal(result, []byte("test")) {
		t.Errorf("PKCS7Unpad = %q, want %q", result, "test")
	}
}

func TestPKCS7Unpad_Empty(t *testing.T) {
	result, err := PKCS7Unpad([]byte{})
	if err != nil {
		t.Fatalf("PKCS7Unpad failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("PKCS7Unpad empty should return empty")
	}
}

func TestPKCS7PadUnpad_Roundtrip(t *testing.T) {
	testCases := [][]byte{
		{},
		{0x01},
		{0x01, 0x02, 0x03},
		[]byte("Hello, World!"),
		make([]byte, 16), // Full block
		make([]byte, 17), // One more than block
	}

	for _, original := range testCases {
		padded := PKCS7Pad(original, 16)
		unpadded, err := PKCS7Unpad(padded)
		if err != nil {
			t.Fatalf("PKCS7Unpad failed for %q: %v", original, err)
		}
		if !bytes.Equal(unpadded, original) {
			t.Errorf("Roundtrip failed: got %q, want %q", unpadded, original)
		}
	}
}

func TestDeriveObjectKey(t *testing.T) {
	fileKey := []byte("0123456789abcdef") // 16 bytes
	objNum := 1
	genNum := 0

	t.Run("RC4", func(t *testing.T) {
		key := DeriveObjectKey(fileKey, objNum, genNum, false)
		if len(key) != 16 { // min(16+5, 16) = 16
			t.Errorf("Key length = %d, want 16", len(key))
		}
	})

	t.Run("AES", func(t *testing.T) {
		key := DeriveObjectKey(fileKey, objNum, genNum, true)
		if len(key) != 16 {
			t.Errorf("Key length = %d, want 16", len(key))
		}
	})

	t.Run("ShortKey", func(t *testing.T) {
		shortKey := []byte("12345") // 5 bytes
		key := DeriveObjectKey(shortKey, objNum, genNum, false)
		if len(key) != 10 { // 5+5 = 10
			t.Errorf("Key length = %d, want 10", len(key))
		}
	})
}

func TestCryptFilter(t *testing.T) {
	t.Run("Identity", func(t *testing.T) {
		f := NewCryptFilter(CryptFilterIdentity, 0)
		data := []byte("test data")

		encrypted, err := f.Encrypt(nil, data)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		if !bytes.Equal(encrypted, data) {
			t.Error("Identity filter should not modify data")
		}

		decrypted, err := f.Decrypt(nil, data)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}
		if !bytes.Equal(decrypted, data) {
			t.Error("Identity filter should not modify data")
		}
	})

	t.Run("RC4", func(t *testing.T) {
		f := NewCryptFilter(CryptFilterV2, 16)
		key := []byte("0123456789abcdef")
		data := []byte("test data")

		encrypted, err := f.Encrypt(key, data)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		decrypted, err := f.Decrypt(key, encrypted)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, data) {
			t.Errorf("Decrypted = %q, want %q", decrypted, data)
		}
	})

	t.Run("AES", func(t *testing.T) {
		f := NewCryptFilter(CryptFilterAESV2, 16)
		key := []byte("0123456789abcdef")
		data := []byte("test data for AES encryption")

		encrypted, err := f.Encrypt(key, data)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		decrypted, err := f.Decrypt(key, encrypted)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, data) {
			t.Errorf("Decrypted = %q, want %q", decrypted, data)
		}
	})
}

func TestCryptFilterType_Constants(t *testing.T) {
	if CryptFilterNone != "None" {
		t.Errorf("CryptFilterNone = %q, want 'None'", CryptFilterNone)
	}
	if CryptFilterV2 != "V2" {
		t.Errorf("CryptFilterV2 = %q, want 'V2'", CryptFilterV2)
	}
	if CryptFilterAESV2 != "AESV2" {
		t.Errorf("CryptFilterAESV2 = %q, want 'AESV2'", CryptFilterAESV2)
	}
	if CryptFilterAESV3 != "AESV3" {
		t.Errorf("CryptFilterAESV3 = %q, want 'AESV3'", CryptFilterAESV3)
	}
	if CryptFilterIdentity != "Identity" {
		t.Errorf("CryptFilterIdentity = %q, want 'Identity'", CryptFilterIdentity)
	}
}
