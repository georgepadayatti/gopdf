package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"hash"
	"math/big"
	"testing"
	"time"
)

// sha256New returns a new SHA-256 hash for testing.
func sha256New() hash.Hash {
	return sha256.New()
}

func TestPubKeyPermissions(t *testing.T) {
	t.Run("AllowEverything", func(t *testing.T) {
		var p PubKeyPermissions
		all := p.AllowEverything()

		if all&PubKeyPermPrint == 0 {
			t.Error("AllowEverything should include Print")
		}
		if all&PubKeyPermModify == 0 {
			t.Error("AllowEverything should include Modify")
		}
		if all&PubKeyPermCopy == 0 {
			t.Error("AllowEverything should include Copy")
		}
	})

	t.Run("AsBytes", func(t *testing.T) {
		p := PubKeyPermPrint | PubKeyPermCopy
		bytes := p.AsBytes()

		if len(bytes) != 4 {
			t.Errorf("AsBytes should return 4 bytes, got %d", len(bytes))
		}

		// Reconstruct and verify
		reconstructed := PubKeyPermissionsFromBytes(bytes)
		if reconstructed != p {
			t.Errorf("Reconstructed permissions %v != original %v", reconstructed, p)
		}
	})

	t.Run("FromBytesShort", func(t *testing.T) {
		p := PubKeyPermissionsFromBytes([]byte{0x01, 0x02})
		if p != 0 {
			t.Errorf("FromBytes with short input should return 0, got %v", p)
		}
	})
}

func TestPubKeyAdbeSubFilter(t *testing.T) {
	if SubFilterS3 != "/adbe.pkcs7.s3" {
		t.Errorf("SubFilterS3 = %q, want /adbe.pkcs7.s3", SubFilterS3)
	}
	if SubFilterS4 != "/adbe.pkcs7.s4" {
		t.Errorf("SubFilterS4 = %q, want /adbe.pkcs7.s4", SubFilterS4)
	}
	if SubFilterS5 != "/adbe.pkcs7.s5" {
		t.Errorf("SubFilterS5 = %q, want /adbe.pkcs7.s5", SubFilterS5)
	}
}

func TestSecurityHandlerVersion(t *testing.T) {
	testCases := []struct {
		version  SecurityHandlerVersion
		expected int
	}{
		{SecurityHandlerVersionRC440, 1},
		{SecurityHandlerVersionRC4Longer, 2},
		{SecurityHandlerVersionRC4OrAES128, 4},
		{SecurityHandlerVersionAES256, 5},
		{SecurityHandlerVersionAESGCM, 6},
	}

	for _, tc := range testCases {
		if int(tc.version) != tc.expected {
			t.Errorf("Version %v = %d, want %d", tc.version, int(tc.version), tc.expected)
		}
	}
}

func TestAESKeyWrap(t *testing.T) {
	// Test vectors from RFC 3394
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}
	plaintext := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	}

	wrapped, err := aesKeyWrap(kek, plaintext)
	if err != nil {
		t.Fatalf("aesKeyWrap failed: %v", err)
	}

	unwrapped, err := aesKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("aesKeyUnwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, plaintext) {
		t.Errorf("Unwrapped key doesn't match original")
	}
}

func TestAESKeyWrapInvalidInput(t *testing.T) {
	kek := make([]byte, 16)

	// Too short
	_, err := aesKeyWrap(kek, []byte{1, 2, 3})
	if err == nil {
		t.Error("Expected error for too short input")
	}

	// Not multiple of 8
	_, err = aesKeyWrap(kek, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	if err == nil {
		t.Error("Expected error for non-multiple of 8")
	}
}

func TestAESKeyUnwrapInvalidInput(t *testing.T) {
	kek := make([]byte, 16)

	// Too short
	_, err := aesKeyUnwrap(kek, []byte{1, 2, 3})
	if err == nil {
		t.Error("Expected error for too short input")
	}

	// Invalid integrity check
	invalid := make([]byte, 24)
	_, err = aesKeyUnwrap(kek, invalid)
	if err == nil {
		t.Error("Expected error for invalid wrapped key")
	}
}

func generateTestCertificate(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, key
}

func TestSimpleEnvelopeKeyDecrypter(t *testing.T) {
	cert, key := generateTestCertificate(t)

	t.Run("Create", func(t *testing.T) {
		decrypter, err := NewSimpleEnvelopeKeyDecrypter(cert, key)
		if err != nil {
			t.Fatalf("Failed to create decrypter: %v", err)
		}

		if decrypter.Certificate() != cert {
			t.Error("Certificate mismatch")
		}
	})

	t.Run("NilCertificate", func(t *testing.T) {
		_, err := NewSimpleEnvelopeKeyDecrypter(nil, key)
		if err != ErrNoCertificate {
			t.Errorf("Expected ErrNoCertificate, got %v", err)
		}
	})

	t.Run("NilPrivateKey", func(t *testing.T) {
		_, err := NewSimpleEnvelopeKeyDecrypter(cert, nil)
		if err != ErrNoPrivateKey {
			t.Errorf("Expected ErrNoPrivateKey, got %v", err)
		}
	})
}

func TestSimpleEnvelopeKeyDecrypterRSA(t *testing.T) {
	cert, key := generateTestCertificate(t)
	decrypter, err := NewSimpleEnvelopeKeyDecrypter(cert, key)
	if err != nil {
		t.Fatalf("Failed to create decrypter: %v", err)
	}

	// Test PKCS#1 v1.5 encryption/decryption
	t.Run("PKCS1v15", func(t *testing.T) {
		plaintext := make([]byte, 32)
		rand.Read(plaintext)

		// Encrypt
		encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Decrypt
		algo := KeyEncryptionAlgorithm{Algorithm: OIDRSAESPKCSv15}
		decrypted, err := decrypter.Decrypt(encrypted, algo)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Error("Decrypted text doesn't match plaintext")
		}
	})

	// Test OAEP encryption/decryption
	t.Run("OAEP", func(t *testing.T) {
		plaintext := make([]byte, 32)
		rand.Read(plaintext)

		// Encrypt with OAEP using real sha256
		encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, plaintext, nil)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Decrypt
		algo := KeyEncryptionAlgorithm{Algorithm: OIDRSAESOAEP}
		decrypted, err := decrypter.Decrypt(encrypted, algo)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Error("Decrypted text doesn't match plaintext")
		}
	})
}

func TestPubKeyCryptFilter(t *testing.T) {
	t.Run("Create", func(t *testing.T) {
		cf := NewPubKeyCryptFilter(CryptFilterAESV3, 32, true, true)
		if cf == nil {
			t.Fatal("Failed to create crypt filter")
		}

		if cf.KeyLength != 32 {
			t.Errorf("KeyLength = %d, want 32", cf.KeyLength)
		}
		if !cf.ActsAsDefault {
			t.Error("ActsAsDefault should be true")
		}
		if !cf.EncryptMetadata {
			t.Error("EncryptMetadata should be true")
		}
	})

	t.Run("SharedKeyNil", func(t *testing.T) {
		cf := NewPubKeyCryptFilter(CryptFilterAESV3, 32, true, true)
		if cf.SharedKey() != nil {
			t.Error("SharedKey should be nil before authentication")
		}
	})
}

func TestPubKeySecurityHandler(t *testing.T) {
	t.Run("Create", func(t *testing.T) {
		handler := NewPubKeySecurityHandler(
			SecurityHandlerVersionAES256,
			SubFilterS5,
			32,
		)

		if handler == nil {
			t.Fatal("Failed to create handler")
		}

		if handler.Version != SecurityHandlerVersionAES256 {
			t.Errorf("Version = %v, want AES256", handler.Version)
		}

		if handler.GetName() != "/Adobe.PubSec" {
			t.Errorf("GetName() = %q, want /Adobe.PubSec", handler.GetName())
		}
	})

	t.Run("BuildFromCerts", func(t *testing.T) {
		cert, _ := generateTestCertificate(t)

		handler, err := BuildFromCerts(
			[]*x509.Certificate{cert},
			SecurityHandlerVersionAES256,
			PubKeyPermissions(0).AllowEverything(),
			RecipientEncryptionPolicy{},
			true,
		)

		if err != nil {
			t.Fatalf("BuildFromCerts failed: %v", err)
		}

		if handler == nil {
			t.Fatal("Handler is nil")
		}

		if handler.KDFSalt == nil {
			t.Error("KDFSalt should be set for AES-256")
		}
		if len(handler.KDFSalt) != 32 {
			t.Errorf("KDFSalt length = %d, want 32", len(handler.KDFSalt))
		}
	})

	t.Run("BuildFromCertsNoCerts", func(t *testing.T) {
		_, err := BuildFromCerts(
			nil,
			SecurityHandlerVersionAES256,
			0,
			RecipientEncryptionPolicy{},
			true,
		)

		if err != ErrNoCertificate {
			t.Errorf("Expected ErrNoCertificate, got %v", err)
		}
	})
}

func TestAuthStatus(t *testing.T) {
	if AuthStatusFailed != 0 {
		t.Error("AuthStatusFailed should be 0")
	}
	if AuthStatusUser != 1 {
		t.Error("AuthStatusUser should be 1")
	}
	if AuthStatusOwner != 2 {
		t.Error("AuthStatusOwner should be 2")
	}
}

func TestRecipientEncryptionPolicy(t *testing.T) {
	policy := RecipientEncryptionPolicy{
		IgnoreKeyUsage: true,
		PreferOAEP:     true,
	}

	if !policy.IgnoreKeyUsage {
		t.Error("IgnoreKeyUsage should be true")
	}
	if !policy.PreferOAEP {
		t.Error("PreferOAEP should be true")
	}

	defaultPolicy := RecipientEncryptionPolicy{}
	if defaultPolicy.IgnoreKeyUsage {
		t.Error("Default IgnoreKeyUsage should be false")
	}
	if defaultPolicy.PreferOAEP {
		t.Error("Default PreferOAEP should be false")
	}
}

func TestX963KDF(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	ukm := make([]byte, 16)
	rand.Read(ukm)

	algo := KeyEncryptionAlgorithm{
		Algorithm: OIDDHSinglePassStdDHSHA256KDF,
	}

	// Test key derivation using crypto/sha256
	key := x963KDF(sharedSecret, ukm, algo, 16, sha256New)

	if len(key) != 16 {
		t.Errorf("Derived key length = %d, want 16", len(key))
	}

	// Same inputs should produce same output
	key2 := x963KDF(sharedSecret, ukm, algo, 16, sha256New)
	if !bytes.Equal(key, key2) {
		t.Error("Same inputs should produce same key")
	}

	// Different shared secret should produce different key
	sharedSecret2 := make([]byte, 32)
	rand.Read(sharedSecret2)
	key3 := x963KDF(sharedSecret2, ukm, algo, 16, sha256New)
	if bytes.Equal(key, key3) {
		t.Error("Different shared secret should produce different key")
	}
}

func TestBuildEnvelopedData(t *testing.T) {
	recipientInfos := [][]byte{
		{0x30, 0x10, 0x01, 0x02, 0x03},
	}
	iv := make([]byte, 16)
	encrypted := make([]byte, 32)

	data, err := buildEnvelopedData(recipientInfos, iv, encrypted)
	if err != nil {
		t.Fatalf("buildEnvelopedData failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("EnvelopedData should not be empty")
	}
}

func TestOIDs(t *testing.T) {
	// Test that OIDs are properly defined
	testCases := []struct {
		name     string
		oid      []int
		expected []int
	}{
		{"RSAESPKCSv15", OIDRSAESPKCSv15, []int{1, 2, 840, 113549, 1, 1, 1}},
		{"RSAESOAEP", OIDRSAESOAEP, []int{1, 2, 840, 113549, 1, 1, 7}},
		{"AESWrap128", OIDAESWrap128, []int{2, 16, 840, 1, 101, 3, 4, 1, 5}},
		{"AESWrap256", OIDAESWrap256, []int{2, 16, 840, 1, 101, 3, 4, 1, 45}},
		{"EnvelopedData", OIDEnvelopedData, []int{1, 2, 840, 113549, 1, 7, 3}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.oid) != len(tc.expected) {
				t.Errorf("OID length mismatch: got %d, want %d", len(tc.oid), len(tc.expected))
				return
			}
			for i := range tc.oid {
				if tc.oid[i] != tc.expected[i] {
					t.Errorf("OID[%d] = %d, want %d", i, tc.oid[i], tc.expected[i])
				}
			}
		})
	}
}

func TestBuildECCCMSSharedInfo(t *testing.T) {
	algo := KeyEncryptionAlgorithm{
		Algorithm: OIDAESWrap128,
	}
	ukm := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	info := buildECCCMSSharedInfo(algo, ukm, 16)

	if len(info) == 0 {
		t.Error("SharedInfo should not be empty")
	}

	// Without UKM
	infoNoUKM := buildECCCMSSharedInfo(algo, nil, 16)
	if len(infoNoUKM) == 0 {
		t.Error("SharedInfo without UKM should not be empty")
	}
}

func TestPubKeySecurityHandlerVersions(t *testing.T) {
	versions := []struct {
		version   SecurityHandlerVersion
		keyLength int
	}{
		{SecurityHandlerVersionRC440, 5},
		{SecurityHandlerVersionRC4Longer, 16},
		{SecurityHandlerVersionRC4OrAES128, 16},
		{SecurityHandlerVersionAES256, 32},
		{SecurityHandlerVersionAESGCM, 32},
	}

	for _, tc := range versions {
		t.Run("Version"+string(rune('0'+tc.version)), func(t *testing.T) {
			cert, _ := generateTestCertificate(t)

			handler, err := BuildFromCerts(
				[]*x509.Certificate{cert},
				tc.version,
				PubKeyPermissions(0).AllowEverything(),
				RecipientEncryptionPolicy{IgnoreKeyUsage: true},
				true,
			)

			if err != nil {
				t.Fatalf("BuildFromCerts failed: %v", err)
			}

			if handler.KeyLength != tc.keyLength {
				t.Errorf("KeyLength = %d, want %d", handler.KeyLength, tc.keyLength)
			}
		})
	}
}
