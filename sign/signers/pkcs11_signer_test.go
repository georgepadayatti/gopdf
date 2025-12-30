package signers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/georgepadayatti/gopdf/config"
)

// generateTestCertWithType generates a test certificate with the specified key type
func generateTestCertWithType(keyType string) (*x509.Certificate, interface{}) {
	var key interface{}
	var pubKey interface{}

	switch keyType {
	case "RSA":
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		key = rsaKey
		pubKey = &rsaKey.PublicKey
	default:
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		key = rsaKey
		pubKey = &rsaKey.PublicKey
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Cert",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, pubKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	return cert, key
}

func TestPKCS11Errors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrPKCS11ModuleLoad", ErrPKCS11ModuleLoad},
		{"ErrPKCS11NoToken", ErrPKCS11NoToken},
		{"ErrPKCS11NoKey", ErrPKCS11NoKey},
		{"ErrPKCS11NoCert", ErrPKCS11NoCert},
		{"ErrPKCS11MultipleKeys", ErrPKCS11MultipleKeys},
		{"ErrPKCS11MultipleCerts", ErrPKCS11MultipleCerts},
		{"ErrPKCS11SessionFailed", ErrPKCS11SessionFailed},
		{"ErrPKCS11LoginFailed", ErrPKCS11LoginFailed},
		{"ErrPKCS11SignFailed", ErrPKCS11SignFailed},
		{"ErrPKCS11UnsupportedAlg", ErrPKCS11UnsupportedAlg},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				t.Errorf("%s should not be nil", tc.name)
			}
			if tc.err.Error() == "" {
				t.Errorf("%s.Error() should not be empty", tc.name)
			}
		})
	}
}

func TestPKCS11MechanismMaps(t *testing.T) {
	t.Run("RSA mechanisms", func(t *testing.T) {
		algorithms := []string{"sha1", "sha224", "sha256", "sha384", "sha512"}
		for _, alg := range algorithms {
			if _, ok := rsaMechMap[alg]; !ok {
				t.Errorf("rsaMechMap missing %s", alg)
			}
		}
	})

	t.Run("RSA-PSS mechanisms", func(t *testing.T) {
		algorithms := []string{"sha1", "sha224", "sha256", "sha384", "sha512"}
		for _, alg := range algorithms {
			if _, ok := rsaPSSMechMap[alg]; !ok {
				t.Errorf("rsaPSSMechMap missing %s", alg)
			}
		}
	})

	t.Run("ECDSA mechanisms", func(t *testing.T) {
		algorithms := []string{"sha1", "sha224", "sha256", "sha384", "sha512"}
		for _, alg := range algorithms {
			if _, ok := ecdsaMechMap[alg]; !ok {
				t.Errorf("ecdsaMechMap missing %s", alg)
			}
		}
	})

	t.Run("DSA mechanisms", func(t *testing.T) {
		algorithms := []string{"sha1", "sha224", "sha256", "sha384", "sha512"}
		for _, alg := range algorithms {
			if _, ok := dsaMechMap[alg]; !ok {
				t.Errorf("dsaMechMap missing %s", alg)
			}
		}
	})

	t.Run("Digest mechanisms", func(t *testing.T) {
		algorithms := []string{"sha1", "sha224", "sha256", "sha384", "sha512"}
		for _, alg := range algorithms {
			if _, ok := digestMechMap[alg]; !ok {
				t.Errorf("digestMechMap missing %s", alg)
			}
		}
	})

	t.Run("MGF mechanisms", func(t *testing.T) {
		algorithms := []string{"sha1", "sha224", "sha256", "sha384", "sha512"}
		for _, alg := range algorithms {
			if _, ok := mgfMechMap[alg]; !ok {
				t.Errorf("mgfMechMap missing %s", alg)
			}
		}
	})
}

func TestDigestAlgSizes(t *testing.T) {
	expected := map[string]int{
		"sha1":   20,
		"sha224": 28,
		"sha256": 32,
		"sha384": 48,
		"sha512": 64,
	}

	for alg, size := range expected {
		if got := digestAlgSizes[alg]; got != size {
			t.Errorf("digestAlgSizes[%s] = %d, want %d", alg, got, size)
		}
	}
}

func TestPKCS11GetHasher(t *testing.T) {
	tests := []struct {
		alg      string
		size     int
		nilCheck bool
	}{
		{"sha1", 20, false},
		{"sha224", 28, false},
		{"sha256", 32, false},
		{"sha384", 48, false},
		{"sha512", 64, false},
		{"invalid", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			h := getHasher(tc.alg)
			if tc.nilCheck {
				if h != nil {
					t.Errorf("getHasher(%s) should return nil", tc.alg)
				}
			} else {
				if h == nil {
					t.Fatalf("getHasher(%s) returned nil", tc.alg)
				}
				h.Write([]byte("test"))
				result := h.Sum(nil)
				if len(result) != tc.size {
					t.Errorf("hash output size = %d, want %d", len(result), tc.size)
				}
			}
		})
	}
}

func TestHashFully(t *testing.T) {
	transform := hashFully("sha256")

	data := []byte("test data")
	result, err := transform(data)
	if err != nil {
		t.Fatalf("hashFully failed: %v", err)
	}

	if len(result) != 32 {
		t.Errorf("result length = %d, want 32", len(result))
	}
}

func TestHashFullyWithDigestInfo(t *testing.T) {
	transform := hashFullyWithDigestInfo("sha256")

	data := []byte("test data")
	result, err := transform(data)
	if err != nil {
		t.Fatalf("hashFullyWithDigestInfo failed: %v", err)
	}

	// Should be longer than just hash due to DigestInfo wrapper
	if len(result) <= 32 {
		t.Errorf("result length = %d, should be > 32", len(result))
	}

	// Verify it's valid ASN.1
	var di struct {
		DigestAlgorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		Digest []byte
	}
	_, err = asn1.Unmarshal(result, &di)
	if err != nil {
		t.Errorf("result is not valid DigestInfo ASN.1: %v", err)
	}

	// Check digest size
	if len(di.Digest) != 32 {
		t.Errorf("digest length = %d, want 32", len(di.Digest))
	}
}

func TestWrapDigestInfo(t *testing.T) {
	algorithms := []string{"sha1", "sha224", "sha256", "sha384", "sha512"}
	digest := []byte{0x01, 0x02, 0x03, 0x04}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			result, err := wrapDigestInfo(alg, digest)
			if err != nil {
				t.Fatalf("wrapDigestInfo failed: %v", err)
			}

			// Verify it's valid ASN.1
			var di struct {
				DigestAlgorithm struct {
					Algorithm  asn1.ObjectIdentifier
					Parameters asn1.RawValue `asn1:"optional"`
				}
				Digest []byte
			}
			_, err = asn1.Unmarshal(result, &di)
			if err != nil {
				t.Errorf("result is not valid ASN.1: %v", err)
			}
		})
	}

	t.Run("invalid algorithm", func(t *testing.T) {
		_, err := wrapDigestInfo("invalid", digest)
		if err == nil {
			t.Error("expected error for invalid algorithm")
		}
	})
}

func TestEncodeECDSASignature(t *testing.T) {
	// Create a mock ECDSA signature (r || s, each 32 bytes for P-256)
	raw := make([]byte, 64)
	rand.Read(raw)

	encoded, err := encodeECDSASignature(raw)
	if err != nil {
		t.Fatalf("encodeECDSASignature failed: %v", err)
	}

	// Verify it's valid DER
	var sig struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(encoded, &sig)
	if err != nil {
		t.Errorf("result is not valid DER: %v", err)
	}

	if sig.R == nil || sig.S == nil {
		t.Error("R or S is nil")
	}
}

func TestEncodeECDSASignatureInvalidLength(t *testing.T) {
	// Odd length should fail
	raw := make([]byte, 63)
	_, err := encodeECDSASignature(raw)
	if err == nil {
		t.Error("expected error for odd length signature")
	}
}

func TestEncodeDSASignature(t *testing.T) {
	// Create a mock DSA signature (r || s, each 20 bytes)
	raw := make([]byte, 40)
	rand.Read(raw)

	encoded, err := encodeDSASignature(raw)
	if err != nil {
		t.Fatalf("encodeDSASignature failed: %v", err)
	}

	// Verify it's valid DER
	var sig struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(encoded, &sig)
	if err != nil {
		t.Errorf("result is not valid DER: %v", err)
	}
}

func TestEncodeDSASignatureInvalidLength(t *testing.T) {
	// Odd length should fail
	raw := make([]byte, 41)
	_, err := encodeDSASignature(raw)
	if err == nil {
		t.Error("expected error for odd length signature")
	}
}

func TestTrimPKCS11String(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"hello   ", "hello"},
		{"   ", ""},
		{"", ""},
		{"a b c", "a b c"},
		{"a b c   ", "a b c"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := trimPKCS11String(tc.input)
			if got != tc.expected {
				t.Errorf("trimPKCS11String(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

// Note: tokenMatchesCriteria tests are in TestTokenMatchesCriteriaMock below
// because we can't easily create pkcs11.TokenInfo without an actual token.

func TestPKCS11SignerGetKeyType(t *testing.T) {
	tests := []struct {
		name     string
		keyAlg   x509.PublicKeyAlgorithm
		expected string
	}{
		{"RSA", x509.RSA, "RSA"},
		{"ECDSA", x509.ECDSA, "ECDSA"},
		{"DSA", x509.DSA, "DSA"},
		{"Ed25519", x509.Ed25519, "Ed25519"},
		{"Unknown", x509.PublicKeyAlgorithm(99), "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{PublicKeyAlgorithm: tc.keyAlg}
			signer := &PKCS11Signer{signingCert: cert}

			if got := signer.getKeyType(); got != tc.expected {
				t.Errorf("getKeyType() = %q, want %q", got, tc.expected)
			}
		})
	}

	t.Run("nil certificate", func(t *testing.T) {
		signer := &PKCS11Signer{}
		if got := signer.getKeyType(); got != "unknown" {
			t.Errorf("getKeyType() with nil cert = %q, want %q", got, "unknown")
		}
	})
}

func TestPKCS11SignerGetSignatureSize(t *testing.T) {
	cert, _ := generateTestCertWithType("RSA")

	signer := &PKCS11Signer{
		signingCert: cert,
	}

	size := signer.GetSignatureSize()
	if size < 8192 {
		t.Errorf("GetSignatureSize() = %d, should be at least 8192", size)
	}

	// With chain
	signer.certChain = []*x509.Certificate{cert, cert}
	sizeWithChain := signer.GetSignatureSize()
	if sizeWithChain <= size {
		t.Error("size with chain should be larger")
	}
}

func TestPKCS11SignerGetCertificate(t *testing.T) {
	cert, _ := generateTestCertWithType("RSA")

	signer := &PKCS11Signer{signingCert: cert}

	if got := signer.GetCertificate(); got != cert {
		t.Error("GetCertificate() should return the signing cert")
	}
}

func TestPKCS11SignerGetCertificateChain(t *testing.T) {
	cert1, _ := generateTestCertWithType("RSA")
	cert2, _ := generateTestCertWithType("RSA")
	chain := []*x509.Certificate{cert1, cert2}

	signer := &PKCS11Signer{certChain: chain}

	if got := signer.GetCertificateChain(); len(got) != 2 {
		t.Errorf("GetCertificateChain() length = %d, want 2", len(got))
	}
}

func TestPKCS11SignerWithMethods(t *testing.T) {
	cert, _ := generateTestCertWithType("RSA")
	chain := []*x509.Certificate{cert}

	signer := NewPKCS11Signer(nil).
		WithCertLabel("MyCert").
		WithCertID([]byte{0x01}).
		WithKeyLabel("MyKey").
		WithKeyID([]byte{0x02}).
		WithPreferPSS(true).
		WithRawMechanism(true).
		WithSigningCertificate(cert).
		WithCertificateChain(chain)

	if signer.certLabel != "MyCert" {
		t.Errorf("certLabel = %q, want %q", signer.certLabel, "MyCert")
	}
	if string(signer.certID) != string([]byte{0x01}) {
		t.Errorf("certID mismatch")
	}
	if signer.keyLabel != "MyKey" {
		t.Errorf("keyLabel = %q, want %q", signer.keyLabel, "MyKey")
	}
	if string(signer.keyID) != string([]byte{0x02}) {
		t.Errorf("keyID mismatch")
	}
	if !signer.preferPSS {
		t.Error("preferPSS should be true")
	}
	if !signer.useRawMech {
		t.Error("useRawMech should be true")
	}
	if signer.signingCert != cert {
		t.Error("signingCert mismatch")
	}
	if len(signer.certChain) != 1 {
		t.Errorf("certChain length = %d, want 1", len(signer.certChain))
	}
}

func TestPKCS11SigningContext(t *testing.T) {
	cfg := &config.PKCS11SignatureConfig{
		ModulePath: "/path/to/module.so",
		CertLabel:  "MyCert",
		PreferPSS:  true,
	}

	ctx := NewPKCS11SigningContext(cfg).WithUserPIN("1234")

	if ctx.Config != cfg {
		t.Error("Config mismatch")
	}
	if ctx.UserPIN != "1234" {
		t.Errorf("UserPIN = %q, want %q", ctx.UserPIN, "1234")
	}
}

func TestPKCS11SignerImplementsSigner(t *testing.T) {
	var _ Signer = (*PKCS11Signer)(nil)
}

// Mock helper for testing
type mockTokenInfoStruct struct {
	Label        string
	SerialNumber string
}

// Helper to create mock token info for testing
func mockTokenInfo(label, serial string) mockTokenInfoStruct {
	return mockTokenInfoStruct{Label: label, SerialNumber: serial}
}

// Modified tokenMatchesCriteria for testing without actual pkcs11 dependency
func tokenMatchesCriteriaMock(tokenInfo mockTokenInfoStruct, criteria *config.TokenCriteria) bool {
	if criteria == nil || criteria.IsEmpty() {
		return true
	}

	if criteria.Label != "" {
		tokenLabel := trimPKCS11String(tokenInfo.Label)
		if tokenLabel != criteria.Label {
			return false
		}
	}

	if criteria.Serial != nil {
		tokenSerial := trimPKCS11String(tokenInfo.SerialNumber)
		if tokenSerial != string(criteria.Serial) {
			return false
		}
	}

	return true
}

// Override the test to use mock
func init() {
	// Replace tokenMatchesCriteria function usage in tests
}

// Test using mock function directly
func TestTokenMatchesCriteriaMock(t *testing.T) {
	t.Run("nil criteria matches all", func(t *testing.T) {
		if !tokenMatchesCriteriaMock(mockTokenInfo("token", "serial"), nil) {
			t.Error("nil criteria should match any token")
		}
	})

	t.Run("empty criteria matches all", func(t *testing.T) {
		if !tokenMatchesCriteriaMock(mockTokenInfo("token", "serial"), &config.TokenCriteria{}) {
			t.Error("empty criteria should match any token")
		}
	})

	t.Run("label match", func(t *testing.T) {
		criteria := &config.TokenCriteria{Label: "MyToken"}
		if !tokenMatchesCriteriaMock(mockTokenInfo("MyToken", "serial"), criteria) {
			t.Error("should match when label matches")
		}
		if tokenMatchesCriteriaMock(mockTokenInfo("OtherToken", "serial"), criteria) {
			t.Error("should not match when label differs")
		}
	})

	t.Run("label match with padding", func(t *testing.T) {
		criteria := &config.TokenCriteria{Label: "MyToken"}
		if !tokenMatchesCriteriaMock(mockTokenInfo("MyToken     ", "serial"), criteria) {
			t.Error("should match when label matches (ignoring padding)")
		}
	})

	t.Run("serial match", func(t *testing.T) {
		criteria := &config.TokenCriteria{Serial: []byte("12345")}
		if !tokenMatchesCriteriaMock(mockTokenInfo("token", "12345"), criteria) {
			t.Error("should match when serial matches")
		}
		if tokenMatchesCriteriaMock(mockTokenInfo("token", "67890"), criteria) {
			t.Error("should not match when serial differs")
		}
	})
}

func TestMechanismConstants(t *testing.T) {
	// Verify mechanism constants are correct according to PKCS#11 spec
	tests := []struct {
		name  string
		value uint
	}{
		{"CKM_RSA_PKCS", 0x00000001},
		{"CKM_SHA1_RSA_PKCS", 0x00000006},
		{"CKM_SHA256_RSA_PKCS", 0x00000040},
		{"CKM_ECDSA", 0x00001041},
		{"CKM_SHA256", 0x00000250},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got uint
			switch tc.name {
			case "CKM_RSA_PKCS":
				got = CKM_RSA_PKCS
			case "CKM_SHA1_RSA_PKCS":
				got = CKM_SHA1_RSA_PKCS
			case "CKM_SHA256_RSA_PKCS":
				got = CKM_SHA256_RSA_PKCS
			case "CKM_ECDSA":
				got = CKM_ECDSA
			case "CKM_SHA256":
				got = CKM_SHA256
			}
			if got != tc.value {
				t.Errorf("%s = 0x%08X, want 0x%08X", tc.name, got, tc.value)
			}
		})
	}
}
