package validation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// createTestCertWithKeyUsage creates a test certificate with specified key usage.
func createTestCertWithKeyUsage(t *testing.T, ku x509.KeyUsage, eku []x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func TestKeyUsageConstants(t *testing.T) {
	tests := []struct {
		ku       KeyUsage
		expected string
	}{
		{KeyUsageDigitalSignature, "digital_signature"},
		{KeyUsageContentCommitment, "content_commitment"},
		{KeyUsageKeyEncipherment, "key_encipherment"},
		{KeyUsageDataEncipherment, "data_encipherment"},
		{KeyUsageKeyAgreement, "key_agreement"},
		{KeyUsageKeyCertSign, "key_cert_sign"},
		{KeyUsageCRLSign, "crl_sign"},
		{KeyUsageEncipherOnly, "encipher_only"},
		{KeyUsageDecipherOnly, "decipher_only"},
	}

	for _, tt := range tests {
		if string(tt.ku) != tt.expected {
			t.Errorf("KeyUsage %v = %s, want %s", tt.ku, string(tt.ku), tt.expected)
		}
	}
}

func TestExtKeyUsageConstants(t *testing.T) {
	tests := []struct {
		eku      ExtKeyUsage
		expected string
	}{
		{ExtKeyUsageAny, "any_extended_key_usage"},
		{ExtKeyUsageServerAuth, "server_auth"},
		{ExtKeyUsageClientAuth, "client_auth"},
		{ExtKeyUsageCodeSigning, "code_signing"},
		{ExtKeyUsageEmailProtection, "email_protection"},
		{ExtKeyUsageTimeStamping, "time_stamping"},
		{ExtKeyUsageOCSPSigning, "ocsp_signing"},
	}

	for _, tt := range tests {
		if string(tt.eku) != tt.expected {
			t.Errorf("ExtKeyUsage %v = %s, want %s", tt.eku, string(tt.eku), tt.expected)
		}
	}
}

func TestNewKeyUsageConstraints(t *testing.T) {
	c := NewKeyUsageConstraints()
	if c == nil {
		t.Fatal("NewKeyUsageConstraints returned nil")
	}
	if !c.ExplicitExtdKeyUsageRequired {
		t.Error("Expected ExplicitExtdKeyUsageRequired = true by default")
	}
	if c.MatchAllKeyUsages {
		t.Error("Expected MatchAllKeyUsages = false by default")
	}
}

func TestSigningConstraints(t *testing.T) {
	c := SigningConstraints()
	if c == nil {
		t.Fatal("SigningConstraints returned nil")
	}
	if len(c.KeyUsage) != 2 {
		t.Errorf("Expected 2 key usages, got %d", len(c.KeyUsage))
	}
	if c.MatchAllKeyUsages {
		t.Error("Expected MatchAllKeyUsages = false")
	}
}

func TestKeyUsageConstraintsValidate(t *testing.T) {
	t.Run("NoConstraints", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, nil)
		c := NewKeyUsageConstraints()

		err := c.Validate(cert)
		if err != nil {
			t.Errorf("Expected no error with no constraints, got: %v", err)
		}
	})

	t.Run("MatchingKeyUsage", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, nil)
		c := &KeyUsageConstraints{
			KeyUsage: []KeyUsage{KeyUsageDigitalSignature},
		}

		err := c.Validate(cert)
		if err != nil {
			t.Errorf("Expected no error with matching key usage, got: %v", err)
		}
	})

	t.Run("NonMatchingKeyUsage", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageKeyEncipherment, nil)
		c := &KeyUsageConstraints{
			KeyUsage: []KeyUsage{KeyUsageDigitalSignature},
		}

		err := c.Validate(cert)
		if err == nil {
			t.Error("Expected error with non-matching key usage")
		}
		if !IsKeyUsageValidationError(err) {
			t.Errorf("Expected KeyUsageValidationError, got: %T", err)
		}
	})

	t.Run("ForbiddenKeyUsage", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, nil)
		c := &KeyUsageConstraints{
			KeyUsage:          []KeyUsage{KeyUsageDigitalSignature},
			KeyUsageForbidden: []KeyUsage{KeyUsageKeyEncipherment},
		}

		err := c.Validate(cert)
		if err == nil {
			t.Error("Expected error with forbidden key usage")
		}
	})

	t.Run("MatchAllKeyUsages", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, nil)
		c := &KeyUsageConstraints{
			KeyUsage:          []KeyUsage{KeyUsageDigitalSignature, KeyUsageContentCommitment},
			MatchAllKeyUsages: true,
		}

		err := c.Validate(cert)
		if err == nil {
			t.Error("Expected error when not all key usages match with MatchAllKeyUsages=true")
		}
	})

	t.Run("MatchAnyKeyUsage", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, nil)
		c := &KeyUsageConstraints{
			KeyUsage:          []KeyUsage{KeyUsageDigitalSignature, KeyUsageContentCommitment},
			MatchAllKeyUsages: false,
		}

		err := c.Validate(cert)
		if err != nil {
			t.Errorf("Expected no error when any key usage matches, got: %v", err)
		}
	})
}

func TestExtKeyUsageConstraintsValidate(t *testing.T) {
	t.Run("NoExtKeyUsageConstraints", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, 0, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})
		c := &KeyUsageConstraints{
			ExtdKeyUsage: nil, // nil means accept all
		}

		err := c.Validate(cert)
		if err != nil {
			t.Errorf("Expected no error with nil ExtdKeyUsage, got: %v", err)
		}
	})

	t.Run("MatchingExtKeyUsage", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, 0, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})
		c := &KeyUsageConstraints{
			ExtdKeyUsage:                 []ExtKeyUsage{ExtKeyUsageCodeSigning},
			ExplicitExtdKeyUsageRequired: true,
		}

		err := c.Validate(cert)
		if err != nil {
			t.Errorf("Expected no error with matching ext key usage, got: %v", err)
		}
	})

	t.Run("NonMatchingExtKeyUsage", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, 0, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		c := &KeyUsageConstraints{
			ExtdKeyUsage:                 []ExtKeyUsage{ExtKeyUsageCodeSigning},
			ExplicitExtdKeyUsageRequired: true,
		}

		err := c.Validate(cert)
		if err == nil {
			t.Error("Expected error with non-matching ext key usage")
		}
	})

	t.Run("NoExtKeyUsageExtensionRequired", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, 0, nil) // No EKU extension
		c := &KeyUsageConstraints{
			ExtdKeyUsage:                 []ExtKeyUsage{ExtKeyUsageCodeSigning},
			ExplicitExtdKeyUsageRequired: true,
		}

		err := c.Validate(cert)
		if err == nil {
			t.Error("Expected error when EKU required but not present")
		}
	})

	t.Run("NoExtKeyUsageExtensionOptional", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, 0, nil) // No EKU extension
		c := &KeyUsageConstraints{
			ExtdKeyUsage:                 []ExtKeyUsage{ExtKeyUsageCodeSigning},
			ExplicitExtdKeyUsageRequired: false,
		}

		err := c.Validate(cert)
		if err != nil {
			t.Errorf("Expected no error when EKU optional and not present, got: %v", err)
		}
	})

	t.Run("AnyExtKeyUsageAllowed", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, 0, []x509.ExtKeyUsage{x509.ExtKeyUsageAny})
		c := &KeyUsageConstraints{
			ExtdKeyUsage:                 []ExtKeyUsage{ExtKeyUsageCodeSigning},
			ExplicitExtdKeyUsageRequired: false,
		}

		err := c.Validate(cert)
		if err != nil {
			t.Errorf("Expected no error with anyExtendedKeyUsage, got: %v", err)
		}
	})

	t.Run("AnyExtKeyUsageNotAllowedWhenExplicitRequired", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, 0, []x509.ExtKeyUsage{x509.ExtKeyUsageAny})
		c := &KeyUsageConstraints{
			ExtdKeyUsage:                 []ExtKeyUsage{ExtKeyUsageCodeSigning},
			ExplicitExtdKeyUsageRequired: true,
		}

		err := c.Validate(cert)
		if err == nil {
			t.Error("Expected error when explicit EKU required but only anyExtendedKeyUsage present")
		}
	})
}

func TestValidateWithExtra(t *testing.T) {
	t.Run("ExtraKeyUsage", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, 0, nil) // No key usage in cert
		c := &KeyUsageConstraints{
			KeyUsage: []KeyUsage{KeyUsageDigitalSignature},
		}

		// Without extra - should fail
		err := c.Validate(cert)
		if err == nil {
			t.Error("Expected error without extra key usage")
		}

		// With extra - should pass
		err = c.ValidateWithExtra(cert, []KeyUsage{KeyUsageDigitalSignature}, nil)
		if err != nil {
			t.Errorf("Expected no error with extra key usage, got: %v", err)
		}
	})

	t.Run("ExtraExtKeyUsage", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, 0, nil) // No EKU in cert
		c := &KeyUsageConstraints{
			ExtdKeyUsage:                 []ExtKeyUsage{ExtKeyUsageCodeSigning},
			ExplicitExtdKeyUsageRequired: true,
		}

		// With extra - should pass
		err := c.ValidateWithExtra(cert, nil, []ExtKeyUsage{ExtKeyUsageCodeSigning})
		if err != nil {
			t.Errorf("Expected no error with extra ext key usage, got: %v", err)
		}
	})
}

func TestParseKeyUsage(t *testing.T) {
	tests := []struct {
		input    string
		expected KeyUsage
		hasError bool
	}{
		{"digital_signature", KeyUsageDigitalSignature, false},
		{"digital-signature", KeyUsageDigitalSignature, false},
		{"DIGITAL_SIGNATURE", KeyUsageDigitalSignature, false},
		{"content_commitment", KeyUsageContentCommitment, false},
		{"non_repudiation", KeyUsageContentCommitment, false},
		{"key_encipherment", KeyUsageKeyEncipherment, false},
		{"data_encipherment", KeyUsageDataEncipherment, false},
		{"key_agreement", KeyUsageKeyAgreement, false},
		{"key_cert_sign", KeyUsageKeyCertSign, false},
		{"crl_sign", KeyUsageCRLSign, false},
		{"encipher_only", KeyUsageEncipherOnly, false},
		{"decipher_only", KeyUsageDecipherOnly, false},
		{"unknown", "", true},
	}

	for _, tt := range tests {
		ku, err := ParseKeyUsage(tt.input)
		if tt.hasError {
			if err == nil {
				t.Errorf("ParseKeyUsage(%s) expected error", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParseKeyUsage(%s) error: %v", tt.input, err)
			}
			if ku != tt.expected {
				t.Errorf("ParseKeyUsage(%s) = %s, want %s", tt.input, ku, tt.expected)
			}
		}
	}
}

func TestParseExtKeyUsage(t *testing.T) {
	tests := []struct {
		input    string
		expected ExtKeyUsage
		hasError bool
	}{
		{"any", ExtKeyUsageAny, false},
		{"any_extended_key_usage", ExtKeyUsageAny, false},
		{"server_auth", ExtKeyUsageServerAuth, false},
		{"server-auth", ExtKeyUsageServerAuth, false},
		{"SERVER_AUTH", ExtKeyUsageServerAuth, false},
		{"client_auth", ExtKeyUsageClientAuth, false},
		{"code_signing", ExtKeyUsageCodeSigning, false},
		{"email_protection", ExtKeyUsageEmailProtection, false},
		{"time_stamping", ExtKeyUsageTimeStamping, false},
		{"ocsp_signing", ExtKeyUsageOCSPSigning, false},
		{"unknown", "", true},
	}

	for _, tt := range tests {
		eku, err := ParseExtKeyUsage(tt.input)
		if tt.hasError {
			if err == nil {
				t.Errorf("ParseExtKeyUsage(%s) expected error", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParseExtKeyUsage(%s) error: %v", tt.input, err)
			}
			if eku != tt.expected {
				t.Errorf("ParseExtKeyUsage(%s) = %s, want %s", tt.input, eku, tt.expected)
			}
		}
	}
}

func TestExtractKeyUsages(t *testing.T) {
	tests := []struct {
		ku       x509.KeyUsage
		expected int
	}{
		{0, 0},
		{x509.KeyUsageDigitalSignature, 1},
		{x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment, 2},
		{x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, 3},
	}

	for _, tt := range tests {
		usages := extractKeyUsages(tt.ku)
		if len(usages) != tt.expected {
			t.Errorf("extractKeyUsages(%d) returned %d usages, want %d", tt.ku, len(usages), tt.expected)
		}
	}
}

func TestExtractExtKeyUsages(t *testing.T) {
	tests := []struct {
		ekus     []x509.ExtKeyUsage
		expected int
	}{
		{nil, 0},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, 1},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection}, 2},
	}

	for _, tt := range tests {
		usages := extractExtKeyUsages(tt.ekus, nil)
		if len(usages) != tt.expected {
			t.Errorf("extractExtKeyUsages returned %d usages, want %d", len(usages), tt.expected)
		}
	}
}

func TestKeyUsageToX509(t *testing.T) {
	tests := []struct {
		usages   []KeyUsage
		expected x509.KeyUsage
	}{
		{nil, 0},
		{[]KeyUsage{KeyUsageDigitalSignature}, x509.KeyUsageDigitalSignature},
		{[]KeyUsage{KeyUsageDigitalSignature, KeyUsageContentCommitment},
			x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment},
	}

	for _, tt := range tests {
		ku := KeyUsageToX509(tt.usages)
		if ku != tt.expected {
			t.Errorf("KeyUsageToX509 = %d, want %d", ku, tt.expected)
		}
	}
}

func TestExtKeyUsageToX509(t *testing.T) {
	tests := []struct {
		usages   []ExtKeyUsage
		expected []x509.ExtKeyUsage
	}{
		{nil, nil},
		{[]ExtKeyUsage{ExtKeyUsageCodeSigning}, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}},
	}

	for _, tt := range tests {
		ekus := ExtKeyUsageToX509(tt.usages)
		if len(ekus) != len(tt.expected) {
			t.Errorf("ExtKeyUsageToX509 returned %d, want %d", len(ekus), len(tt.expected))
		}
	}
}

func TestValidateCertificateKeyUsage(t *testing.T) {
	cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, nil)

	err := ValidateCertificateKeyUsage(cert, []KeyUsage{KeyUsageDigitalSignature})
	if err != nil {
		t.Errorf("ValidateCertificateKeyUsage failed: %v", err)
	}

	err = ValidateCertificateKeyUsage(cert, []KeyUsage{KeyUsageKeyEncipherment})
	if err == nil {
		t.Error("Expected error for non-matching key usage")
	}
}

func TestValidateCertificateExtKeyUsage(t *testing.T) {
	cert := createTestCertWithKeyUsage(t, 0, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

	err := ValidateCertificateExtKeyUsage(cert, []ExtKeyUsage{ExtKeyUsageCodeSigning})
	if err != nil {
		t.Errorf("ValidateCertificateExtKeyUsage failed: %v", err)
	}

	err = ValidateCertificateExtKeyUsage(cert, []ExtKeyUsage{ExtKeyUsageServerAuth})
	if err == nil {
		t.Error("Expected error for non-matching ext key usage")
	}
}

func TestKeyUsageConstraintsBuilder(t *testing.T) {
	t.Run("BasicBuilder", func(t *testing.T) {
		c := NewKeyUsageConstraintsBuilder().
			RequireKeyUsage(KeyUsageDigitalSignature).
			RequireKeyUsage(KeyUsageContentCommitment).
			MatchAll(false).
			Build()

		if len(c.KeyUsage) != 2 {
			t.Errorf("Expected 2 key usages, got %d", len(c.KeyUsage))
		}
		if c.MatchAllKeyUsages {
			t.Error("Expected MatchAllKeyUsages = false")
		}
	})

	t.Run("BuilderWithForbidden", func(t *testing.T) {
		c := NewKeyUsageConstraintsBuilder().
			RequireKeyUsage(KeyUsageDigitalSignature).
			ForbidKeyUsage(KeyUsageKeyEncipherment).
			Build()

		if len(c.KeyUsageForbidden) != 1 {
			t.Errorf("Expected 1 forbidden key usage, got %d", len(c.KeyUsageForbidden))
		}
	})

	t.Run("BuilderWithExtKeyUsage", func(t *testing.T) {
		c := NewKeyUsageConstraintsBuilder().
			RequireExtKeyUsage(ExtKeyUsageCodeSigning).
			ExplicitExtKeyUsageRequired(true).
			Build()

		if len(c.ExtdKeyUsage) != 1 {
			t.Errorf("Expected 1 ext key usage, got %d", len(c.ExtdKeyUsage))
		}
		if !c.ExplicitExtdKeyUsageRequired {
			t.Error("Expected ExplicitExtdKeyUsageRequired = true")
		}
	})
}

func TestFormatKeyUsage(t *testing.T) {
	tests := []struct {
		ku       KeyUsage
		expected string
	}{
		{KeyUsageDigitalSignature, "digital signature"},
		{KeyUsageContentCommitment, "content commitment"},
		{KeyUsageKeyEncipherment, "key encipherment"},
	}

	for _, tt := range tests {
		formatted := formatKeyUsage(tt.ku)
		if formatted != tt.expected {
			t.Errorf("formatKeyUsage(%s) = %s, want %s", tt.ku, formatted, tt.expected)
		}
	}
}

func TestFormatExtKeyUsage(t *testing.T) {
	tests := []struct {
		eku      ExtKeyUsage
		expected string
	}{
		{ExtKeyUsageCodeSigning, "code signing"},
		{ExtKeyUsageTimeStamping, "time stamping"},
		{ExtKeyUsageServerAuth, "server auth"},
	}

	for _, tt := range tests {
		formatted := formatExtKeyUsage(tt.eku)
		if formatted != tt.expected {
			t.Errorf("formatExtKeyUsage(%s) = %s, want %s", tt.eku, formatted, tt.expected)
		}
	}
}

func TestMatchUsages(t *testing.T) {
	tests := []struct {
		required map[KeyUsage]bool
		present  map[KeyUsage]bool
		needAll  bool
		expected bool
	}{
		// Empty required - always true
		{map[KeyUsage]bool{}, map[KeyUsage]bool{KeyUsageDigitalSignature: true}, false, false},

		// Match any - one present
		{map[KeyUsage]bool{KeyUsageDigitalSignature: true},
			map[KeyUsage]bool{KeyUsageDigitalSignature: true}, false, true},

		// Match any - none present
		{map[KeyUsage]bool{KeyUsageDigitalSignature: true},
			map[KeyUsage]bool{KeyUsageKeyEncipherment: true}, false, false},

		// Match all - all present
		{map[KeyUsage]bool{KeyUsageDigitalSignature: true, KeyUsageContentCommitment: true},
			map[KeyUsage]bool{KeyUsageDigitalSignature: true, KeyUsageContentCommitment: true}, true, true},

		// Match all - not all present
		{map[KeyUsage]bool{KeyUsageDigitalSignature: true, KeyUsageContentCommitment: true},
			map[KeyUsage]bool{KeyUsageDigitalSignature: true}, true, false},
	}

	for i, tt := range tests {
		result := matchUsages(tt.required, tt.present, tt.needAll)
		if result != tt.expected {
			t.Errorf("Test %d: matchUsages = %v, want %v", i, result, tt.expected)
		}
	}
}

func TestIsKeyUsageValidationError(t *testing.T) {
	kuErr := &KeyUsageValidationError{Message: "test error"}
	if !IsKeyUsageValidationError(kuErr) {
		t.Error("Expected IsKeyUsageValidationError to return true for KeyUsageValidationError")
	}

	otherErr := &ValidationError{Message: "other error"}
	if IsKeyUsageValidationError(otherErr) {
		t.Error("Expected IsKeyUsageValidationError to return false for other error types")
	}
}

// ValidationError is a placeholder for testing
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// createTestCertWithDocumentSigningEKU creates a test certificate with the RFC 9336 Document Signing EKU.
func createTestCertWithDocumentSigningEKU(t *testing.T, ku x509.KeyUsage) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Build EKU extension with Document Signing OID
	ekuOIDs := []asn1.ObjectIdentifier{OIDExtKeyUsageDocumentSigning}
	ekuBytes, err := asn1.Marshal(ekuOIDs)
	if err != nil {
		t.Fatalf("Failed to marshal EKU: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Document Signing Certificate",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              ku,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 37}, // id-ce-extKeyUsage
				Critical: false,
				Value:    ekuBytes,
			},
		},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// RFC 9336 Document Signing EKU Tests

func TestOIDExtKeyUsageDocumentSigning(t *testing.T) {
	expected := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}
	if !OIDExtKeyUsageDocumentSigning.Equal(expected) {
		t.Errorf("OIDExtKeyUsageDocumentSigning = %v, want %v", OIDExtKeyUsageDocumentSigning, expected)
	}
}

func TestExtKeyUsageDocumentSigningConstant(t *testing.T) {
	if string(ExtKeyUsageDocumentSigning) != "document_signing" {
		t.Errorf("ExtKeyUsageDocumentSigning = %s, want document_signing", ExtKeyUsageDocumentSigning)
	}
}

func TestDocumentSigningConstraints(t *testing.T) {
	c := DocumentSigningConstraints()
	if c == nil {
		t.Fatal("DocumentSigningConstraints returned nil")
	}

	// Should require Digital Signature key usage
	if len(c.KeyUsage) != 1 || c.KeyUsage[0] != KeyUsageDigitalSignature {
		t.Error("Expected KeyUsage to contain only DigitalSignature")
	}

	if !c.MatchAllKeyUsages {
		t.Error("Expected MatchAllKeyUsages = true")
	}

	// Should accept Document Signing, Email Protection, and Client Auth
	if len(c.ExtdKeyUsage) != 3 {
		t.Errorf("Expected 3 ExtdKeyUsage entries, got %d", len(c.ExtdKeyUsage))
	}

	hasDocSigning := false
	hasEmail := false
	hasClient := false
	for _, eku := range c.ExtdKeyUsage {
		switch eku {
		case ExtKeyUsageDocumentSigning:
			hasDocSigning = true
		case ExtKeyUsageEmailProtection:
			hasEmail = true
		case ExtKeyUsageClientAuth:
			hasClient = true
		}
	}

	if !hasDocSigning {
		t.Error("Expected DocumentSigningConstraints to include Document Signing EKU")
	}
	if !hasEmail {
		t.Error("Expected DocumentSigningConstraints to include Email Protection EKU")
	}
	if !hasClient {
		t.Error("Expected DocumentSigningConstraints to include Client Auth EKU")
	}

	// Should not require explicit EKU
	if c.ExplicitExtdKeyUsageRequired {
		t.Error("Expected ExplicitExtdKeyUsageRequired = false")
	}
}

func TestStrictDocumentSigningConstraints(t *testing.T) {
	c := StrictDocumentSigningConstraints()
	if c == nil {
		t.Fatal("StrictDocumentSigningConstraints returned nil")
	}

	// Should only accept Document Signing EKU
	if len(c.ExtdKeyUsage) != 1 || c.ExtdKeyUsage[0] != ExtKeyUsageDocumentSigning {
		t.Error("Expected ExtdKeyUsage to contain only DocumentSigning")
	}

	// Should require explicit EKU
	if !c.ExplicitExtdKeyUsageRequired {
		t.Error("Expected ExplicitExtdKeyUsageRequired = true")
	}
}

func TestNonRepudiationDocumentSigningConstraints(t *testing.T) {
	c := NonRepudiationDocumentSigningConstraints()
	if c == nil {
		t.Fatal("NonRepudiationDocumentSigningConstraints returned nil")
	}

	// Should require both Digital Signature and Content Commitment
	if len(c.KeyUsage) != 2 {
		t.Errorf("Expected 2 KeyUsage entries, got %d", len(c.KeyUsage))
	}

	hasDS := false
	hasCC := false
	for _, ku := range c.KeyUsage {
		switch ku {
		case KeyUsageDigitalSignature:
			hasDS = true
		case KeyUsageContentCommitment:
			hasCC = true
		}
	}

	if !hasDS || !hasCC {
		t.Error("Expected both DigitalSignature and ContentCommitment key usages")
	}

	if !c.MatchAllKeyUsages {
		t.Error("Expected MatchAllKeyUsages = true (require both)")
	}
}

func TestHasDocumentSigningEKU(t *testing.T) {
	t.Run("WithDocumentSigningEKU", func(t *testing.T) {
		cert := createTestCertWithDocumentSigningEKU(t, x509.KeyUsageDigitalSignature)
		if !HasDocumentSigningEKU(cert) {
			t.Error("Expected HasDocumentSigningEKU to return true")
		}
	})

	t.Run("WithoutDocumentSigningEKU", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection})
		if HasDocumentSigningEKU(cert) {
			t.Error("Expected HasDocumentSigningEKU to return false")
		}
	})

	t.Run("WithNoEKU", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, nil)
		if HasDocumentSigningEKU(cert) {
			t.Error("Expected HasDocumentSigningEKU to return false for cert without EKU")
		}
	})
}

func TestHasDigitalSignatureKeyUsage(t *testing.T) {
	t.Run("WithDigitalSignature", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, nil)
		if !HasDigitalSignatureKeyUsage(cert) {
			t.Error("Expected HasDigitalSignatureKeyUsage to return true")
		}
	})

	t.Run("WithoutDigitalSignature", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageKeyEncipherment, nil)
		if HasDigitalSignatureKeyUsage(cert) {
			t.Error("Expected HasDigitalSignatureKeyUsage to return false")
		}
	})
}

func TestHasNonRepudiationKeyUsage(t *testing.T) {
	t.Run("WithNonRepudiation", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageContentCommitment, nil)
		if !HasNonRepudiationKeyUsage(cert) {
			t.Error("Expected HasNonRepudiationKeyUsage to return true")
		}
	})

	t.Run("WithoutNonRepudiation", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, nil)
		if HasNonRepudiationKeyUsage(cert) {
			t.Error("Expected HasNonRepudiationKeyUsage to return false")
		}
	})
}

func TestValidateKeyUsageDetailed(t *testing.T) {
	t.Run("ValidDocumentSigningCert", func(t *testing.T) {
		cert := createTestCertWithDocumentSigningEKU(t, x509.KeyUsageDigitalSignature)
		result := ValidateKeyUsageDetailed(cert, DocumentSigningConstraints())

		if !result.KeyUsageValid {
			t.Errorf("Expected KeyUsageValid = true, got error: %s", result.KeyUsageError)
		}
		if !result.ExtKeyUsageValid {
			t.Errorf("Expected ExtKeyUsageValid = true, got error: %s", result.ExtKeyUsageError)
		}
		if !result.HasDocumentSigningEKU {
			t.Error("Expected HasDocumentSigningEKU = true")
		}
		if !result.HasDigitalSignature {
			t.Error("Expected HasDigitalSignature = true")
		}
	})

	t.Run("EmailProtectionFallback", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection})
		result := ValidateKeyUsageDetailed(cert, DocumentSigningConstraints())

		if !result.KeyUsageValid {
			t.Errorf("Expected KeyUsageValid = true")
		}
		if !result.ExtKeyUsageValid {
			t.Errorf("Expected ExtKeyUsageValid = true (email protection is allowed)")
		}
		if result.HasDocumentSigningEKU {
			t.Error("Expected HasDocumentSigningEKU = false")
		}
	})

	t.Run("MissingDigitalSignature", func(t *testing.T) {
		cert := createTestCertWithDocumentSigningEKU(t, x509.KeyUsageKeyEncipherment)
		result := ValidateKeyUsageDetailed(cert, DocumentSigningConstraints())

		if result.KeyUsageValid {
			t.Error("Expected KeyUsageValid = false (missing DigitalSignature)")
		}
		if result.KeyUsageError == "" {
			t.Error("Expected KeyUsageError to be set")
		}
		if !result.HasDocumentSigningEKU {
			t.Error("Expected HasDocumentSigningEKU = true")
		}
	})

	t.Run("InvalidEKUWithStrictConstraints", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		result := ValidateKeyUsageDetailed(cert, StrictDocumentSigningConstraints())

		if !result.KeyUsageValid {
			t.Errorf("Expected KeyUsageValid = true")
		}
		if result.ExtKeyUsageValid {
			t.Error("Expected ExtKeyUsageValid = false (ServerAuth not acceptable)")
		}
		if result.ExtKeyUsageError == "" {
			t.Error("Expected ExtKeyUsageError to be set")
		}
	})

	t.Run("NilConstraints", func(t *testing.T) {
		cert := createTestCertWithDocumentSigningEKU(t, x509.KeyUsageDigitalSignature)
		result := ValidateKeyUsageDetailed(cert, nil)

		// With nil constraints, validation should pass
		if !result.KeyUsageValid {
			t.Error("Expected KeyUsageValid = true with nil constraints")
		}
		if !result.ExtKeyUsageValid {
			t.Error("Expected ExtKeyUsageValid = true with nil constraints")
		}
	})
}

func TestValidateDocumentSigningCertificate(t *testing.T) {
	t.Run("ValidCert", func(t *testing.T) {
		cert := createTestCertWithDocumentSigningEKU(t, x509.KeyUsageDigitalSignature)
		err := ValidateDocumentSigningCertificate(cert)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("ValidWithEmailProtection", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection})
		err := ValidateDocumentSigningCertificate(cert)
		if err != nil {
			t.Errorf("Expected no error with Email Protection fallback, got: %v", err)
		}
	})

	t.Run("InvalidMissingKeyUsage", func(t *testing.T) {
		cert := createTestCertWithDocumentSigningEKU(t, x509.KeyUsageKeyEncipherment)
		err := ValidateDocumentSigningCertificate(cert)
		if err == nil {
			t.Error("Expected error for missing Digital Signature key usage")
		}
	})
}

func TestValidateDocumentSigningCertificateStrict(t *testing.T) {
	t.Run("ValidWithDocumentSigningEKU", func(t *testing.T) {
		cert := createTestCertWithDocumentSigningEKU(t, x509.KeyUsageDigitalSignature)
		err := ValidateDocumentSigningCertificateStrict(cert)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("InvalidWithEmailProtection", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection})
		err := ValidateDocumentSigningCertificateStrict(cert)
		if err == nil {
			t.Error("Expected error - strict mode requires Document Signing EKU")
		}
	})

	t.Run("InvalidWithNoEKU", func(t *testing.T) {
		cert := createTestCertWithKeyUsage(t, x509.KeyUsageDigitalSignature, nil)
		err := ValidateDocumentSigningCertificateStrict(cert)
		if err == nil {
			t.Error("Expected error - strict mode requires EKU extension")
		}
	})
}

func TestParseDocumentSigningExtKeyUsage(t *testing.T) {
	tests := []struct {
		input    string
		expected ExtKeyUsage
		hasError bool
	}{
		{"document_signing", ExtKeyUsageDocumentSigning, false},
		{"documentsigning", ExtKeyUsageDocumentSigning, false},
		{"DOCUMENT_SIGNING", ExtKeyUsageDocumentSigning, false},
		{"document-signing", ExtKeyUsageDocumentSigning, false},
	}

	for _, tt := range tests {
		eku, err := ParseExtKeyUsage(tt.input)
		if tt.hasError {
			if err == nil {
				t.Errorf("ParseExtKeyUsage(%s) expected error", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParseExtKeyUsage(%s) error: %v", tt.input, err)
			}
			if eku != tt.expected {
				t.Errorf("ParseExtKeyUsage(%s) = %s, want %s", tt.input, eku, tt.expected)
			}
		}
	}
}

func TestExtractExtKeyUsagesWithDocumentSigning(t *testing.T) {
	t.Run("WithDocumentSigningOID", func(t *testing.T) {
		unknownEKUs := []asn1.ObjectIdentifier{OIDExtKeyUsageDocumentSigning}
		usages := extractExtKeyUsages(nil, unknownEKUs)

		if len(usages) != 1 {
			t.Fatalf("Expected 1 usage, got %d", len(usages))
		}
		if usages[0] != ExtKeyUsageDocumentSigning {
			t.Errorf("Expected DocumentSigning, got %s", usages[0])
		}
	})

	t.Run("WithMixedEKUs", func(t *testing.T) {
		knownEKUs := []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		unknownEKUs := []asn1.ObjectIdentifier{OIDExtKeyUsageDocumentSigning}
		usages := extractExtKeyUsages(knownEKUs, unknownEKUs)

		if len(usages) != 2 {
			t.Fatalf("Expected 2 usages, got %d", len(usages))
		}

		hasEmail := false
		hasDocSigning := false
		for _, u := range usages {
			switch u {
			case ExtKeyUsageEmailProtection:
				hasEmail = true
			case ExtKeyUsageDocumentSigning:
				hasDocSigning = true
			}
		}

		if !hasEmail {
			t.Error("Expected Email Protection in usages")
		}
		if !hasDocSigning {
			t.Error("Expected Document Signing in usages")
		}
	})
}

func TestDocumentSigningCertificateWithNonRepudiation(t *testing.T) {
	t.Run("ValidWithBothKeyUsages", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)

		ekuOIDs := []asn1.ObjectIdentifier{OIDExtKeyUsageDocumentSigning}
		ekuBytes, _ := asn1.Marshal(ekuOIDs)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Test"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
			ExtraExtensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: ekuBytes},
			},
		}

		derBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(derBytes)

		err := NonRepudiationDocumentSigningConstraints().Validate(cert)
		if err != nil {
			t.Errorf("Expected no error for cert with both key usages, got: %v", err)
		}
	})

	t.Run("InvalidMissingNonRepudiation", func(t *testing.T) {
		cert := createTestCertWithDocumentSigningEKU(t, x509.KeyUsageDigitalSignature)
		err := NonRepudiationDocumentSigningConstraints().Validate(cert)
		if err == nil {
			t.Error("Expected error for cert missing Non-Repudiation")
		}
	})
}
