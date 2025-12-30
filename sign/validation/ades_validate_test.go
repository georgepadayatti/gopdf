package validation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/georgepadayatti/gopdf/certvalidator"
	"github.com/georgepadayatti/gopdf/sign/ades"
)

// Helper to create a test certificate for AdES tests
func createTestCertificateForAdES(t *testing.T) *x509.Certificate {
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
		KeyUsage:              x509.KeyUsageDigitalSignature,
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

// TestValidationObjectType tests the validation object type enum.
func TestValidationObjectType(t *testing.T) {
	tests := []struct {
		objType  ValidationObjectType
		expected string
	}{
		{ValidationObjectCertificate, "certificate"},
		{ValidationObjectCRL, "crl"},
		{ValidationObjectOCSP, "ocsp"},
		{ValidationObjectTimestamp, "timestamp"},
		{ValidationObjectSignedData, "signed_data"},
		{ValidationObjectType(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.objType.String(); got != tt.expected {
			t.Errorf("ValidationObjectType(%d).String() = %s, want %s", tt.objType, got, tt.expected)
		}
	}
}

// TestValidationObjectSet tests the validation object set.
func TestValidationObjectSet(t *testing.T) {
	t.Run("NewValidationObjectSet", func(t *testing.T) {
		set := NewValidationObjectSet()
		if set == nil {
			t.Fatal("NewValidationObjectSet returned nil")
		}
		if set.Count() != 0 {
			t.Errorf("Expected empty set, got count %d", set.Count())
		}
	})

	t.Run("AddAndGet", func(t *testing.T) {
		set := NewValidationObjectSet()
		cert := createTestCertificateForAdES(t)

		obj := &ValidationObject{
			ObjectType: ValidationObjectCertificate,
			Value:      cert,
			Identifier: "test-cert-1",
		}

		set.Add(obj)

		if set.Count() != 1 {
			t.Errorf("Expected count 1, got %d", set.Count())
		}

		retrieved, ok := set.Get("test-cert-1")
		if !ok {
			t.Fatal("Object not found")
		}
		if retrieved != obj {
			t.Error("Retrieved object mismatch")
		}
	})

	t.Run("All", func(t *testing.T) {
		set := NewValidationObjectSet()

		obj1 := &ValidationObject{
			ObjectType: ValidationObjectCertificate,
			Identifier: "cert-1",
		}
		obj2 := &ValidationObject{
			ObjectType: ValidationObjectCRL,
			Identifier: "crl-1",
		}

		set.Add(obj1)
		set.Add(obj2)

		all := set.All()
		if len(all) != 2 {
			t.Errorf("Expected 2 objects, got %d", len(all))
		}
	})

	t.Run("AddWithEmptyIdentifier", func(t *testing.T) {
		set := NewValidationObjectSet()

		obj := &ValidationObject{
			ObjectType: ValidationObjectCertificate,
			Identifier: "", // Empty identifier should be ignored
		}

		set.Add(obj)

		if set.Count() != 0 {
			t.Error("Object with empty identifier should not be added")
		}
	})
}

// TestDeriveValidationObjectIdentifier tests identifier derivation.
func TestDeriveValidationObjectIdentifier(t *testing.T) {
	t.Run("Certificate", func(t *testing.T) {
		cert := createTestCertificateForAdES(t)
		obj := &ValidationObject{
			ObjectType: ValidationObjectCertificate,
			Value:      cert,
		}

		id := DeriveValidationObjectIdentifier(obj)
		if id == "" {
			t.Error("Expected non-empty identifier")
		}
		if len(id) < 20 { // "vo-certificate-" + hex
			t.Errorf("Identifier too short: %s", id)
		}
	})

	t.Run("ByteSlice", func(t *testing.T) {
		obj := &ValidationObject{
			ObjectType: ValidationObjectCRL,
			Value:      []byte("test crl data"),
		}

		id := DeriveValidationObjectIdentifier(obj)
		if id == "" {
			t.Error("Expected non-empty identifier")
		}
	})

	t.Run("UnsupportedType", func(t *testing.T) {
		obj := &ValidationObject{
			ObjectType: ValidationObjectCertificate,
			Value:      "string value", // Unsupported
		}

		id := DeriveValidationObjectIdentifier(obj)
		if id != "" {
			t.Error("Expected empty identifier for unsupported type")
		}
	})
}

// TestAdESBasicValidationResult tests the basic validation result.
func TestAdESBasicValidationResult(t *testing.T) {
	t.Run("NewAdESBasicValidationResult", func(t *testing.T) {
		result := NewAdESBasicValidationResult()
		if result == nil {
			t.Fatal("NewAdESBasicValidationResult returned nil")
		}
		if result.Indication != ades.IndicationIndeterminate {
			t.Errorf("Expected INDETERMINATE, got %s", result.Indication)
		}
		if result.ValidationObjects == nil {
			t.Error("ValidationObjects should not be nil")
		}
	})

	t.Run("IsPassed", func(t *testing.T) {
		result := NewAdESBasicValidationResult()
		result.Indication = ades.IndicationPassed

		if !result.IsPassed() {
			t.Error("Expected IsPassed() = true")
		}
		if result.IsFailed() {
			t.Error("Expected IsFailed() = false")
		}
	})

	t.Run("IsFailed", func(t *testing.T) {
		result := NewAdESBasicValidationResult()
		result.Indication = ades.IndicationFailed

		if result.IsPassed() {
			t.Error("Expected IsPassed() = false")
		}
		if !result.IsFailed() {
			t.Error("Expected IsFailed() = true")
		}
	})
}

// TestAdESWithTimeValidationResult tests the with-time validation result.
func TestAdESWithTimeValidationResult(t *testing.T) {
	result := NewAdESWithTimeValidationResult()
	if result == nil {
		t.Fatal("NewAdESWithTimeValidationResult returned nil")
	}
	if result.AdESBasicValidationResult == nil {
		t.Error("AdESBasicValidationResult should not be nil")
	}
}

// TestAdESLTAValidationResult tests the LTA validation result.
func TestAdESLTAValidationResult(t *testing.T) {
	result := NewAdESLTAValidationResult()
	if result == nil {
		t.Fatal("NewAdESLTAValidationResult returned nil")
	}
	if result.AdESWithTimeValidationResult == nil {
		t.Error("AdESWithTimeValidationResult should not be nil")
	}
	if result.DocumentTimestamps != nil && len(result.DocumentTimestamps) > 0 {
		t.Error("DocumentTimestamps should be empty initially")
	}
}

// TestAdESValidationSpec tests the validation spec.
func TestAdESValidationSpec(t *testing.T) {
	tm := certvalidator.NewSimpleTrustManager()

	t.Run("NewAdESValidationSpec", func(t *testing.T) {
		spec := NewAdESValidationSpec(tm)
		if spec == nil {
			t.Fatal("NewAdESValidationSpec returned nil")
		}
		if spec.TrustManager != tm {
			t.Error("TrustManager not set correctly")
		}
		if spec.AlgorithmPolicy == nil {
			t.Error("AlgorithmPolicy should not be nil")
		}
		if spec.RevocationPolicy == nil {
			t.Error("RevocationPolicy should not be nil")
		}
		if spec.LocalKnowledge == nil {
			t.Error("LocalKnowledge should not be nil")
		}
		if spec.ValidationTime.IsZero() {
			t.Error("ValidationTime should be set")
		}
	})
}

// TestAdESValidator tests the AdES validator.
func TestAdESValidator(t *testing.T) {
	tm := certvalidator.NewSimpleTrustManager()

	t.Run("NewAdESValidator", func(t *testing.T) {
		validator := NewAdESValidator(tm)
		if validator == nil {
			t.Fatal("NewAdESValidator returned nil")
		}
		if validator.Spec == nil {
			t.Error("Spec should not be nil")
		}
		if validator.Spec.TrustManager != tm {
			t.Error("TrustManager not set correctly")
		}
	})
}

// TestAdESIndicationConstants tests that indication constants are correct.
func TestAdESIndicationConstants(t *testing.T) {
	if ades.IndicationPassed != "PASSED" {
		t.Errorf("Expected 'PASSED', got '%s'", ades.IndicationPassed)
	}
	if ades.IndicationFailed != "FAILED" {
		t.Errorf("Expected 'FAILED', got '%s'", ades.IndicationFailed)
	}
	if ades.IndicationIndeterminate != "INDETERMINATE" {
		t.Errorf("Expected 'INDETERMINATE', got '%s'", ades.IndicationIndeterminate)
	}
}

// TestAdESSubIndicationConstants tests sub-indication constants.
func TestAdESSubIndicationConstants(t *testing.T) {
	subIndications := []string{
		ades.SubIndicationFormatFailure,
		ades.SubIndicationHashFailure,
		ades.SubIndicationSigConstraintsFailure,
		ades.SubIndicationCryptoConstraintsFailure,
		ades.SubIndicationNoCertificateChainFound,
		ades.SubIndicationNoSignerCertFound,
		ades.SubIndicationNoValidTimestamp,
		ades.SubIndicationOutOfBoundsNoPoE,
	}

	for _, si := range subIndications {
		if si == "" {
			t.Error("Sub-indication should not be empty")
		}
	}
}

// TestValidationObjectAddFromCertificate tests adding certificate objects.
func TestValidationObjectAddFromCertificate(t *testing.T) {
	set := NewValidationObjectSet()
	cert := createTestCertificateForAdES(t)

	vo := &ValidationObject{
		ObjectType: ValidationObjectCertificate,
		Value:      cert,
	}
	vo.Identifier = DeriveValidationObjectIdentifier(vo)

	set.Add(vo)

	if set.Count() != 1 {
		t.Errorf("Expected count 1, got %d", set.Count())
	}

	retrieved, ok := set.Get(vo.Identifier)
	if !ok {
		t.Error("Failed to retrieve added object")
	}

	if retrieved.ObjectType != ValidationObjectCertificate {
		t.Error("Object type mismatch")
	}
}

// TestAdESValidationResultChaining tests result type chaining.
func TestAdESValidationResultChaining(t *testing.T) {
	// Test that LTA result can access basic result fields
	ltaResult := NewAdESLTAValidationResult()
	ltaResult.Indication = ades.IndicationPassed
	ltaResult.SubIndication = ""
	ltaResult.FailureMessage = ""
	ltaResult.BestSignatureTime = time.Now()
	ltaResult.DSSPresent = true

	// Access fields through the chain
	if ltaResult.Indication != ades.IndicationPassed {
		t.Error("Failed to access Indication through chain")
	}
	if ltaResult.BestSignatureTime.IsZero() {
		t.Error("Failed to access BestSignatureTime")
	}
	if !ltaResult.DSSPresent {
		t.Error("DSSPresent should be true")
	}
}

// TestAdESLTAResultFields tests LTA-specific fields.
func TestAdESLTAResultFields(t *testing.T) {
	result := NewAdESLTAValidationResult()

	// Set LTA-specific fields
	result.DSSPresent = true
	result.RevocationDataComplete = true
	result.CertificateDataComplete = true
	result.DocumentTimestamps = []*TimestampSignatureStatus{
		{
			Valid:     true,
			Trusted:   true,
			Timestamp: time.Now(),
		},
	}

	if !result.DSSPresent {
		t.Error("DSSPresent should be true")
	}
	if !result.RevocationDataComplete {
		t.Error("RevocationDataComplete should be true")
	}
	if !result.CertificateDataComplete {
		t.Error("CertificateDataComplete should be true")
	}
	if len(result.DocumentTimestamps) != 1 {
		t.Errorf("Expected 1 timestamp, got %d", len(result.DocumentTimestamps))
	}
}
