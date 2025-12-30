// Package certvalidator provides X.509 certificate path validation.
// This file contains tests for the main validation functions.
package certvalidator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

func generateTestCertForValidate(t *testing.T, cn string, isCA bool, issuer *x509.Certificate, issuerKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	signingCert := template
	signingKey := key
	if issuer != nil {
		signingCert = issuer
		signingKey = issuerKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, signingCert, &key.PublicKey, signingKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, key
}

func TestValidatePath(t *testing.T) {
	// Create a simple chain: root -> leaf
	rootCert, rootKey := generateTestCertForValidate(t, "Root CA", true, nil, nil)
	leafCert, _ := generateTestCertForValidate(t, "Leaf Cert", false, rootCert, rootKey)

	// Create validation context
	ctx, err := NewEnhancedValidationContext(
		WithTrustRoots([]*x509.Certificate{rootCert}),
	)
	if err != nil {
		t.Fatalf("failed to create validation context: %v", err)
	}

	// Create validation path
	path := NewValidationPath(rootCert)
	path.SetEECert(leafCert)

	// Validate path
	result, err := ValidatePath(ctx, path, nil)
	if err != nil {
		t.Fatalf("ValidatePath returned error: %v", err)
	}

	if !result.Valid {
		t.Errorf("Expected valid path, got invalid with errors: %v", result.Errors)
	}

	if result.LeafCert == nil {
		t.Error("Expected leaf cert to be set in result")
	}

	if result.Path == nil {
		t.Error("Expected path to be set in result")
	}
}

func TestValidatePathNilContext(t *testing.T) {
	path := NewValidationPath(nil)

	_, err := ValidatePath(nil, path, nil)
	if err == nil {
		t.Error("Expected error for nil context")
	}
}

func TestValidatePathNilPath(t *testing.T) {
	ctx, _ := NewEnhancedValidationContext()

	_, err := ValidatePath(ctx, nil, nil)
	if err == nil {
		t.Error("Expected error for nil path")
	}
}

func TestValidatePathExpiredCert(t *testing.T) {
	// Create an expired certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Expired Cert",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Expired
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	ctx, _ := NewEnhancedValidationContext(
		WithTrustRoots([]*x509.Certificate{cert}),
	)

	path := NewValidationPath(cert)
	path.SetEECert(cert)

	result, err := ValidatePath(ctx, path, nil)
	if err != nil {
		t.Fatalf("ValidatePath returned error: %v", err)
	}

	if result.Valid {
		t.Error("Expected invalid path for expired certificate")
	}
}

func TestValidatePathWhitelistedCert(t *testing.T) {
	// Create an expired certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Expired But Whitelisted",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Expired
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Create context with whitelisted cert
	ctx, _ := NewEnhancedValidationContext(
		WithTrustRoots([]*x509.Certificate{cert}),
	)

	// Whitelist the expired cert
	fingerprint := certFingerprint(cert)
	ctx.AddWhitelistedCert(fingerprint)

	if !ctx.IsWhitelisted(cert) {
		t.Error("Expected cert to be whitelisted")
	}
}

func TestCheckValidity(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name        string
		notBefore   time.Time
		notAfter    time.Time
		moment      time.Time
		tolerance   time.Duration
		expectError bool
	}{
		{
			name:        "valid_cert",
			notBefore:   time.Now().Add(-time.Hour),
			notAfter:    time.Now().Add(24 * time.Hour),
			moment:      time.Now(),
			tolerance:   time.Second,
			expectError: false,
		},
		{
			name:        "expired_cert",
			notBefore:   time.Now().Add(-48 * time.Hour),
			notAfter:    time.Now().Add(-24 * time.Hour),
			moment:      time.Now(),
			tolerance:   time.Second,
			expectError: true,
		},
		{
			name:        "not_yet_valid_cert",
			notBefore:   time.Now().Add(24 * time.Hour),
			notAfter:    time.Now().Add(48 * time.Hour),
			moment:      time.Now(),
			tolerance:   time.Second,
			expectError: true,
		},
		{
			name:        "expired_within_tolerance",
			notBefore:   time.Now().Add(-48 * time.Hour),
			notAfter:    time.Now().Add(-100 * time.Millisecond),
			moment:      time.Now(),
			tolerance:   5 * time.Second,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{CommonName: "Test"},
				NotBefore:    tt.notBefore,
				NotAfter:     tt.notAfter,
			}
			certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			cert, _ := x509.ParseCertificate(certBytes)

			err := CheckValidity(cert, tt.moment, tt.tolerance)
			if (err != nil) != tt.expectError {
				t.Errorf("CheckValidity() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestValidateTLSHostname(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"example.com", "*.example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	ctx, _ := NewEnhancedValidationContext()

	tests := []struct {
		hostname    string
		expectError bool
	}{
		{"example.com", false},
		{"sub.example.com", false},
		{"other.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			err := ValidateTLSHostname(ctx, cert, tt.hostname)
			if (err != nil) != tt.expectError {
				t.Errorf("ValidateTLSHostname(%s) error = %v, expectError %v", tt.hostname, err, tt.expectError)
			}
		})
	}
}

func TestValidateUsage(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	ctx, _ := NewEnhancedValidationContext()

	tests := []struct {
		name        string
		keyUsage    x509.KeyUsage
		extKeyUsage []x509.ExtKeyUsage
		extOptional bool
		expectError bool
	}{
		{
			name:        "valid_usage",
			keyUsage:    x509.KeyUsageDigitalSignature,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			expectError: false,
		},
		{
			name:        "missing_key_usage",
			keyUsage:    x509.KeyUsageCertSign,
			extKeyUsage: nil,
			expectError: true,
		},
		{
			name:        "missing_ext_key_usage",
			keyUsage:    0,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			expectError: true,
		},
		{
			name:        "optional_ext_key_usage",
			keyUsage:    0,
			extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			extOptional: true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsage(ctx, cert, tt.keyUsage, tt.extKeyUsage, tt.extOptional)
			if (err != nil) != tt.expectError {
				t.Errorf("ValidateUsage() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestValidateAAUsage(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Valid AA certificate
	aaTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "AA Cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         false,
	}
	aaBytes, _ := x509.CreateCertificate(rand.Reader, aaTemplate, aaTemplate, &key.PublicKey, key)
	aaCert, _ := x509.ParseCertificate(aaBytes)

	// Invalid AA certificate (is CA)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "CA Cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caBytes, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	caCert, _ := x509.ParseCertificate(caBytes)

	ctx, _ := NewEnhancedValidationContext()

	tests := []struct {
		name        string
		cert        *x509.Certificate
		expectError bool
	}{
		{"valid_aa", aaCert, false},
		{"invalid_aa_is_ca", caCert, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAAUsage(ctx, tt.cert, nil)
			if (err != nil) != tt.expectError {
				t.Errorf("ValidateAAUsage() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestValidatePathResult(t *testing.T) {
	result := &ValidatePathResult{
		Valid: true,
	}

	if !result.Valid {
		t.Error("Expected result to be valid")
	}

	result.Errors = append(result.Errors, errors.New("test error"))
	result.Valid = false

	if result.Valid {
		t.Error("Expected result to be invalid")
	}

	if len(result.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(result.Errors))
	}
}

func TestPathValidationConfig(t *testing.T) {
	ctx, _ := NewEnhancedValidationContext()
	config := NewPathValidationConfig(ctx)

	if config.ValidationContext != ctx {
		t.Error("ValidationContext not set correctly")
	}

	if config.CertProfile != EECertProfileRegular {
		t.Errorf("CertProfile = %v, want %v", config.CertProfile, EECertProfileRegular)
	}
}

func TestEECertProfile(t *testing.T) {
	tests := []struct {
		profile  EECertProfile
		expected int
	}{
		{EECertProfileRegular, 0},
		{EECertProfileAttributeAuthority, 1},
	}

	for _, tt := range tests {
		if int(tt.profile) != tt.expected {
			t.Errorf("EECertProfile %v = %d, want %d", tt.profile, int(tt.profile), tt.expected)
		}
	}
}

func TestOIDOCSPNoCheck(t *testing.T) {
	expected := []int{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	for i, v := range OIDOCSPNoCheck {
		if v != expected[i] {
			t.Errorf("OIDOCSPNoCheck[%d] = %d, want %d", i, v, expected[i])
		}
	}
}

func TestIsOCSPNoMatchesError(t *testing.T) {
	ocspErr := NewOCSPNoMatchesError("test")
	if !isOCSPNoMatchesError(ocspErr) {
		t.Error("Expected isOCSPNoMatchesError to return true")
	}

	otherErr := errors.New("other error")
	if isOCSPNoMatchesError(otherErr) {
		t.Error("Expected isOCSPNoMatchesError to return false for other error")
	}
}

func TestIsCRLNoMatchesError(t *testing.T) {
	crlErr := NewCRLNoMatchesError("test")
	if !isCRLNoMatchesError(crlErr) {
		t.Error("Expected isCRLNoMatchesError to return true")
	}

	otherErr := errors.New("other error")
	if isCRLNoMatchesError(otherErr) {
		t.Error("Expected isCRLNoMatchesError to return false for other error")
	}
}

func TestPOEManagerFromContext(t *testing.T) {
	ctx, _ := NewEnhancedValidationContext()

	poeManager := POEManagerFromContext(ctx)
	if poeManager != ctx.POEManager {
		t.Error("POEManagerFromContext should return context's POEManager")
	}
}

func TestRecordPOE(t *testing.T) {
	ctx, _ := NewEnhancedValidationContext()
	cert, _ := generateTestCertForValidate(t, "Test", false, nil, nil)

	// Record POE
	now := time.Now()
	RecordPOE(ctx, cert, now)

	// Check that POE was recorded
	if ctx.POEManager == nil {
		t.Fatal("POEManager is nil")
	}
}

func TestHasOCSPNoCheck(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Certificate without OCSP No Check extension
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	if hasOCSPNoCheck(cert) {
		t.Error("Expected hasOCSPNoCheck to return false for cert without extension")
	}
}

func TestValidRevocationReasons(t *testing.T) {
	// Test that all expected reasons are present
	expectedReasons := []string{
		"unspecified",
		"keyCompromise",
		"cACompromise",
		"affiliationChanged",
		"superseded",
		"cessationOfOperation",
		"certificateHold",
		"privilegeWithdrawn",
		"aACompromise",
	}

	for _, reason := range expectedReasons {
		if !ValidRevocationReasons[reason] {
			t.Errorf("Expected ValidRevocationReasons to contain %s", reason)
		}
	}

	if len(ValidRevocationReasons) != len(expectedReasons) {
		t.Errorf("ValidRevocationReasons has %d entries, expected %d", len(ValidRevocationReasons), len(expectedReasons))
	}
}

// Helper function to get cert fingerprint
func certFingerprint(cert *x509.Certificate) string {
	h := hashCertSHA1(cert.Raw)
	return hexEncode(h)
}

func hexEncode(b []byte) string {
	const hextable = "0123456789abcdef"
	dst := make([]byte, len(b)*2)
	for i, v := range b {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return string(dst)
}
