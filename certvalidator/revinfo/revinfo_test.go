// Package revinfo provides revocation information handling tests.
package revinfo

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Test helper functions

func generateTestCertificate(t *testing.T, isCA bool, parent *x509.Certificate, parentKey interface{}) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test Certificate",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		CRLDistributionPoints: []string{"http://example.com/crl"},
		OCSPServer:            []string{"http://example.com/ocsp"},
	}

	signerCert := template
	signerKey := key
	if parent != nil {
		signerCert = parent
		signerKey = parentKey.(*ecdsa.PrivateKey)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, key
}

func generateTestCRL(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, revokedSerials []*big.Int) []byte {
	t.Helper()

	var revokedCerts []pkix.RevokedCertificate
	for _, serial := range revokedSerials {
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Hour),
		})
	}

	template := &x509.RevocationList{
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now().Add(-time.Hour),
		NextUpdate:          time.Now().Add(24 * time.Hour),
		RevokedCertificates: revokedCerts,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, issuer, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create CRL: %v", err)
	}

	return crlDER
}

// RevocationReason tests

func TestRevocationReasonString(t *testing.T) {
	tests := []struct {
		reason   RevocationReason
		expected string
	}{
		{ReasonUnspecified, "unspecified"},
		{ReasonKeyCompromise, "keyCompromise"},
		{ReasonCACompromise, "cACompromise"},
		{ReasonAffiliationChanged, "affiliationChanged"},
		{ReasonSuperseded, "superseded"},
		{ReasonCessationOfOperation, "cessationOfOperation"},
		{ReasonCertificateHold, "certificateHold"},
		{ReasonRemoveFromCRL, "removeFromCRL"},
		{ReasonPrivilegeWithdrawn, "privilegeWithdrawn"},
		{ReasonAACompromise, "aACompromise"},
		{RevocationReason(99), "unknown(99)"},
	}

	for _, tt := range tests {
		result := tt.reason.String()
		if result != tt.expected {
			t.Errorf("RevocationReason(%d).String() = %q, want %q", tt.reason, result, tt.expected)
		}
	}
}

// RevocationStatus tests

func TestRevocationStatusString(t *testing.T) {
	tests := []struct {
		status   RevocationStatus
		expected string
	}{
		{StatusGood, "good"},
		{StatusRevoked, "revoked"},
		{StatusUnknown, "unknown"},
		{RevocationStatus(99), "unknown"},
	}

	for _, tt := range tests {
		result := tt.status.String()
		if result != tt.expected {
			t.Errorf("RevocationStatus(%d).String() = %q, want %q", tt.status, result, tt.expected)
		}
	}
}

// RevocationInfo tests

func TestRevocationInfoIsValid(t *testing.T) {
	now := time.Now()
	nextUpdate := now.Add(time.Hour)

	tests := []struct {
		name     string
		info     *RevocationInfo
		at       time.Time
		expected bool
	}{
		{
			name: "valid within range",
			info: &RevocationInfo{
				ThisUpdate: now.Add(-time.Hour),
				NextUpdate: &nextUpdate,
			},
			at:       now,
			expected: true,
		},
		{
			name: "before this update",
			info: &RevocationInfo{
				ThisUpdate: now.Add(time.Hour),
				NextUpdate: nil,
			},
			at:       now,
			expected: false,
		},
		{
			name: "after next update",
			info: &RevocationInfo{
				ThisUpdate: now.Add(-2 * time.Hour),
				NextUpdate: func() *time.Time { t := now.Add(-time.Hour); return &t }(),
			},
			at:       now,
			expected: false,
		},
		{
			name: "no next update",
			info: &RevocationInfo{
				ThisUpdate: now.Add(-time.Hour),
				NextUpdate: nil,
			},
			at:       now,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.info.IsValid(tt.at)
			if result != tt.expected {
				t.Errorf("IsValid() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// CRLInfo tests

func TestNewCRLInfo(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	crlData := generateTestCRL(t, caCert, caKey, nil)

	info, err := NewCRLInfo(crlData, caCert, "http://example.com/crl")
	if err != nil {
		t.Fatalf("NewCRLInfo failed: %v", err)
	}

	if info.CRL == nil {
		t.Error("CRL should not be nil")
	}
	if info.URL != "http://example.com/crl" {
		t.Errorf("URL = %q, want %q", info.URL, "http://example.com/crl")
	}
	if info.IsDelta {
		t.Error("Should not be delta CRL")
	}
}

func TestNewCRLInfoInvalidData(t *testing.T) {
	_, err := NewCRLInfo([]byte("invalid"), nil, "")
	if err == nil {
		t.Error("Expected error for invalid CRL data")
	}
}

func TestCRLInfoValidate(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	crlData := generateTestCRL(t, caCert, caKey, nil)

	info, err := NewCRLInfo(crlData, caCert, "http://example.com/crl")
	if err != nil {
		t.Fatalf("NewCRLInfo failed: %v", err)
	}

	// Valid time
	if err := info.Validate(time.Now()); err != nil {
		t.Errorf("Validate failed for valid time: %v", err)
	}

	// Before this update
	if err := info.Validate(time.Now().Add(-2 * time.Hour)); err == nil {
		t.Error("Expected error for time before thisUpdate")
	}

	// After next update
	if err := info.Validate(time.Now().Add(48 * time.Hour)); err == nil {
		t.Error("Expected error for time after nextUpdate")
	}
}

func TestCRLInfoCheckCertificate(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateTestCertificate(t, false, caCert, caKey)
	revokedCert, _ := generateTestCertificate(t, false, caCert, caKey)

	crlData := generateTestCRL(t, caCert, caKey, []*big.Int{revokedCert.SerialNumber})
	info, _ := NewCRLInfo(crlData, caCert, "http://example.com/crl")

	// Check non-revoked certificate
	result := info.CheckCertificate(cert)
	if result.Status != StatusGood {
		t.Errorf("Expected StatusGood, got %v", result.Status)
	}

	// Check revoked certificate
	result = info.CheckCertificate(revokedCert)
	if result.Status != StatusRevoked {
		t.Errorf("Expected StatusRevoked, got %v", result.Status)
	}
	if result.RevocationTime == nil {
		t.Error("RevocationTime should not be nil")
	}
}

// RevocationInfoArchive tests

func TestRevocationInfoArchive(t *testing.T) {
	archive := NewRevocationInfoArchive()

	if archive.crls == nil || archive.ocsps == nil || archive.certs == nil {
		t.Error("Archive maps should be initialized")
	}
}

func TestRevocationInfoArchiveCRL(t *testing.T) {
	archive := NewRevocationInfoArchive()
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	crlData := generateTestCRL(t, caCert, caKey, nil)
	info, _ := NewCRLInfo(crlData, caCert, "http://example.com/crl")

	// Add and retrieve
	archive.AddCRL(info)
	retrieved := archive.GetCRL("http://example.com/crl")
	if retrieved == nil {
		t.Error("Should retrieve added CRL")
	}

	// Get non-existent
	if archive.GetCRL("http://nonexistent.com/crl") != nil {
		t.Error("Should return nil for non-existent CRL")
	}

	// AllCRLs
	allCRLs := archive.AllCRLs()
	if len(allCRLs) != 1 {
		t.Errorf("AllCRLs() returned %d, want 1", len(allCRLs))
	}

	// RawCRLs
	rawCRLs := archive.RawCRLs()
	if len(rawCRLs) != 1 {
		t.Errorf("RawCRLs() returned %d, want 1", len(rawCRLs))
	}
}

func TestRevocationInfoArchiveCertificate(t *testing.T) {
	archive := NewRevocationInfoArchive()
	cert, _ := generateTestCertificate(t, false, nil, nil)

	// Add and retrieve
	archive.AddCertificate(cert)
	retrieved := archive.GetCertificate(cert.RawSubject, cert.SerialNumber)
	if retrieved == nil {
		t.Error("Should retrieve added certificate")
	}

	// AllCertificates
	allCerts := archive.AllCertificates()
	if len(allCerts) != 1 {
		t.Errorf("AllCertificates() returned %d, want 1", len(allCerts))
	}
}

// CRLValidator tests

func TestCRLValidator(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	validator := NewCRLValidator([]*x509.Certificate{caCert})

	if len(validator.TrustAnchors) != 1 {
		t.Errorf("TrustAnchors = %d, want 1", len(validator.TrustAnchors))
	}

	crlData := generateTestCRL(t, caCert, caKey, nil)
	crl, _ := x509.ParseRevocationList(crlData)

	// Valid CRL
	if err := validator.ValidateCRL(crl, time.Now()); err != nil {
		t.Errorf("ValidateCRL failed: %v", err)
	}
}

func TestCRLValidatorExpired(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	validator := NewCRLValidator([]*x509.Certificate{caCert})

	crlData := generateTestCRL(t, caCert, caKey, nil)
	crl, _ := x509.ParseRevocationList(crlData)

	// Expired CRL (future time)
	err := validator.ValidateCRL(crl, time.Now().Add(48*time.Hour))
	if err == nil {
		t.Error("Expected error for expired CRL")
	}
}

func TestCRLValidatorAllowExpired(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	validator := NewCRLValidator([]*x509.Certificate{caCert})
	validator.AllowExpired = true

	crlData := generateTestCRL(t, caCert, caKey, nil)
	crl, _ := x509.ParseRevocationList(crlData)

	// Should allow expired when flag is set
	if err := validator.ValidateCRL(crl, time.Now().Add(48*time.Hour)); err != nil {
		t.Errorf("ValidateCRL should allow expired: %v", err)
	}
}

// OCSPValidator tests

func TestOCSPValidator(t *testing.T) {
	caCert, _ := generateTestCertificate(t, true, nil, nil)
	validator := NewOCSPValidator([]*x509.Certificate{caCert})

	if len(validator.TrustAnchors) != 1 {
		t.Errorf("TrustAnchors = %d, want 1", len(validator.TrustAnchors))
	}
}

func TestOCSPValidatorValidate(t *testing.T) {
	caCert, _ := generateTestCertificate(t, true, nil, nil)
	validator := NewOCSPValidator([]*x509.Certificate{caCert})

	now := time.Now()
	resp := &ocsp.Response{
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(time.Hour),
	}

	// Valid response
	if err := validator.ValidateOCSP(resp, now); err != nil {
		t.Errorf("ValidateOCSP failed: %v", err)
	}

	// Before this update
	if err := validator.ValidateOCSP(resp, now.Add(-2*time.Hour)); err == nil {
		t.Error("Expected error for time before thisUpdate")
	}

	// After next update
	if err := validator.ValidateOCSP(resp, now.Add(2*time.Hour)); err == nil {
		t.Error("Expected error for time after nextUpdate")
	}
}

func TestOCSPValidatorAllowExpired(t *testing.T) {
	caCert, _ := generateTestCertificate(t, true, nil, nil)
	validator := NewOCSPValidator([]*x509.Certificate{caCert})
	validator.AllowExpired = true

	now := time.Now()
	resp := &ocsp.Response{
		ThisUpdate: now.Add(-2 * time.Hour),
		NextUpdate: now.Add(-time.Hour),
	}

	// Should allow expired when flag is set
	if err := validator.ValidateOCSP(resp, now); err != nil {
		t.Errorf("ValidateOCSP should allow expired: %v", err)
	}
}

// RevocationChecker tests

func TestRevocationChecker(t *testing.T) {
	caCert, _ := generateTestCertificate(t, true, nil, nil)
	checker := NewRevocationChecker([]*x509.Certificate{caCert})

	if checker.Archive == nil {
		t.Error("Archive should not be nil")
	}
	if checker.CRLValidator == nil {
		t.Error("CRLValidator should not be nil")
	}
	if checker.OCSPValidator == nil {
		t.Error("OCSPValidator should not be nil")
	}
	if !checker.PreferOCSP {
		t.Error("PreferOCSP should be true by default")
	}
}

func TestRevocationCheckerCheckRevocation(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateTestCertificate(t, false, caCert, caKey)

	checker := NewRevocationChecker([]*x509.Certificate{caCert})

	// Without any cached data, should return no revocation info
	ctx := context.Background()
	_, err := checker.CheckRevocation(ctx, cert, caCert, time.Now())
	if err == nil {
		t.Error("Expected error when no revocation info available")
	}
}

func TestRevocationCheckerWithCRL(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateTestCertificate(t, false, caCert, caKey)

	crlData := generateTestCRL(t, caCert, caKey, nil)
	crlInfo, _ := NewCRLInfo(crlData, caCert, cert.CRLDistributionPoints[0])

	checker := NewRevocationChecker([]*x509.Certificate{caCert})
	checker.PreferOCSP = false
	checker.Archive.AddCRL(crlInfo)

	ctx := context.Background()
	info, err := checker.CheckRevocation(ctx, cert, caCert, time.Now())
	if err != nil {
		t.Fatalf("CheckRevocation failed: %v", err)
	}
	if info.Status != StatusGood {
		t.Errorf("Expected StatusGood, got %v", info.Status)
	}
}

// RevocationPolicy tests

func TestDefaultRevocationPolicy(t *testing.T) {
	policy := DefaultRevocationPolicy()

	if policy.Mode != RevocationModeSoft {
		t.Errorf("Mode = %v, want RevocationModeSoft", policy.Mode)
	}
	if !policy.AllowMissing {
		t.Error("AllowMissing should be true")
	}
	if policy.HardFail {
		t.Error("HardFail should be false")
	}
	if !policy.PreferOCSP {
		t.Error("PreferOCSP should be true")
	}
}

func TestStrictRevocationPolicy(t *testing.T) {
	policy := StrictRevocationPolicy()

	if policy.Mode != RevocationModeHard {
		t.Errorf("Mode = %v, want RevocationModeHard", policy.Mode)
	}
	if policy.AllowMissing {
		t.Error("AllowMissing should be false")
	}
	if !policy.HardFail {
		t.Error("HardFail should be true")
	}
}

// OCSP helper tests

func TestCreateOCSPRequest(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateTestCertificate(t, false, caCert, caKey)

	// With default hash
	req, err := CreateOCSPRequest(cert, caCert, 0)
	if err != nil {
		t.Fatalf("CreateOCSPRequest failed: %v", err)
	}
	if len(req) == 0 {
		t.Error("Request should not be empty")
	}

	// With specific hash
	req, err = CreateOCSPRequest(cert, caCert, crypto.SHA256)
	if err != nil {
		t.Fatalf("CreateOCSPRequest with SHA256 failed: %v", err)
	}
	if len(req) == 0 {
		t.Error("Request should not be empty")
	}
}

func TestIsOCSPGood(t *testing.T) {
	good := &ocsp.Response{Status: ocsp.Good}
	revoked := &ocsp.Response{Status: ocsp.Revoked}
	unknown := &ocsp.Response{Status: ocsp.Unknown}

	if !IsOCSPGood(good) {
		t.Error("IsOCSPGood should return true for good status")
	}
	if IsOCSPGood(revoked) {
		t.Error("IsOCSPGood should return false for revoked status")
	}
	if IsOCSPGood(unknown) {
		t.Error("IsOCSPGood should return false for unknown status")
	}
}

func TestIsOCSPRevoked(t *testing.T) {
	good := &ocsp.Response{Status: ocsp.Good}
	revoked := &ocsp.Response{Status: ocsp.Revoked}

	if IsOCSPRevoked(good) {
		t.Error("IsOCSPRevoked should return false for good status")
	}
	if !IsOCSPRevoked(revoked) {
		t.Error("IsOCSPRevoked should return true for revoked status")
	}
}

// CRL helper tests

func TestIsDeltaCRL(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	crlData := generateTestCRL(t, caCert, caKey, nil)
	crl, _ := x509.ParseRevocationList(crlData)

	if IsDeltaCRL(crl) {
		t.Error("Regular CRL should not be delta")
	}
}

func TestGetRevokedCertificates(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	serial1 := big.NewInt(12345)
	serial2 := big.NewInt(67890)
	crlData := generateTestCRL(t, caCert, caKey, []*big.Int{serial1, serial2})
	crl, _ := x509.ParseRevocationList(crlData)

	entries := GetRevokedCertificates(crl)
	if len(entries) != 2 {
		t.Errorf("GetRevokedCertificates returned %d, want 2", len(entries))
	}
}

func TestFindRevokedCertificate(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	serial := big.NewInt(12345)
	crlData := generateTestCRL(t, caCert, caKey, []*big.Int{serial})
	crl, _ := x509.ParseRevocationList(crlData)

	// Find existing
	entry := FindRevokedCertificate(crl, serial)
	if entry == nil {
		t.Error("Should find revoked certificate")
	}
	if entry.SerialNumber.Cmp(serial) != 0 {
		t.Error("Serial number mismatch")
	}

	// Find non-existing
	entry = FindRevokedCertificate(crl, big.NewInt(99999))
	if entry != nil {
		t.Error("Should not find non-revoked certificate")
	}
}

// ReasonFlags tests

func TestAllReasons(t *testing.T) {
	flags := AllReasons()

	reasons := []RevocationReason{
		ReasonUnspecified,
		ReasonKeyCompromise,
		ReasonCACompromise,
		ReasonAffiliationChanged,
		ReasonSuperseded,
		ReasonCessationOfOperation,
		ReasonCertificateHold,
		ReasonPrivilegeWithdrawn,
		ReasonAACompromise,
	}

	for _, reason := range reasons {
		if !flags.Contains(reason) {
			t.Errorf("AllReasons should contain %v", reason)
		}
	}
}

func TestReasonFlagsContains(t *testing.T) {
	tests := []struct {
		flag     ReasonFlags
		reason   RevocationReason
		expected bool
	}{
		{ReasonFlagKeyCompromise, ReasonKeyCompromise, true},
		{ReasonFlagKeyCompromise, ReasonCACompromise, false},
		{ReasonFlagCACompromise, ReasonCACompromise, true},
		{ReasonFlagAffiliationChanged, ReasonAffiliationChanged, true},
		{ReasonFlagSuperseded, ReasonSuperseded, true},
		{ReasonFlagCessationOfOp, ReasonCessationOfOperation, true},
		{ReasonFlagCertificateHold, ReasonCertificateHold, true},
		{ReasonFlagPrivilegeWithdrawn, ReasonPrivilegeWithdrawn, true},
		{ReasonFlagAACompromise, ReasonAACompromise, true},
		{ReasonFlagUnused, ReasonUnspecified, true},
		{0, ReasonRemoveFromCRL, false},
	}

	for _, tt := range tests {
		result := tt.flag.Contains(tt.reason)
		if result != tt.expected {
			t.Errorf("ReasonFlags(%d).Contains(%v) = %v, want %v", tt.flag, tt.reason, result, tt.expected)
		}
	}
}

// CRLScope tests

func TestCRLScope(t *testing.T) {
	scope := CRLScope{
		OnlyContainsUserCerts: true,
		OnlySomeReasons:       ReasonFlagKeyCompromise | ReasonFlagCACompromise,
	}

	if !scope.OnlyContainsUserCerts {
		t.Error("OnlyContainsUserCerts should be true")
	}
	if scope.OnlyContainsCACerts {
		t.Error("OnlyContainsCACerts should be false")
	}
	if !scope.OnlySomeReasons.Contains(ReasonKeyCompromise) {
		t.Error("Should contain KeyCompromise")
	}
}

// OCSPInfo tests

func TestOCSPInfoToRevocationInfo(t *testing.T) {
	now := time.Now()
	nextUpdate := now.Add(time.Hour)

	tests := []struct {
		name           string
		status         int
		expectedStatus RevocationStatus
	}{
		{"good", ocsp.Good, StatusGood},
		{"revoked", ocsp.Revoked, StatusRevoked},
		{"unknown", ocsp.Unknown, StatusUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &OCSPInfo{
				Raw: []byte("test"),
				Response: &ocsp.Response{
					Status:     tt.status,
					ProducedAt: now,
					ThisUpdate: now.Add(-time.Hour),
					NextUpdate: nextUpdate,
					RevokedAt:  now.Add(-30 * time.Minute),
				},
			}

			result := info.ToRevocationInfo()
			if result.Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", result.Status, tt.expectedStatus)
			}
			if result.Source != "OCSP" {
				t.Errorf("Source = %q, want %q", result.Source, "OCSP")
			}
		})
	}
}

func TestOCSPInfoValidate(t *testing.T) {
	now := time.Now()

	info := &OCSPInfo{
		Response: &ocsp.Response{
			ThisUpdate: now.Add(-time.Hour),
			NextUpdate: now.Add(time.Hour),
		},
	}

	// Valid
	if err := info.Validate(now); err != nil {
		t.Errorf("Validate failed: %v", err)
	}

	// Before this update
	if err := info.Validate(now.Add(-2 * time.Hour)); err == nil {
		t.Error("Expected error for time before thisUpdate")
	}

	// After next update
	if err := info.Validate(now.Add(2 * time.Hour)); err == nil {
		t.Error("Expected error for time after nextUpdate")
	}
}

// Error tests

func TestErrors(t *testing.T) {
	errors := []error{
		ErrRevoked,
		ErrCRLExpired,
		ErrCRLNotYetValid,
		ErrOCSPExpired,
		ErrOCSPNotYetValid,
		ErrInvalidSignature,
		ErrIssuerMismatch,
		ErrNoRevocationInfo,
		ErrRevocationCheckFailed,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("Error should have non-empty message: %v", err)
		}
	}
}

// Concurrency tests

func TestRevocationInfoArchiveConcurrency(t *testing.T) {
	archive := NewRevocationInfoArchive()
	caCert, caKey := generateTestCertificate(t, true, nil, nil)

	done := make(chan bool)

	// Concurrent writers
	for i := 0; i < 10; i++ {
		go func(idx int) {
			cert, _ := generateTestCertificate(t, false, caCert, caKey)
			archive.AddCertificate(cert)
			done <- true
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 10; i++ {
		go func() {
			_ = archive.AllCertificates()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}

// RevocationMode tests

func TestRevocationMode(t *testing.T) {
	if RevocationModeNone != 0 {
		t.Error("RevocationModeNone should be 0")
	}
	if RevocationModeSoft != 1 {
		t.Error("RevocationModeSoft should be 1")
	}
	if RevocationModeHard != 2 {
		t.Error("RevocationModeHard should be 2")
	}
}

// Archive OCSP tests

func TestRevocationInfoArchiveOCSP(t *testing.T) {
	archive := NewRevocationInfoArchive()
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateTestCertificate(t, false, caCert, caKey)

	ocspInfo := &OCSPInfo{
		Raw: []byte("test"),
		Response: &ocsp.Response{
			Status: ocsp.Good,
		},
		URL: "http://example.com/ocsp",
	}

	// Add and retrieve
	archive.AddOCSP(cert, ocspInfo)
	retrieved := archive.GetOCSP(cert)
	if retrieved == nil {
		t.Error("Should retrieve added OCSP")
	}

	// AllOCSPs
	allOCSPs := archive.AllOCSPs()
	if len(allOCSPs) != 1 {
		t.Errorf("AllOCSPs() returned %d, want 1", len(allOCSPs))
	}

	// RawOCSPs
	rawOCSPs := archive.RawOCSPs()
	if len(rawOCSPs) != 1 {
		t.Errorf("RawOCSPs() returned %d, want 1", len(rawOCSPs))
	}
}
