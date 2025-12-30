// Package ltv provides Long-Term Validation tests.
package ltv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Test helpers

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

func generateExpiredCertificate(t *testing.T, parent *x509.Certificate, parentKey interface{}) (*x509.Certificate, *ecdsa.PrivateKey) {
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
			CommonName:   "Expired Certificate",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Expired
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
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

func generateTestCRL(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) *x509.RevocationList {
	t.Helper()

	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, issuer, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create CRL: %v", err)
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	return crl
}

// POEType tests

func TestPOETypeString(t *testing.T) {
	tests := []struct {
		poeType  POEType
		expected string
	}{
		{POETypeTimestamp, "timestamp"},
		{POETypeSignature, "signature"},
		{POETypeCRL, "crl"},
		{POETypeOCSP, "ocsp"},
		{POETypeArchiveTimestamp, "archive_timestamp"},
		{POETypeExternal, "external"},
		{POEType(99), "unknown(99)"},
	}

	for _, tt := range tests {
		result := tt.poeType.String()
		if result != tt.expected {
			t.Errorf("POEType(%d).String() = %q, want %q", tt.poeType, result, tt.expected)
		}
	}
}

// ProofOfExistence tests

func TestProofOfExistenceIsValidAt(t *testing.T) {
	now := time.Now()
	poe := &ProofOfExistence{
		Time:     now,
		Type:     POETypeTimestamp,
		DataHash: []byte("test"),
	}

	// At POE time
	if !poe.IsValidAt(now) {
		t.Error("POE should be valid at its own time")
	}

	// After POE time
	if !poe.IsValidAt(now.Add(time.Hour)) {
		t.Error("POE should be valid after its time")
	}

	// Before POE time
	if poe.IsValidAt(now.Add(-time.Hour)) {
		t.Error("POE should not be valid before its time")
	}
}

// POEManager tests

func TestPOEManager(t *testing.T) {
	manager := NewPOEManager()
	if manager.poes == nil {
		t.Error("POE manager should be initialized")
	}
}

func TestPOEManagerAddAndGet(t *testing.T) {
	manager := NewPOEManager()
	dataHash := []byte("test-data")
	poe := &ProofOfExistence{
		Time:     time.Now(),
		Type:     POETypeTimestamp,
		DataHash: dataHash,
	}

	manager.Add(poe)
	result := manager.Get(dataHash)

	if len(result) != 1 {
		t.Errorf("Expected 1 POE, got %d", len(result))
	}
	if result[0] != poe {
		t.Error("Retrieved POE should match added POE")
	}
}

func TestPOEManagerGetEarliest(t *testing.T) {
	manager := NewPOEManager()
	dataHash := []byte("test-data")
	now := time.Now()

	poe1 := &ProofOfExistence{Time: now, Type: POETypeTimestamp, DataHash: dataHash}
	poe2 := &ProofOfExistence{Time: now.Add(-time.Hour), Type: POETypeCRL, DataHash: dataHash}
	poe3 := &ProofOfExistence{Time: now.Add(time.Hour), Type: POETypeOCSP, DataHash: dataHash}

	manager.Add(poe1)
	manager.Add(poe2)
	manager.Add(poe3)

	earliest := manager.GetEarliest(dataHash)
	if earliest != poe2 {
		t.Error("Should return the earliest POE")
	}
}

func TestPOEManagerGetLatest(t *testing.T) {
	manager := NewPOEManager()
	dataHash := []byte("test-data")
	now := time.Now()

	poe1 := &ProofOfExistence{Time: now, Type: POETypeTimestamp, DataHash: dataHash}
	poe2 := &ProofOfExistence{Time: now.Add(-time.Hour), Type: POETypeCRL, DataHash: dataHash}
	poe3 := &ProofOfExistence{Time: now.Add(time.Hour), Type: POETypeOCSP, DataHash: dataHash}

	manager.Add(poe1)
	manager.Add(poe2)
	manager.Add(poe3)

	latest := manager.GetLatest(dataHash)
	if latest != poe3 {
		t.Error("Should return the latest POE")
	}
}

func TestPOEManagerGetBefore(t *testing.T) {
	manager := NewPOEManager()
	dataHash := []byte("test-data")
	now := time.Now()

	poe1 := &ProofOfExistence{Time: now, Type: POETypeTimestamp, DataHash: dataHash}
	poe2 := &ProofOfExistence{Time: now.Add(-2 * time.Hour), Type: POETypeCRL, DataHash: dataHash}
	poe3 := &ProofOfExistence{Time: now.Add(time.Hour), Type: POETypeOCSP, DataHash: dataHash}

	manager.Add(poe1)
	manager.Add(poe2)
	manager.Add(poe3)

	before := manager.GetBefore(dataHash, now.Add(-time.Hour))
	if len(before) != 1 {
		t.Errorf("Expected 1 POE, got %d", len(before))
	}
}

func TestPOEManagerHasPOE(t *testing.T) {
	manager := NewPOEManager()
	dataHash := []byte("test-data")

	if manager.HasPOE(dataHash) {
		t.Error("Should not have POE initially")
	}

	manager.Add(&ProofOfExistence{Time: time.Now(), DataHash: dataHash})

	if !manager.HasPOE(dataHash) {
		t.Error("Should have POE after adding")
	}
}

func TestPOEManagerAll(t *testing.T) {
	manager := NewPOEManager()

	manager.Add(&ProofOfExistence{Time: time.Now(), DataHash: []byte("a")})
	manager.Add(&ProofOfExistence{Time: time.Now(), DataHash: []byte("b")})
	manager.Add(&ProofOfExistence{Time: time.Now(), DataHash: []byte("c")})

	all := manager.All()
	if len(all) != 3 {
		t.Errorf("Expected 3 POEs, got %d", len(all))
	}
}

// ValidationTimeType tests

func TestValidationTimeTypeString(t *testing.T) {
	tests := []struct {
		vtt      ValidationTimeType
		expected string
	}{
		{ValidationTimeNow, "now"},
		{ValidationTimeSignature, "signature"},
		{ValidationTimeTimestamp, "timestamp"},
		{ValidationTimePOE, "poe"},
		{ValidationTimeExplicit, "explicit"},
		{ValidationTimeType(99), "unknown(99)"},
	}

	for _, tt := range tests {
		result := tt.vtt.String()
		if result != tt.expected {
			t.Errorf("ValidationTimeType(%d).String() = %q, want %q", tt.vtt, result, tt.expected)
		}
	}
}

// ValidationTime tests

func TestNewValidationTimeNow(t *testing.T) {
	vt := NewValidationTimeNow()
	if vt.Type != ValidationTimeNow {
		t.Error("Type should be ValidationTimeNow")
	}
	if time.Since(vt.Time) > time.Second {
		t.Error("Time should be close to now")
	}
}

func TestNewValidationTimeExplicit(t *testing.T) {
	specificTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	vt := NewValidationTimeExplicit(specificTime, "test time")

	if vt.Type != ValidationTimeExplicit {
		t.Error("Type should be ValidationTimeExplicit")
	}
	if !vt.Time.Equal(specificTime) {
		t.Error("Time should match provided time")
	}
	if vt.Label != "test time" {
		t.Error("Label should match provided label")
	}
}

func TestNewValidationTimeFromPOE(t *testing.T) {
	poe := &ProofOfExistence{
		Time: time.Now(),
		Type: POETypeTimestamp,
	}
	vt := NewValidationTimeFromPOE(poe)

	if vt.Type != ValidationTimePOE {
		t.Error("Type should be ValidationTimePOE")
	}
	if vt.POE != poe {
		t.Error("POE should match provided POE")
	}
}

// LTVStatus tests

func TestLTVStatusString(t *testing.T) {
	tests := []struct {
		status   LTVStatus
		expected string
	}{
		{LTVStatusEnabled, "enabled"},
		{LTVStatusDisabled, "disabled"},
		{LTVStatusPartial, "partial"},
		{LTVStatusExpired, "expired"},
		{LTVStatusUnknown, "unknown"},
	}

	for _, tt := range tests {
		result := tt.status.String()
		if result != tt.expected {
			t.Errorf("LTVStatus(%d).String() = %q, want %q", tt.status, result, tt.expected)
		}
	}
}

// LTVInfo tests

func TestLTVInfo(t *testing.T) {
	info := NewLTVInfo()
	if info.Status != LTVStatusUnknown {
		t.Error("Initial status should be unknown")
	}
}

func TestLTVInfoAddError(t *testing.T) {
	info := NewLTVInfo()
	info.AddError(ErrNoPOE)

	if !info.HasErrors() {
		t.Error("Should have errors")
	}
	if len(info.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(info.Errors))
	}
}

func TestLTVInfoAddWarning(t *testing.T) {
	info := NewLTVInfo()
	info.AddWarning("test warning")

	if len(info.Warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d", len(info.Warnings))
	}
}

func TestLTVInfoIsValid(t *testing.T) {
	info := NewLTVInfo()
	info.Status = LTVStatusEnabled

	if !info.IsValid() {
		t.Error("Should be valid when enabled with no errors")
	}

	info.AddError(ErrNoPOE)
	if info.IsValid() {
		t.Error("Should not be valid when there are errors")
	}
}

// TimeSlideValidator tests

func TestTimeSlideValidator(t *testing.T) {
	caCert, _ := generateTestCertificate(t, true, nil, nil)
	validator := NewTimeSlideValidator([]*x509.Certificate{caCert})

	if len(validator.TrustAnchors) != 1 {
		t.Error("Should have 1 trust anchor")
	}
	if validator.POEManager == nil {
		t.Error("POEManager should be initialized")
	}
}

func TestTimeSlideValidatorValidateAt(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateTestCertificate(t, false, caCert, caKey)

	validator := NewTimeSlideValidator([]*x509.Certificate{caCert})

	// Valid time
	result, err := validator.ValidateAt(cert, time.Now())
	if err != nil {
		t.Fatalf("ValidateAt failed: %v", err)
	}
	if !result.Valid {
		t.Error("Validation should pass for valid certificate")
	}
	if result.CertificateStatus != "valid" {
		t.Errorf("Status = %q, want 'valid'", result.CertificateStatus)
	}
}

func TestTimeSlideValidatorValidateAtBeforeNotBefore(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateTestCertificate(t, false, caCert, caKey)

	validator := NewTimeSlideValidator([]*x509.Certificate{caCert})

	// Before NotBefore
	result, _ := validator.ValidateAt(cert, cert.NotBefore.Add(-24*time.Hour))
	if result.Valid {
		t.Error("Validation should fail before NotBefore")
	}
	if result.CertificateStatus != "not_yet_valid" {
		t.Errorf("Status = %q, want 'not_yet_valid'", result.CertificateStatus)
	}
}

func TestTimeSlideValidatorValidateAtExpired(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateExpiredCertificate(t, caCert, caKey)

	validator := NewTimeSlideValidator([]*x509.Certificate{caCert})

	// After NotAfter
	result, _ := validator.ValidateAt(cert, time.Now())
	if result.Valid {
		t.Error("Validation should fail for expired certificate")
	}
	if result.CertificateStatus != "expired" {
		t.Errorf("Status = %q, want 'expired'", result.CertificateStatus)
	}
}

func TestTimeSlideValidatorAllowExpired(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateExpiredCertificate(t, caCert, caKey)

	validator := NewTimeSlideValidator([]*x509.Certificate{caCert})
	validator.AllowExpiredCerts = true
	validator.GracePeriod = 48 * time.Hour

	// Validate at current time - within grace period, so status is "valid"
	result, _ := validator.ValidateAt(cert, time.Now())
	if result.CertificateStatus != "valid" {
		t.Errorf("Status = %q, want 'valid' (within grace period)", result.CertificateStatus)
	}
	if !result.Valid {
		t.Error("Should be valid within grace period")
	}

	// Validate beyond grace period - should be expired
	validator.GracePeriod = 12 * time.Hour // Less than 24 hours since expiry
	result2, _ := validator.ValidateAt(cert, time.Now())
	if result2.CertificateStatus != "expired" {
		t.Errorf("Status = %q, want 'expired' (outside grace period)", result2.CertificateStatus)
	}
	// Still valid because AllowExpiredCerts is true
	if !result2.Valid {
		t.Error("Should still be valid when AllowExpiredCerts is true")
	}
}

func TestTimeSlideValidatorValidateWithPOE(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateTestCertificate(t, false, caCert, caKey)

	validator := NewTimeSlideValidator([]*x509.Certificate{caCert})
	poe := &ProofOfExistence{
		Time: time.Now(),
		Type: POETypeTimestamp,
	}

	result, err := validator.ValidateWithPOE(cert, poe)
	if err != nil {
		t.Fatalf("ValidateWithPOE failed: %v", err)
	}
	if !result.Valid {
		t.Error("Validation should pass")
	}
}

func TestTimeSlideValidatorValidateWithPOENil(t *testing.T) {
	caCert, _ := generateTestCertificate(t, true, nil, nil)
	validator := NewTimeSlideValidator([]*x509.Certificate{caCert})

	_, err := validator.ValidateWithPOE(nil, nil)
	if err != ErrNoPOE {
		t.Errorf("Expected ErrNoPOE, got %v", err)
	}
}

// AdESValidationLevel tests

func TestAdESValidationLevelString(t *testing.T) {
	tests := []struct {
		level    AdESValidationLevel
		expected string
	}{
		{AdESLevelBES, "BES"},
		{AdESLevelT, "T"},
		{AdESLevelC, "C"},
		{AdESLevelX, "X"},
		{AdESLevelXL, "XL"},
		{AdESLevelA, "A"},
		{AdESValidationLevel(99), "unknown(99)"},
	}

	for _, tt := range tests {
		result := tt.level.String()
		if result != tt.expected {
			t.Errorf("AdESValidationLevel(%d).String() = %q, want %q", tt.level, result, tt.expected)
		}
	}
}

// AdESPastValidator tests

func TestAdESPastValidator(t *testing.T) {
	caCert, _ := generateTestCertificate(t, true, nil, nil)
	validator := NewAdESPastValidator([]*x509.Certificate{caCert})

	if validator.POEManager == nil {
		t.Error("POEManager should be initialized")
	}
	if validator.TimeSlide == nil {
		t.Error("TimeSlide should be initialized")
	}
	if !validator.AllowExpired {
		t.Error("AllowExpired should be true by default")
	}
}

func TestAdESPastValidatorValidate(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateTestCertificate(t, false, caCert, caKey)

	validator := NewAdESPastValidator([]*x509.Certificate{caCert})
	signatureTime := time.Now()

	result, err := validator.Validate(cert, &signatureTime)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if !result.Valid {
		t.Error("Validation should pass for valid certificate")
	}
	if result.Indication != "PASSED" {
		t.Errorf("Indication = %q, want 'PASSED'", result.Indication)
	}
	if result.Level != AdESLevelBES {
		t.Errorf("Level = %v, want AdESLevelBES", result.Level)
	}
}

func TestAdESPastValidatorWithTimestamp(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateTestCertificate(t, false, caCert, caKey)

	validator := NewAdESPastValidator([]*x509.Certificate{caCert})

	// Add timestamp POE
	validator.POEManager.Add(&ProofOfExistence{
		Time:     time.Now(),
		Type:     POETypeTimestamp,
		DataHash: cert.Raw,
	})

	signatureTime := time.Now()
	result, _ := validator.Validate(cert, &signatureTime)

	if result.Level != AdESLevelT {
		t.Errorf("Level = %v, want AdESLevelT", result.Level)
	}
}

// LTVValidator tests

func TestLTVValidator(t *testing.T) {
	caCert, _ := generateTestCertificate(t, true, nil, nil)
	validator := NewLTVValidator([]*x509.Certificate{caCert})

	if validator.POEManager == nil {
		t.Error("POEManager should be initialized")
	}
}

func TestLTVValidatorAddCertificate(t *testing.T) {
	caCert, _ := generateTestCertificate(t, true, nil, nil)
	validator := NewLTVValidator([]*x509.Certificate{caCert})

	cert, _ := generateTestCertificate(t, false, nil, nil)
	validator.AddCertificate(cert)

	if len(validator.Certificates) != 1 {
		t.Error("Should have 1 certificate")
	}
}

func TestLTVValidatorAddCRL(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	validator := NewLTVValidator([]*x509.Certificate{caCert})

	crl := generateTestCRL(t, caCert, caKey)
	validator.AddCRL(crl)

	if len(validator.CRLs) != 1 {
		t.Error("Should have 1 CRL")
	}
}

func TestLTVValidatorCheckLTV(t *testing.T) {
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	cert, _ := generateTestCertificate(t, false, caCert, caKey)

	validator := NewLTVValidator([]*x509.Certificate{caCert})

	// Without any data
	info := validator.CheckLTV(cert)
	if info.Status != LTVStatusDisabled {
		t.Errorf("Status = %v, want LTVStatusDisabled", info.Status)
	}

	// With CRL but no timestamp
	crl := generateTestCRL(t, caCert, caKey)
	validator.AddCRL(crl)
	info = validator.CheckLTV(cert)
	if info.Status != LTVStatusPartial {
		t.Errorf("Status = %v, want LTVStatusPartial", info.Status)
	}

	// With timestamp
	validator.AddTimestamp([]byte("mock-timestamp"))
	info = validator.CheckLTV(cert)
	if info.Status != LTVStatusEnabled {
		t.Errorf("Status = %v, want LTVStatusEnabled", info.Status)
	}
}

// ValidationDataSet tests

func TestValidationDataSet(t *testing.T) {
	set := NewValidationDataSet()
	if !set.IsEmpty() {
		t.Error("New set should be empty")
	}
}

func TestValidationDataSetAdd(t *testing.T) {
	set := NewValidationDataSet()

	cert, _ := generateTestCertificate(t, false, nil, nil)
	set.AddCertificate(cert)
	if len(set.Certificates) != 1 {
		t.Error("Should have 1 certificate")
	}

	set.AddOCSPResponse([]byte("ocsp"))
	if len(set.OCSPResponses) != 1 {
		t.Error("Should have 1 OCSP response")
	}

	set.AddTimestamp([]byte("timestamp"))
	if len(set.Timestamps) != 1 {
		t.Error("Should have 1 timestamp")
	}

	poe := &ProofOfExistence{Time: time.Now()}
	set.AddPOE(poe)
	if len(set.POEs) != 1 {
		t.Error("Should have 1 POE")
	}

	if set.IsEmpty() {
		t.Error("Set should not be empty")
	}
}

func TestValidationDataSetMerge(t *testing.T) {
	set1 := NewValidationDataSet()
	cert1, _ := generateTestCertificate(t, false, nil, nil)
	set1.AddCertificate(cert1)

	set2 := NewValidationDataSet()
	cert2, _ := generateTestCertificate(t, false, nil, nil)
	set2.AddCertificate(cert2)

	set1.Merge(set2)
	if len(set1.Certificates) != 2 {
		t.Error("Merged set should have 2 certificates")
	}

	// Merge nil
	set1.Merge(nil)
	if len(set1.Certificates) != 2 {
		t.Error("Merge nil should not change the set")
	}
}

// ArchivalInfo tests

func TestArchivalInfo(t *testing.T) {
	archive := NewArchivalInfo(time.Now())
	if archive.ValidationData == nil {
		t.Error("ValidationData should be initialized")
	}
}

func TestArchivalInfoChainLength(t *testing.T) {
	archive1 := NewArchivalInfo(time.Now())
	if archive1.ChainLength() != 1 {
		t.Error("Single archive should have length 1")
	}

	archive2 := NewArchivalInfo(time.Now().Add(time.Hour))
	archive2.PreviousArchive = archive1
	if archive2.ChainLength() != 2 {
		t.Error("Chained archive should have length 2")
	}

	archive3 := NewArchivalInfo(time.Now().Add(2 * time.Hour))
	archive3.PreviousArchive = archive2
	if archive3.ChainLength() != 3 {
		t.Error("Chained archive should have length 3")
	}
}

func TestArchivalInfoAllValidationData(t *testing.T) {
	archive1 := NewArchivalInfo(time.Now())
	cert1, _ := generateTestCertificate(t, false, nil, nil)
	archive1.ValidationData.AddCertificate(cert1)

	archive2 := NewArchivalInfo(time.Now().Add(time.Hour))
	cert2, _ := generateTestCertificate(t, false, nil, nil)
	archive2.ValidationData.AddCertificate(cert2)
	archive2.PreviousArchive = archive1

	allData := archive2.AllValidationData()
	if len(allData.Certificates) != 2 {
		t.Error("Should have 2 certificates from chain")
	}
}

// RevocationFreshness tests

func TestDefaultRevocationFreshness(t *testing.T) {
	freshness := DefaultRevocationFreshness()
	if freshness.MaxCRLAge != 7*24*time.Hour {
		t.Error("Default CRL age should be 7 days")
	}
	if freshness.MaxOCSPAge != 24*time.Hour {
		t.Error("Default OCSP age should be 1 day")
	}
}

func TestStrictRevocationFreshness(t *testing.T) {
	freshness := StrictRevocationFreshness()
	if freshness.MaxCRLAge != 24*time.Hour {
		t.Error("Strict CRL age should be 1 day")
	}
	if !freshness.RequireFresh {
		t.Error("Strict should require fresh")
	}
}

func TestRevocationFreshnessIsCRLFresh(t *testing.T) {
	freshness := DefaultRevocationFreshness()
	caCert, caKey := generateTestCertificate(t, true, nil, nil)
	crl := generateTestCRL(t, caCert, caKey)

	if !freshness.IsCRLFresh(crl, time.Now()) {
		t.Error("Recent CRL should be fresh")
	}

	if freshness.IsCRLFresh(crl, time.Now().Add(10*24*time.Hour)) {
		t.Error("Old CRL should not be fresh")
	}
}

// LTVPolicy tests

func TestDefaultLTVPolicy(t *testing.T) {
	policy := DefaultLTVPolicy()
	if policy.RequireTimestamp {
		t.Error("Default should not require timestamp")
	}
	if !policy.RequireRevocationInfo {
		t.Error("Default should require revocation info")
	}
	if !policy.AllowExpiredWithPOE {
		t.Error("Default should allow expired with POE")
	}
}

func TestStrictLTVPolicy(t *testing.T) {
	policy := StrictLTVPolicy()
	if !policy.RequireTimestamp {
		t.Error("Strict should require timestamp")
	}
	if !policy.RequireCompleteChain {
		t.Error("Strict should require complete chain")
	}
}

// CertificateTimeline tests

func TestCertificateTimeline(t *testing.T) {
	cert, _ := generateTestCertificate(t, false, nil, nil)
	timeline := NewCertificateTimeline(cert)

	if len(timeline.Events) != 2 {
		t.Errorf("Should have 2 initial events, got %d", len(timeline.Events))
	}
}

func TestCertificateTimelineAddEvent(t *testing.T) {
	cert, _ := generateTestCertificate(t, false, nil, nil)
	timeline := NewCertificateTimeline(cert)

	timeline.AddEvent(time.Now(), "custom", "Custom event")
	if len(timeline.Events) != 3 {
		t.Error("Should have 3 events after adding")
	}
}

func TestCertificateTimelineWasValidAt(t *testing.T) {
	cert, _ := generateTestCertificate(t, false, nil, nil)
	timeline := NewCertificateTimeline(cert)

	if !timeline.WasValidAt(time.Now()) {
		t.Error("Should be valid now")
	}

	if timeline.WasValidAt(cert.NotBefore.Add(-24 * time.Hour)) {
		t.Error("Should not be valid before NotBefore")
	}

	if timeline.WasValidAt(cert.NotAfter.Add(24 * time.Hour)) {
		t.Error("Should not be valid after NotAfter")
	}
}

func TestCertificateTimelineStatusAt(t *testing.T) {
	cert, _ := generateTestCertificate(t, false, nil, nil)
	timeline := NewCertificateTimeline(cert)

	status := timeline.StatusAt(time.Now())
	if status != "valid" {
		t.Errorf("Status = %q, want 'valid'", status)
	}

	status = timeline.StatusAt(cert.NotBefore.Add(-24 * time.Hour))
	if status != "not_yet_valid" {
		t.Errorf("Status = %q, want 'not_yet_valid'", status)
	}

	status = timeline.StatusAt(cert.NotAfter.Add(24 * time.Hour))
	if status != "expired" {
		t.Errorf("Status = %q, want 'expired'", status)
	}
}

// Error tests

func TestErrors(t *testing.T) {
	errors := []error{
		ErrNoPOE,
		ErrPOENotFound,
		ErrValidationTimeTooOld,
		ErrCertificateExpired,
		ErrCertificateRevoked,
		ErrNoTrustAnchor,
		ErrChainBuildingFailed,
		ErrTimeSlideInvalid,
		ErrInsufficientData,
		ErrTimestampInvalid,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("Error should have non-empty message: %v", err)
		}
	}
}

// Concurrency tests

func TestPOEManagerConcurrency(t *testing.T) {
	manager := NewPOEManager()
	done := make(chan bool)

	// Concurrent writers
	for i := 0; i < 10; i++ {
		go func(idx int) {
			manager.Add(&ProofOfExistence{
				Time:     time.Now(),
				DataHash: []byte{byte(idx)},
			})
			done <- true
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 10; i++ {
		go func() {
			_ = manager.All()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}
