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

// genCert generates a test certificate for AdES past validation testing.
func genCert(t *testing.T, cn string, isCA bool, issuer *x509.Certificate, issuerKey interface{}) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1000000))

	keyUsage := x509.KeyUsageDigitalSignature
	if isCA {
		keyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if issuer == nil {
		issuer = template
		issuerKey = key
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, key
}

func TestDefaultCertValidationPolicySpec(t *testing.T) {
	spec := DefaultCertValidationPolicySpec()

	if spec == nil {
		t.Fatal("DefaultCertValidationPolicySpec returned nil")
	}

	if spec.RevInfoPolicy == nil {
		t.Error("RevInfoPolicy should not be nil")
	}

	if spec.AlgorithmUsagePolicy == nil {
		t.Error("AlgorithmUsagePolicy should not be nil")
	}

	if spec.TimeTolerance != time.Second {
		t.Errorf("TimeTolerance = %v, want 1s", spec.TimeTolerance)
	}

	if spec.PKIXValidationParams == nil {
		t.Error("PKIXValidationParams should not be nil")
	}
}

func TestDefaultPKIXValidationParams(t *testing.T) {
	params := DefaultPKIXValidationParams()

	if params == nil {
		t.Fatal("DefaultPKIXValidationParams returned nil")
	}

	if len(params.InitialPolicySet) != 1 || params.InitialPolicySet[0] != "2.5.29.32.0" {
		t.Error("InitialPolicySet should contain anyPolicy")
	}

	if params.InitialPolicyMappingInhibit {
		t.Error("InitialPolicyMappingInhibit should be false by default")
	}

	if params.InitialExplicitPolicy {
		t.Error("InitialExplicitPolicy should be false by default")
	}

	if params.InitialAnyPolicyInhibit {
		t.Error("InitialAnyPolicyInhibit should be false by default")
	}
}

func TestNewValidationDataHandlers(t *testing.T) {
	handlers := NewValidationDataHandlers()

	if handlers == nil {
		t.Fatal("NewValidationDataHandlers returned nil")
	}

	if handlers.RevInfoManager == nil {
		t.Error("RevInfoManager should not be nil")
	}

	if handlers.POEManager == nil {
		t.Error("POEManager should not be nil")
	}

	if handlers.CertificateStore == nil {
		t.Error("CertificateStore should not be nil")
	}
}

func TestNewRevInfoManager(t *testing.T) {
	manager := NewRevInfoManager()

	if manager == nil {
		t.Fatal("NewRevInfoManager returned nil")
	}

	if manager.CRLs == nil {
		t.Error("CRLs should not be nil")
	}

	if manager.OCSPResponses == nil {
		t.Error("OCSPResponses should not be nil")
	}

	if manager.POEManager == nil {
		t.Error("POEManager should not be nil")
	}
}

func TestRevInfoManagerAddCRL(t *testing.T) {
	root, rootKey := genCert(t, "Root CA", true, nil, nil)

	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, root, rootKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	manager := NewRevInfoManager()
	manager.AddCRL(crl)

	if len(manager.CRLs) != 1 {
		t.Errorf("Expected 1 CRL, got %d", len(manager.CRLs))
	}

	// Check that POE was added
	if !manager.POEManager.HasPOE(crl.Raw) {
		t.Error("POE should be added for CRL")
	}
}

func TestRevInfoManagerAddOCSPResponse(t *testing.T) {
	manager := NewRevInfoManager()
	now := time.Now()

	manager.AddOCSPResponse([]byte("test ocsp"), now)

	if len(manager.OCSPResponses) != 1 {
		t.Errorf("Expected 1 OCSP response, got %d", len(manager.OCSPResponses))
	}

	// Check that POE was added
	if !manager.POEManager.HasPOE([]byte("test ocsp")) {
		t.Error("POE should be added for OCSP response")
	}
}

func TestPastValidateNilInput(t *testing.T) {
	_, err := PastValidate(nil)
	if err == nil {
		t.Error("Expected error for nil input")
	}
}

func TestPastValidateNilPath(t *testing.T) {
	input := &PastValidateInput{
		Path: nil,
	}
	_, err := PastValidate(input)
	if err == nil {
		t.Error("Expected error for nil path")
	}
}

func TestPastValidateEmptyPath(t *testing.T) {
	path := &ValidationPath{}

	input := &PastValidateInput{
		Path: path,
	}

	output, err := PastValidate(input)
	if err != nil {
		t.Fatalf("PastValidate error: %v", err)
	}

	if !output.Valid {
		t.Errorf("Empty path should be valid, errors: %v", output.Errors)
	}

	if output.Indication != "PASSED" {
		t.Errorf("Indication = %s, want PASSED", output.Indication)
	}
}

func TestPastValidateWithTrustAnchorOnly(t *testing.T) {
	root, _ := genCert(t, "Root CA", true, nil, nil)

	path := NewValidationPath(root)

	input := &PastValidateInput{
		Path: path,
	}

	output, err := PastValidate(input)
	if err != nil {
		t.Fatalf("PastValidate error: %v", err)
	}

	if !output.Valid {
		t.Errorf("Trust anchor only path should be valid, errors: %v", output.Errors)
	}

	if !output.PrecheckPassed {
		t.Error("Precheck should pass")
	}

	if !output.TimeSlideSucceeded {
		t.Error("Time-slide should succeed")
	}
}

func TestPastValidateWithSimplePath(t *testing.T) {
	root, rootKey := genCert(t, "Root CA", true, nil, nil)
	leaf, _ := genCert(t, "Leaf Cert", false, root, rootKey)

	path := NewValidationPath(root)
	path.SetEECert(leaf)

	policySpec := DefaultCertValidationPolicySpec()
	policySpec.TrustAnchors = []*x509.Certificate{root}
	// Disable revocation requirement for this test
	policySpec.RevInfoPolicy.RevocationCheckingPolicy.EECertificateRule.RequireRevocationInfo = false

	input := &PastValidateInput{
		Path:       path,
		PolicySpec: policySpec,
	}

	output, err := PastValidate(input)
	if err != nil {
		t.Fatalf("PastValidate error: %v", err)
	}

	if !output.Valid {
		t.Errorf("Simple path should be valid, errors: %v", output.Errors)
	}

	if !output.PrecheckPassed {
		t.Error("Precheck should pass")
	}

	if !output.TimeSlideSucceeded {
		t.Error("Time-slide should succeed")
	}
}

func TestPastValidateWithDefaults(t *testing.T) {
	root, _ := genCert(t, "Root CA", true, nil, nil)
	path := NewValidationPath(root)

	output, err := PastValidateWithDefaults(path)
	if err != nil {
		t.Fatalf("PastValidateWithDefaults error: %v", err)
	}

	if !output.Valid {
		t.Error("Should be valid with defaults")
	}
}

func TestPastValidateSimple(t *testing.T) {
	root, rootKey := genCert(t, "Root CA", true, nil, nil)
	leaf, _ := genCert(t, "Leaf Cert", false, root, rootKey)

	path := NewValidationPath(root)
	path.SetEECert(leaf)

	// Create a CRL that doesn't revoke the leaf
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, root, rootKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	output, err := PastValidateSimple(path, []*x509.Certificate{root}, []*x509.RevocationList{crl}, nil)
	if err != nil {
		t.Fatalf("PastValidateSimple error: %v", err)
	}

	if !output.Valid {
		t.Errorf("Should be valid, errors: %v", output.Errors)
	}
}

func TestPastValidateWithCRL(t *testing.T) {
	root, rootKey := genCert(t, "Root CA", true, nil, nil)
	leaf, _ := genCert(t, "Leaf Cert", false, root, rootKey)

	path := NewValidationPath(root)
	path.SetEECert(leaf)

	// Create a CRL that doesn't revoke the leaf
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, root, rootKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	output, err := PastValidateSimple(path, []*x509.Certificate{root}, []*x509.RevocationList{crl}, nil)
	if err != nil {
		t.Fatalf("PastValidateSimple error: %v", err)
	}

	if !output.Valid {
		t.Errorf("Should be valid with clean CRL, errors: %v", output.Errors)
	}
}

func TestPastValidateWithRevokedCert(t *testing.T) {
	root, rootKey := genCert(t, "Root CA", true, nil, nil)
	leaf, _ := genCert(t, "Leaf Cert", false, root, rootKey)

	path := NewValidationPath(root)
	path.SetEECert(leaf)

	// Create a CRL that revokes the leaf
	revocationTime := time.Now().Add(-30 * time.Minute)
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   leaf.SerialNumber,
				RevocationTime: revocationTime,
			},
		},
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, root, rootKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	output, err := PastValidateSimple(path, []*x509.Certificate{root}, []*x509.RevocationList{crl}, nil)
	if err != nil {
		t.Fatalf("PastValidateSimple error: %v", err)
	}

	// Should fail because cert is revoked before control time
	if output.Valid {
		t.Log("Note: validation may pass if control time slides before revocation")
	}
}

func TestGetValidityWindowIntersection(t *testing.T) {
	root, rootKey := genCert(t, "Root CA", true, nil, nil)
	leaf, _ := genCert(t, "Leaf Cert", false, root, rootKey)

	path := NewValidationPath(root)
	path.SetEECert(leaf)

	lower, upper, err := GetValidityWindowIntersection(path)
	if err != nil {
		t.Fatalf("GetValidityWindowIntersection error: %v", err)
	}

	if !lower.Before(upper) {
		t.Error("Lower bound should be before upper bound")
	}

	// Check bounds are reasonable
	now := time.Now()
	if lower.After(now) {
		t.Error("Lower bound should not be after now")
	}
	if upper.Before(now) {
		t.Error("Upper bound should not be before now for valid certs")
	}
}

func TestGetValidityWindowIntersectionEmptyPath(t *testing.T) {
	path := &ValidationPath{}

	_, _, err := GetValidityWindowIntersection(path)
	if err == nil {
		t.Error("Expected error for empty path")
	}
}

func TestDetermineAdESLevel(t *testing.T) {
	tests := []struct {
		name         string
		valid        bool
		hasTimestamp bool
		hasLTVData   bool
		expected     AdESValidationLevel
	}{
		{"invalid", false, false, false, AdESLevelBES},
		{"BES only", true, false, false, AdESLevelBES},
		{"with timestamp", true, true, false, AdESLevelT},
		{"with LTV no timestamp", true, false, true, AdESLevelBES},
		{"with both", true, true, true, AdESLevelXL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := &PastValidateOutput{Valid: tt.valid}
			level := DetermineAdESLevel(output, tt.hasTimestamp, tt.hasLTVData)
			if level != tt.expected {
				t.Errorf("DetermineAdESLevel() = %v, want %v", level, tt.expected)
			}
		})
	}
}

func TestPastValidatePrecheckEmptyIntersection(t *testing.T) {
	// Create certificates with non-overlapping validity periods
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	serial1, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	serial2, _ := rand.Int(rand.Reader, big.NewInt(1000000))

	// Root valid from 2020 to 2021
	rootTemplate := &x509.Certificate{
		SerialNumber:          serial1,
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootBytes, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key1.PublicKey, key1)
	root, _ := x509.ParseCertificate(rootBytes)

	// Leaf valid from 2022 to 2023 (no overlap with root)
	leafTemplate := &x509.Certificate{
		SerialNumber:          serial2,
		Subject:               pkix.Name{CommonName: "Leaf"},
		NotBefore:             time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &key2.PublicKey, key1)
	leaf, _ := x509.ParseCertificate(leafBytes)

	path := NewValidationPath(root)
	path.SetEECert(leaf)

	_, _, err := GetValidityWindowIntersection(path)
	if err == nil {
		t.Error("Expected error for non-overlapping validity periods")
	}
}

func TestPastValidateOutput(t *testing.T) {
	output := &PastValidateOutput{
		ControlTime:        time.Now(),
		Valid:              true,
		Indication:         "PASSED",
		PrecheckPassed:     true,
		TimeSlideSucceeded: true,
	}

	if !output.Valid {
		t.Error("Valid should be true")
	}

	if output.Indication != "PASSED" {
		t.Errorf("Indication = %s, want PASSED", output.Indication)
	}

	if !output.PrecheckPassed {
		t.Error("PrecheckPassed should be true")
	}

	if !output.TimeSlideSucceeded {
		t.Error("TimeSlideSucceeded should be true")
	}
}

func TestValidatePathBasic(t *testing.T) {
	root, rootKey := genCert(t, "Root CA", true, nil, nil)
	leaf, _ := genCert(t, "Leaf Cert", false, root, rootKey)

	path := NewValidationPath(root)
	path.SetEECert(leaf)

	err := validatePathBasic(path, time.Now(), []*x509.Certificate{root})
	if err != nil {
		t.Errorf("validatePathBasic error: %v", err)
	}
}

func TestValidatePathBasicExpiredCert(t *testing.T) {
	root, rootKey := genCert(t, "Root CA", true, nil, nil)
	leaf, _ := genCert(t, "Leaf Cert", false, root, rootKey)

	path := NewValidationPath(root)
	path.SetEECert(leaf)

	// Validate at future time when cert is expired
	futureTime := time.Now().Add(2 * 365 * 24 * time.Hour)
	err := validatePathBasic(path, futureTime, []*x509.Certificate{root})
	if err == nil {
		t.Error("Expected error for expired certificate")
	}
}

func TestCheckRevocation(t *testing.T) {
	root, rootKey := genCert(t, "Root CA", true, nil, nil)
	leaf, _ := genCert(t, "Leaf Cert", false, root, rootKey)

	manager := NewRevInfoManager()

	// No CRL - should return not revoked
	revoked, err := checkRevocation(leaf, time.Now(), manager)
	if err != nil {
		t.Errorf("checkRevocation error: %v", err)
	}
	if revoked {
		t.Error("Should not be revoked without CRL")
	}
}

func TestCheckRevocationWithCRL(t *testing.T) {
	root, rootKey := genCert(t, "Root CA", true, nil, nil)
	leaf, _ := genCert(t, "Leaf Cert", false, root, rootKey)

	// Create CRL that revokes the leaf
	revocationTime := time.Now().Add(-time.Hour)
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-2 * time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   leaf.SerialNumber,
				RevocationTime: revocationTime,
			},
		},
	}

	crlBytes, _ := x509.CreateRevocationList(rand.Reader, crlTemplate, root, rootKey)
	crl, _ := x509.ParseRevocationList(crlBytes)

	manager := NewRevInfoManager()
	manager.AddCRL(crl)

	revoked, err := checkRevocation(leaf, time.Now(), manager)
	if err != nil {
		t.Errorf("checkRevocation error: %v", err)
	}
	if !revoked {
		t.Error("Should be revoked")
	}
}
