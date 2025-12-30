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

// genTestCert generates a test certificate for testing.
func genTestCert(t *testing.T, cn string, isCA bool, issuer *x509.Certificate, issuerKey interface{}) (*x509.Certificate, *ecdsa.PrivateKey) {
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

func TestValidationTimingInfo(t *testing.T) {
	info := ValidationTimingInfo{}.Now()

	if info.ValidationTime.IsZero() {
		t.Error("ValidationTime should not be zero")
	}

	if info.BestSignatureTime.IsZero() {
		t.Error("BestSignatureTime should not be zero")
	}

	if info.PointInTimeValidation {
		t.Error("PointInTimeValidation should be false for Now()")
	}
}

func TestValidationTimingParams(t *testing.T) {
	now := time.Now()
	params := &ValidationTimingParams{
		TimingInfo: ValidationTimingInfo{
			ValidationTime:        now,
			BestSignatureTime:     now.Add(-time.Hour),
			PointInTimeValidation: true,
		},
		TimeTolerance: time.Minute,
	}

	if !params.ValidationTime().Equal(now) {
		t.Error("ValidationTime() should return correct time")
	}

	if !params.BestSignatureTime().Equal(now.Add(-time.Hour)) {
		t.Error("BestSignatureTime() should return correct time")
	}

	if !params.PointInTimeValidation() {
		t.Error("PointInTimeValidation() should return true")
	}
}

func TestRevinfoUsabilityRating(t *testing.T) {
	tests := []struct {
		rating   RevinfoUsabilityRating
		expected string
		usable   bool
	}{
		{RevinfoUsabilityUnknown, "unknown", false},
		{RevinfoUsabilityUsable, "usable", true},
		{RevinfoUsabilityStale, "stale", false},
		{RevinfoUsabilityTooNew, "too_new", false},
		{RevinfoUsabilityExpired, "expired", false},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.rating.String() != tt.expected {
				t.Errorf("String() = %s, want %s", tt.rating.String(), tt.expected)
			}
			if tt.rating.UsableAdES() != tt.usable {
				t.Errorf("UsableAdES() = %v, want %v", tt.rating.UsableAdES(), tt.usable)
			}
		})
	}
}

func TestRevinfoContainerUsableAt(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		issued   *time.Time
		next     *time.Time
		valTime  time.Time
		expected RevinfoUsabilityRating
	}{
		{
			name:     "usable",
			issued:   timePtr(now.Add(-time.Hour)),
			next:     timePtr(now.Add(time.Hour)),
			valTime:  now,
			expected: RevinfoUsabilityUsable,
		},
		{
			name:     "too new",
			issued:   timePtr(now.Add(time.Hour)),
			next:     timePtr(now.Add(2 * time.Hour)),
			valTime:  now,
			expected: RevinfoUsabilityTooNew,
		},
		{
			name:     "expired",
			issued:   timePtr(now.Add(-2 * time.Hour)),
			next:     timePtr(now.Add(-time.Hour)),
			valTime:  now,
			expected: RevinfoUsabilityExpired,
		},
		{
			name:     "no issuance date",
			issued:   nil,
			next:     timePtr(now.Add(time.Hour)),
			valTime:  now,
			expected: RevinfoUsabilityUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			container := &RevinfoContainer{
				IssuanceDate: tt.issued,
				NextUpdate:   tt.next,
			}
			params := &ValidationTimingParams{
				TimingInfo: ValidationTimingInfo{
					ValidationTime:        tt.valTime,
					BestSignatureTime:     tt.valTime,
					PointInTimeValidation: true,
				},
				TimeTolerance: time.Minute,
			}

			usability := container.UsableAt(params)
			if usability.Rating != tt.expected {
				t.Errorf("UsableAt() rating = %v, want %v", usability.Rating, tt.expected)
			}
		})
	}
}

func TestDefaultAlgorithmUsagePolicy(t *testing.T) {
	policy := NewDefaultAlgorithmUsagePolicy()

	// Test allowed algorithm
	constraint := policy.SignatureAlgorithmAllowed("SHA256-RSA", time.Now(), nil)
	if !constraint.Allowed {
		t.Error("SHA256-RSA should be allowed")
	}

	// Test permanently banned algorithm
	constraint = policy.SignatureAlgorithmAllowed("MD5-RSA", time.Now(), nil)
	if constraint.Allowed {
		t.Error("MD5-RSA should not be allowed")
	}

	// Test time-limited banned algorithm (before ban date)
	beforeBan := time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)
	constraint = policy.SignatureAlgorithmAllowed("SHA1-RSA", beforeBan, nil)
	if !constraint.Allowed {
		t.Error("SHA1-RSA should be allowed before 2017")
	}

	// Test time-limited banned algorithm (after ban date)
	afterBan := time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	constraint = policy.SignatureAlgorithmAllowed("SHA1-RSA", afterBan, nil)
	if constraint.Allowed {
		t.Error("SHA1-RSA should not be allowed after 2017")
	}
	if constraint.NotAllowedAfter == nil {
		t.Error("NotAllowedAfter should be set")
	}
}

func TestRevocationCheckingRule(t *testing.T) {
	rule := DefaultRevocationCheckingRule()

	if !rule.OCSPRelevant {
		t.Error("OCSPRelevant should be true by default")
	}
	if !rule.CRLRelevant {
		t.Error("CRLRelevant should be true by default")
	}
	if !rule.RequireRevocationInfo {
		t.Error("RequireRevocationInfo should be true by default")
	}
	if !rule.AllowNoRevCheck {
		t.Error("AllowNoRevCheck should be true by default")
	}
}

func TestNewTimeSlideContext(t *testing.T) {
	ctx := NewTimeSlideContext(nil)

	if ctx.POEManager == nil {
		t.Error("POEManager should not be nil")
	}
	if ctx.RevTrustPolicy == nil {
		t.Error("RevTrustPolicy should not be nil")
	}
	if ctx.AlgoPolicy == nil {
		t.Error("AlgoPolicy should not be nil")
	}
	if ctx.TimeTolerance != time.Minute {
		t.Errorf("TimeTolerance = %v, want 1m", ctx.TimeTolerance)
	}
}

func TestTimeSlideEmptyPath(t *testing.T) {
	path := &ValidationPath{}
	ctx := NewTimeSlideContext(nil)

	input := &TimeSlideInput{
		Path:            path,
		InitControlTime: time.Now(),
		Context:         ctx,
	}

	output, err := TimeSlide(input)
	if err != nil {
		t.Fatalf("TimeSlide error: %v", err)
	}

	if !output.Success {
		t.Error("Empty path should succeed")
	}
}

func TestTimeSlideNilInput(t *testing.T) {
	_, err := TimeSlide(nil)
	if err == nil {
		t.Error("Expected error for nil input")
	}

	_, err = TimeSlide(&TimeSlideInput{Path: nil})
	if err == nil {
		t.Error("Expected error for nil path")
	}
}

func TestTimeSlideWithTrustAnchorOnly(t *testing.T) {
	root, _ := genTestCert(t, "Root CA", true, nil, nil)

	path := NewValidationPath(root)
	ctx := NewTimeSlideContext(nil)

	input := &TimeSlideInput{
		Path:            path,
		InitControlTime: time.Now(),
		Context:         ctx,
	}

	output, err := TimeSlide(input)
	if err != nil {
		t.Fatalf("TimeSlide error: %v", err)
	}

	if !output.Success {
		t.Error("Trust anchor only path should succeed")
	}

	// Trust anchor alone should succeed (no status entries needed for anchor-only)
}

func TestTimeSlideWithSimplePath(t *testing.T) {
	root, rootKey := genTestCert(t, "Root CA", true, nil, nil)
	leaf, _ := genTestCert(t, "Leaf Cert", false, root, rootKey)

	path := NewValidationPath(root)
	path.SetEECert(leaf)

	ctx := NewTimeSlideContext(nil)
	// Disable revocation checking for this test
	ctx.RevTrustPolicy.RevocationCheckingPolicy.EECertificateRule.RequireRevocationInfo = false
	ctx.RevTrustPolicy.RevocationCheckingPolicy.IntermediateCACertRule.RequireRevocationInfo = false

	input := &TimeSlideInput{
		Path:            path,
		InitControlTime: time.Now(),
		Context:         ctx,
	}

	output, err := TimeSlide(input)
	if err != nil {
		t.Fatalf("TimeSlide error: %v", err)
	}

	if !output.Success {
		t.Errorf("Simple path should succeed, errors: %v", output.Errors)
	}
}

func TestTimeSlideWithPOEConstraint(t *testing.T) {
	root, rootKey := genTestCert(t, "Root CA", true, nil, nil)
	leaf, _ := genTestCert(t, "Leaf Cert", false, root, rootKey)

	path := NewValidationPath(root)
	path.SetEECert(leaf)

	poeManager := NewPOEManager()
	// Add POE that's in the future
	futureTime := time.Now().Add(time.Hour)
	poeManager.Add(&ProofOfExistence{
		Time:     futureTime,
		Type:     POETypeTimestamp,
		DataHash: leaf.Raw,
	})

	ctx := NewTimeSlideContext(poeManager)
	ctx.RevTrustPolicy.RevocationCheckingPolicy.EECertificateRule.RequireRevocationInfo = false

	controlTime := time.Now()
	input := &TimeSlideInput{
		Path:            path,
		InitControlTime: controlTime,
		Context:         ctx,
	}

	output, err := TimeSlide(input)
	if err != nil {
		t.Fatalf("TimeSlide error: %v", err)
	}

	if output.Success {
		t.Error("Should fail due to POE constraint")
	}
}

func TestTimeSlideWithCRL(t *testing.T) {
	root, rootKey := genTestCert(t, "Root CA", true, nil, nil)
	leaf, _ := genTestCert(t, "Leaf Cert", false, root, rootKey)

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

	ctx := NewTimeSlideContext(nil)
	ctx.AddCRL(crl, root)

	input := &TimeSlideInput{
		Path:            path,
		InitControlTime: time.Now(),
		Context:         ctx,
	}

	output, err := TimeSlide(input)
	if err != nil {
		t.Fatalf("TimeSlide error: %v", err)
	}

	if !output.Success {
		t.Errorf("Should succeed with valid CRL, errors: %v", output.Errors)
	}

	// Note: RevinfoUsed may be empty if the CRL wasn't in scope for the leaf cert
	// The important thing is that we have CRL available and no errors
}

func TestTimeSlideWithRevokedCert(t *testing.T) {
	root, rootKey := genTestCert(t, "Root CA", true, nil, nil)
	leaf, _ := genTestCert(t, "Leaf Cert", false, root, rootKey)

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

	ctx := NewTimeSlideContext(nil)
	ctx.AddCRL(crl, root)

	controlTime := time.Now()
	input := &TimeSlideInput{
		Path:            path,
		InitControlTime: controlTime,
		Context:         ctx,
	}

	output, err := TimeSlide(input)
	if err != nil {
		t.Fatalf("TimeSlide error: %v", err)
	}

	// Should succeed but slide time back to revocation time
	if !output.Success {
		t.Errorf("Should succeed (sliding time back), errors: %v", output.Errors)
	}

	if output.ControlTime.After(revocationTime) {
		t.Errorf("Control time should be <= revocation time, got %v, want <= %v",
			output.ControlTime, revocationTime)
	}
}

func TestTimeSlideWithDefaults(t *testing.T) {
	root, _ := genTestCert(t, "Root CA", true, nil, nil)
	path := NewValidationPath(root)

	output, err := TimeSlideWithDefaults(path, time.Now(), nil)
	if err != nil {
		t.Fatalf("TimeSlideWithDefaults error: %v", err)
	}

	if !output.Success {
		t.Error("Should succeed with defaults")
	}
}

func TestGatherPrimaFacieRevinfo(t *testing.T) {
	root, _ := genTestCert(t, "Root CA", true, nil, nil)
	path := NewValidationPath(root)

	ctx := NewTimeSlideContext(nil)

	now := time.Now()
	pastTime := now.Add(-time.Hour)
	futureTime := now.Add(time.Hour)

	// Add CRLs - one past, one future
	ctx.CRLs = []*CRLOfInterest{
		{IssuanceDate: &pastTime},
		{IssuanceDate: &futureTime},
	}

	// Add OCSP responses - one past, one future
	ctx.OCSPs = []*OCSPResponseOfInterest{
		{IssuanceDate: &pastTime},
		{IssuanceDate: &futureTime},
	}

	rule := DefaultRevocationCheckingRule()
	crls, ocsps := GatherPrimaFacieRevinfo(path, ctx, now, rule)

	// Should only get past ones
	if len(crls) != 1 {
		t.Errorf("Expected 1 CRL, got %d", len(crls))
	}
	if len(ocsps) != 1 {
		t.Errorf("Expected 1 OCSP, got %d", len(ocsps))
	}
}

func TestPastValidatePrecheck(t *testing.T) {
	root, rootKey := genTestCert(t, "Root CA", true, nil, nil)
	leaf, _ := genTestCert(t, "Leaf Cert", false, root, rootKey)

	path := NewValidationPath(root)
	path.SetEECert(leaf)

	poeManager := NewPOEManager()

	// Should pass without constraints
	result, err := PastValidatePrecheck(path, time.Now(), poeManager)
	if err != nil {
		t.Fatalf("PastValidatePrecheck error: %v", err)
	}
	if !result.Passed {
		t.Errorf("Should pass, got failure: %s", result.FailureReason)
	}

	// Add POE in the future - should fail
	futureTime := time.Now().Add(time.Hour)
	poeManager.Add(&ProofOfExistence{
		Time:     futureTime,
		Type:     POETypeTimestamp,
		DataHash: leaf.Raw,
	})

	result, err = PastValidatePrecheck(path, time.Now(), poeManager)
	if err != nil {
		t.Fatalf("PastValidatePrecheck error: %v", err)
	}
	if result.Passed {
		t.Error("Should fail due to POE constraint")
	}
	if result.SuggestedControlTime == nil {
		t.Error("Should suggest a control time")
	}
}

func TestPastValidatePrecheckBeforeValidity(t *testing.T) {
	root, rootKey := genTestCert(t, "Root CA", true, nil, nil)
	leaf, _ := genTestCert(t, "Leaf Cert", false, root, rootKey)

	path := NewValidationPath(root)
	path.SetEECert(leaf)

	poeManager := NewPOEManager()

	// Control time before certificate validity
	controlTime := leaf.NotBefore.Add(-time.Hour)

	result, err := PastValidatePrecheck(path, controlTime, poeManager)
	if err != nil {
		t.Fatalf("PastValidatePrecheck error: %v", err)
	}
	if result.Passed {
		t.Error("Should fail when control time is before certificate validity")
	}
}

func TestAddCRL(t *testing.T) {
	root, rootKey := genTestCert(t, "Root CA", true, nil, nil)

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

	ctx := NewTimeSlideContext(nil)
	ctx.AddCRL(crl, root)

	if len(ctx.CRLs) != 1 {
		t.Errorf("Expected 1 CRL, got %d", len(ctx.CRLs))
	}

	if ctx.CRLs[0].Container == nil {
		t.Error("CRL container should not be nil")
	}

	if ctx.CRLs[0].Container.Type != "CRL" {
		t.Errorf("Container type = %s, want CRL", ctx.CRLs[0].Container.Type)
	}
}

func TestAddOCSPResponse(t *testing.T) {
	root, _ := genTestCert(t, "Root CA", true, nil, nil)

	ctx := NewTimeSlideContext(nil)
	now := time.Now()
	nextUpdate := now.Add(time.Hour)

	ctx.AddOCSPResponse([]byte("test ocsp"), now, &nextUpdate, root)

	if len(ctx.OCSPs) != 1 {
		t.Errorf("Expected 1 OCSP, got %d", len(ctx.OCSPs))
	}

	if ctx.OCSPs[0].OCSPResponse == nil {
		t.Error("OCSP response should not be nil")
	}

	if ctx.OCSPs[0].OCSPResponse.Type != "OCSP" {
		t.Errorf("Container type = %s, want OCSP", ctx.OCSPs[0].OCSPResponse.Type)
	}
}

func TestValidationPathMethods(t *testing.T) {
	root, rootKey := genTestCert(t, "Root CA", true, nil, nil)
	intermediate, intKey := genTestCert(t, "Intermediate CA", true, root, rootKey)
	leaf, _ := genTestCert(t, "Leaf Cert", false, intermediate, intKey)

	path := NewValidationPath(root)
	path.AddIntermediate(intermediate)
	path.SetEECert(leaf)

	if path.PKIXLen() != 2 {
		t.Errorf("PKIXLen() = %d, want 2", path.PKIXLen())
	}

	allCerts := path.AllCerts()
	if len(allCerts) != 3 {
		t.Errorf("AllCerts() len = %d, want 3", len(allCerts))
	}

	if path.Leaf() != leaf {
		t.Error("Leaf() should return the EE cert")
	}
}

func TestHasOCSPNoCheck(t *testing.T) {
	// Test with regular certificate (no OCSP noCheck)
	cert, _ := genTestCert(t, "Test Cert", false, nil, nil)

	if hasOCSPNoCheck(cert) {
		t.Error("Regular cert should not have OCSP noCheck")
	}
}

func TestApplyAlgorithmPolicy(t *testing.T) {
	policy := NewDefaultAlgorithmUsagePolicy()

	// Allowed algorithm - no time change
	controlTime := time.Now()
	newTime, err := applyAlgorithmPolicy(policy, "SHA256-RSA", controlTime, nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !newTime.Equal(controlTime) {
		t.Error("Control time should not change for allowed algorithm")
	}

	// Banned algorithm after date - time should slide back
	afterBan := time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	newTime, err = applyAlgorithmPolicy(policy, "SHA1-RSA", afterBan, nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !newTime.Before(afterBan) {
		t.Error("Control time should slide back for time-banned algorithm")
	}

	// Permanently banned algorithm - should error
	_, err = applyAlgorithmPolicy(policy, "MD5-RSA", controlTime, nil)
	if err == nil {
		t.Error("Expected error for permanently banned algorithm")
	}
}

// Helper function to create time pointers
func timePtr(t time.Time) *time.Time {
	return &t
}
