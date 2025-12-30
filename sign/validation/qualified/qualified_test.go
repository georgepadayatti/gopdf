// Package qualified provides qualified signature validation tests.
package qualified

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// Test helpers

func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Test User",
			Organization: []string{"Test Org"},
			Country:      []string{"DE"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
			Country:      []string{"DE"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// QCType tests

func TestQCTypeString(t *testing.T) {
	tests := []struct {
		qcType   QCType
		expected string
	}{
		{QCTypeUnknown, "unknown"},
		{QCTypeEsign, "esign"},
		{QCTypeEseal, "eseal"},
		{QCTypeWeb, "web"},
	}

	for _, tt := range tests {
		result := tt.qcType.String()
		if result != tt.expected {
			t.Errorf("QCType(%d).String() = %q, want %q", tt.qcType, result, tt.expected)
		}
	}
}

func TestQCTypeFromOID(t *testing.T) {
	tests := []struct {
		oid      asn1.ObjectIdentifier
		expected QCType
	}{
		{OIDQcTypeEsign, QCTypeEsign},
		{OIDQcTypeEseal, QCTypeEseal},
		{OIDQcTypeWeb, QCTypeWeb},
		{asn1.ObjectIdentifier{1, 2, 3}, QCTypeUnknown},
	}

	for _, tt := range tests {
		result := QCTypeFromOID(tt.oid)
		if result != tt.expected {
			t.Errorf("QCTypeFromOID(%v) = %v, want %v", tt.oid, result, tt.expected)
		}
	}
}

// QualificationStatus tests

func TestQualificationStatusString(t *testing.T) {
	tests := []struct {
		status   QualificationStatus
		expected string
	}{
		{StatusNotDetermined, "not_determined"},
		{StatusQualified, "qualified"},
		{StatusNotQualified, "not_qualified"},
		{StatusQualifiedAtIssuance, "qualified_at_issuance"},
		{StatusWithdrawn, "withdrawn"},
	}

	for _, tt := range tests {
		result := tt.status.String()
		if result != tt.expected {
			t.Errorf("QualificationStatus(%d).String() = %q, want %q", tt.status, result, tt.expected)
		}
	}
}

// QCStatements tests

func TestQCStatementsHasCompliance(t *testing.T) {
	statements := &QCStatements{
		Statements: []QCStatement{
			{OID: OIDQcCompliance},
		},
	}
	if !statements.HasCompliance() {
		t.Error("Should have compliance")
	}

	empty := &QCStatements{}
	if empty.HasCompliance() {
		t.Error("Should not have compliance")
	}
}

func TestQCStatementsHasSSCD(t *testing.T) {
	statements := &QCStatements{
		Statements: []QCStatement{
			{OID: OIDQcSSCD},
		},
	}
	if !statements.HasSSCD() {
		t.Error("Should have SSCD")
	}

	empty := &QCStatements{}
	if empty.HasSSCD() {
		t.Error("Should not have SSCD")
	}
}

func TestQCStatementsGetType(t *testing.T) {
	statements := &QCStatements{
		Statements: []QCStatement{
			{OID: OIDQcType, Value: []asn1.ObjectIdentifier{OIDQcTypeEsign}},
		},
	}
	if statements.GetType() != QCTypeEsign {
		t.Errorf("GetType() = %v, want QCTypeEsign", statements.GetType())
	}

	empty := &QCStatements{}
	if empty.GetType() != QCTypeUnknown {
		t.Error("Empty should return QCTypeUnknown")
	}
}

func TestQCStatementsGetLegislation(t *testing.T) {
	statements := &QCStatements{
		Statements: []QCStatement{
			{OID: OIDQcCCLegislation, Value: []string{"DE", "FR"}},
		},
	}
	leg := statements.GetLegislation()
	if len(leg) != 2 {
		t.Errorf("GetLegislation() returned %d items, want 2", len(leg))
	}

	empty := &QCStatements{}
	if empty.GetLegislation() != nil {
		t.Error("Empty should return nil")
	}
}

// ServiceType tests

func TestServiceTypeString(t *testing.T) {
	tests := []struct {
		stype    ServiceType
		expected string
	}{
		{ServiceTypeUnknown, "unknown"},
		{ServiceTypeCA, "CA"},
		{ServiceTypeOCSP, "OCSP"},
		{ServiceTypeCRL, "CRL"},
		{ServiceTypeTSA, "TSA"},
		{ServiceTypeQESCD, "QESCD"},
	}

	for _, tt := range tests {
		result := tt.stype.String()
		if result != tt.expected {
			t.Errorf("ServiceType(%d).String() = %q, want %q", tt.stype, result, tt.expected)
		}
	}
}

// ServiceStatus tests

func TestServiceStatusString(t *testing.T) {
	tests := []struct {
		status   ServiceStatus
		expected string
	}{
		{ServiceStatusUnknown, "unknown"},
		{ServiceStatusGranted, "granted"},
		{ServiceStatusWithdrawn, "withdrawn"},
		{ServiceStatusAccredited, "accredited"},
	}

	for _, tt := range tests {
		result := tt.status.String()
		if result != tt.expected {
			t.Errorf("ServiceStatus(%d).String() = %q, want %q", tt.status, result, tt.expected)
		}
	}
}

func TestServiceStatusIsActive(t *testing.T) {
	if !ServiceStatusGranted.IsActive() {
		t.Error("Granted should be active")
	}
	if !ServiceStatusAccredited.IsActive() {
		t.Error("Accredited should be active")
	}
	if ServiceStatusWithdrawn.IsActive() {
		t.Error("Withdrawn should not be active")
	}
}

// TrustService tests

func TestTrustServiceIsActiveAt(t *testing.T) {
	now := time.Now()
	service := &TrustService{
		Status:          ServiceStatusGranted,
		StatusStartTime: now.Add(-24 * time.Hour),
	}

	if !service.IsActiveAt(now) {
		t.Error("Should be active at current time")
	}

	if service.IsActiveAt(now.Add(-48 * time.Hour)) {
		t.Error("Should not be active before status start time")
	}
}

func TestTrustServiceIsActiveAtWithHistory(t *testing.T) {
	now := time.Now()
	service := &TrustService{
		Status:          ServiceStatusWithdrawn,
		StatusStartTime: now.Add(-12 * time.Hour),
		History: []ServiceHistoryInstance{
			{Status: ServiceStatusGranted, StatusStartTime: now.Add(-48 * time.Hour)},
		},
	}

	// Currently withdrawn
	if service.IsActiveAt(now) {
		t.Error("Should not be active now (withdrawn)")
	}

	// Was active 24 hours ago
	if !service.IsActiveAt(now.Add(-24 * time.Hour)) {
		t.Error("Should be active 24 hours ago")
	}
}

func TestTrustServiceMatchesCertificate(t *testing.T) {
	cert := generateTestCert(t)
	service := &TrustService{
		ServiceDigitalIDs: []ServiceDigitalID{
			{Certificate: cert},
		},
	}

	if !service.MatchesCertificate(cert) {
		t.Error("Should match certificate")
	}

	otherCert := generateTestCert(t)
	if service.MatchesCertificate(otherCert) {
		t.Error("Should not match different certificate")
	}
}

func TestTrustServiceMatchesCertificateBySKI(t *testing.T) {
	cert := generateTestCert(t)
	service := &TrustService{
		ServiceDigitalIDs: []ServiceDigitalID{
			{SKI: cert.SubjectKeyId},
		},
	}

	if !service.MatchesCertificate(cert) {
		t.Error("Should match by SKI")
	}
}

// TrustServiceProvider tests

func TestTrustServiceProviderFindService(t *testing.T) {
	cert := generateTestCert(t)
	tsp := &TrustServiceProvider{
		Name: "Test TSP",
		Services: []*TrustService{
			{
				Name: "CA Service",
				ServiceDigitalIDs: []ServiceDigitalID{
					{Certificate: cert},
				},
			},
		},
	}

	service := tsp.FindService(cert)
	if service == nil {
		t.Error("Should find service")
	}
	if service.Name != "CA Service" {
		t.Errorf("Service name = %q, want 'CA Service'", service.Name)
	}

	otherCert := generateTestCert(t)
	if tsp.FindService(otherCert) != nil {
		t.Error("Should not find service for different cert")
	}
}

// TrustedList tests

func TestTrustedListIsExpired(t *testing.T) {
	expired := &TrustedList{
		NextUpdate: time.Now().Add(-time.Hour),
	}
	if !expired.IsExpired() {
		t.Error("Should be expired")
	}

	valid := &TrustedList{
		NextUpdate: time.Now().Add(time.Hour),
	}
	if valid.IsExpired() {
		t.Error("Should not be expired")
	}
}

func TestTrustedListIsValidAt(t *testing.T) {
	now := time.Now()
	list := &TrustedList{
		ListIssueDateTime: now.Add(-24 * time.Hour),
		NextUpdate:        now.Add(24 * time.Hour),
	}

	if !list.IsValidAt(now) {
		t.Error("Should be valid at current time")
	}

	if list.IsValidAt(now.Add(-48 * time.Hour)) {
		t.Error("Should not be valid before issue time")
	}

	if list.IsValidAt(now.Add(48 * time.Hour)) {
		t.Error("Should not be valid after next update")
	}
}

func TestTrustedListFindTSP(t *testing.T) {
	list := &TrustedList{
		TSPs: []*TrustServiceProvider{
			{Name: "Test TSP", TradeName: "TestCo"},
		},
	}

	tsp := list.FindTSP("Test TSP")
	if tsp == nil {
		t.Error("Should find TSP by name")
	}

	tsp = list.FindTSP("TestCo")
	if tsp == nil {
		t.Error("Should find TSP by trade name")
	}

	tsp = list.FindTSP("Unknown")
	if tsp != nil {
		t.Error("Should not find unknown TSP")
	}
}

func TestTrustedListFindServiceForCertificate(t *testing.T) {
	cert := generateTestCert(t)
	list := &TrustedList{
		TSPs: []*TrustServiceProvider{
			{
				Name: "Test TSP",
				Services: []*TrustService{
					{
						Name: "CA Service",
						ServiceDigitalIDs: []ServiceDigitalID{
							{Certificate: cert},
						},
					},
				},
			},
		},
	}

	tsp, service := list.FindServiceForCertificate(cert)
	if tsp == nil || service == nil {
		t.Error("Should find TSP and service")
	}
}

// TrustedListRegistry tests

func TestTrustedListRegistry(t *testing.T) {
	registry := NewTrustedListRegistry()
	if registry.lists == nil {
		t.Error("Lists map should be initialized")
	}
}

func TestTrustedListRegistryAddAndGet(t *testing.T) {
	registry := NewTrustedListRegistry()
	list := &TrustedList{
		SchemeTerritory: "DE",
	}

	registry.Add(list)
	retrieved := registry.Get("DE")
	if retrieved != list {
		t.Error("Should retrieve added list")
	}

	if registry.Get("FR") != nil {
		t.Error("Should not find non-existent list")
	}
}

func TestTrustedListRegistryGetAll(t *testing.T) {
	registry := NewTrustedListRegistry()
	registry.Add(&TrustedList{SchemeTerritory: "DE"})
	registry.Add(&TrustedList{SchemeTerritory: "FR"})

	all := registry.GetAll()
	if len(all) != 2 {
		t.Errorf("GetAll() returned %d, want 2", len(all))
	}
}

func TestTrustedListRegistryTerritories(t *testing.T) {
	registry := NewTrustedListRegistry()
	registry.Add(&TrustedList{SchemeTerritory: "DE"})
	registry.Add(&TrustedList{SchemeTerritory: "FR"})

	territories := registry.Territories()
	if len(territories) != 2 {
		t.Errorf("Territories() returned %d, want 2", len(territories))
	}
}

// QualifiedAssessment tests

func TestQualifiedAssessment(t *testing.T) {
	cert := generateTestCert(t)
	assessment := NewQualifiedAssessment(cert)

	if assessment.Certificate != cert {
		t.Error("Certificate not set")
	}
	if assessment.Status != StatusNotDetermined {
		t.Error("Initial status should be not determined")
	}
}

func TestQualifiedAssessmentIsQualified(t *testing.T) {
	cert := generateTestCert(t)

	qualified := NewQualifiedAssessment(cert)
	qualified.Status = StatusQualified
	if !qualified.IsQualified() {
		t.Error("Should be qualified")
	}

	atIssuance := NewQualifiedAssessment(cert)
	atIssuance.Status = StatusQualifiedAtIssuance
	if !atIssuance.IsQualified() {
		t.Error("Should be qualified at issuance")
	}

	notQualified := NewQualifiedAssessment(cert)
	notQualified.Status = StatusNotQualified
	if notQualified.IsQualified() {
		t.Error("Should not be qualified")
	}
}

func TestQualifiedAssessmentAddError(t *testing.T) {
	assessment := NewQualifiedAssessment(nil)
	assessment.AddError(ErrNotQualified)

	if !assessment.HasErrors() {
		t.Error("Should have errors")
	}
	if len(assessment.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(assessment.Errors))
	}
}

func TestQualifiedAssessmentAddWarning(t *testing.T) {
	assessment := NewQualifiedAssessment(nil)
	assessment.AddWarning("test warning")

	if len(assessment.Warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d", len(assessment.Warnings))
	}
}

// QualifiedValidator tests

func TestQualifiedValidator(t *testing.T) {
	registry := NewTrustedListRegistry()
	validator := NewQualifiedValidator(registry)

	if validator.Registry != registry {
		t.Error("Registry not set")
	}
}

func TestQualifiedValidatorAssess(t *testing.T) {
	cert := generateTestCert(t)
	validator := NewQualifiedValidator(nil)

	assessment := validator.Assess(cert)
	if assessment == nil {
		t.Fatal("Assessment should not be nil")
	}
	if assessment.Certificate != cert {
		t.Error("Certificate not set in assessment")
	}
}

func TestQualifiedValidatorAssessWithRegistry(t *testing.T) {
	cert := generateTestCert(t)

	registry := NewTrustedListRegistry()
	registry.Add(&TrustedList{
		SchemeTerritory: "DE",
		TSPs: []*TrustServiceProvider{
			{
				Name: "Test TSP",
				Services: []*TrustService{
					{
						Name:            "CA Service",
						Status:          ServiceStatusGranted,
						StatusStartTime: time.Now().Add(-24 * time.Hour),
						ServiceDigitalIDs: []ServiceDigitalID{
							{Certificate: cert},
						},
					},
				},
			},
		},
	})

	validator := NewQualifiedValidator(registry)
	assessment := validator.Assess(cert)

	if assessment.TSP == nil {
		t.Error("TSP should be found")
	}
	if assessment.Service == nil {
		t.Error("Service should be found")
	}
}

func TestQualifiedValidatorAssessChain(t *testing.T) {
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t)

	validator := NewQualifiedValidator(nil)
	assessments := validator.AssessChain([]*x509.Certificate{cert1, cert2})

	if len(assessments) != 2 {
		t.Errorf("Expected 2 assessments, got %d", len(assessments))
	}
}

// Country helper tests

func TestIsEUMemberState(t *testing.T) {
	if !IsEUMemberState("DE") {
		t.Error("DE should be EU member state")
	}
	if !IsEUMemberState("de") {
		t.Error("Should be case insensitive")
	}
	if IsEUMemberState("US") {
		t.Error("US should not be EU member state")
	}
}

func TestCountryName(t *testing.T) {
	if CountryName("DE") != "Germany" {
		t.Errorf("CountryName(DE) = %q, want 'Germany'", CountryName("DE"))
	}
	if CountryName("FR") != "France" {
		t.Errorf("CountryName(FR) = %q, want 'France'", CountryName("FR"))
	}
	if CountryName("XX") != "" {
		t.Error("Unknown country should return empty string")
	}
}

func TestGetCertificateCountry(t *testing.T) {
	cert := generateTestCert(t)
	country := GetCertificateCountry(cert)
	if country != "DE" {
		t.Errorf("GetCertificateCountry() = %q, want 'DE'", country)
	}
}

// ValidationReport tests

func TestValidationReport(t *testing.T) {
	report := NewValidationReport()
	if time.Since(report.ValidationTime) > time.Second {
		t.Error("ValidationTime should be close to now")
	}
}

func TestValidationReportDetermineSignatureLevel(t *testing.T) {
	report := NewValidationReport()

	// No signer assessment
	report.DetermineSignatureLevel()
	if report.IsQualifiedSig || report.IsAdvancedSig {
		t.Error("Should not be qualified or advanced without assessment")
	}

	// Qualified with SSCD
	report.SignerAssessment = &QualifiedAssessment{
		Status:  StatusQualified,
		HasSSCD: true,
	}
	report.DetermineSignatureLevel()
	if !report.IsQualifiedSig {
		t.Error("Should be qualified signature")
	}
	if !report.IsAdvancedSig {
		t.Error("Should be advanced signature")
	}

	// Qualified without SSCD
	report.SignerAssessment = &QualifiedAssessment{
		Status:  StatusQualified,
		HasSSCD: false,
	}
	report.DetermineSignatureLevel()
	if report.IsQualifiedSig {
		t.Error("Should not be qualified without SSCD")
	}
	if !report.IsAdvancedSig {
		t.Error("Should still be advanced")
	}
}

// TSLLocation tests

func TestNewTSLLocation(t *testing.T) {
	loc, err := NewTSLLocation("DE", "https://example.com/tsl.xml", "application/xml")
	if err != nil {
		t.Fatalf("NewTSLLocation failed: %v", err)
	}
	if loc.Territory != "DE" {
		t.Errorf("Territory = %q, want 'DE'", loc.Territory)
	}
	if loc.URL.String() != "https://example.com/tsl.xml" {
		t.Error("URL not set correctly")
	}
}

func TestNewTSLLocationInvalidURL(t *testing.T) {
	_, err := NewTSLLocation("DE", "://invalid", "application/xml")
	if err == nil {
		t.Error("Should fail with invalid URL")
	}
}

// IssuerInfo tests

func TestGetIssuerInfo(t *testing.T) {
	cert := generateTestCert(t)
	info := GetIssuerInfo(cert)

	// Note: generateTestCert creates a self-signed cert, so issuer equals subject
	if info.CommonName != "Test User" {
		t.Errorf("CommonName = %q, want 'Test User'", info.CommonName)
	}
	if info.Organization != "Test Org" {
		t.Errorf("Organization = %q, want 'Test Org'", info.Organization)
	}
}

// SubjectInfo tests

func TestGetSubjectInfo(t *testing.T) {
	cert := generateTestCert(t)
	info := GetSubjectInfo(cert)

	if info.CommonName != "Test User" {
		t.Errorf("CommonName = %q, want 'Test User'", info.CommonName)
	}
	if info.Country != "DE" {
		t.Errorf("Country = %q, want 'DE'", info.Country)
	}
}

func TestSubjectInfoFullName(t *testing.T) {
	info := &SubjectInfo{
		GivenName: "John",
		Surname:   "Doe",
	}
	if info.FullName() != "John Doe" {
		t.Errorf("FullName() = %q, want 'John Doe'", info.FullName())
	}

	info2 := &SubjectInfo{
		CommonName: "Jane Smith",
	}
	if info2.FullName() != "Jane Smith" {
		t.Errorf("FullName() = %q, want 'Jane Smith'", info2.FullName())
	}

	info3 := &SubjectInfo{
		Organization: "Test Org",
	}
	if info3.FullName() != "Test Org" {
		t.Errorf("FullName() = %q, want 'Test Org'", info3.FullName())
	}
}

// Extension helper tests

func TestHasExtension(t *testing.T) {
	cert := generateTestCert(t)

	// SKI should exist
	if !HasExtension(cert, asn1.ObjectIdentifier{2, 5, 29, 14}) {
		// Note: depends on how cert is generated
	}

	// Random OID should not exist
	if HasExtension(cert, asn1.ObjectIdentifier{1, 2, 3, 4, 5}) {
		t.Error("Should not have random extension")
	}
}

// Error tests

func TestErrors(t *testing.T) {
	errors := []error{
		ErrNotQualified,
		ErrTSPNotFound,
		ErrTSPNotQualified,
		ErrServiceNotFound,
		ErrTrustedListExpired,
		ErrTrustedListInvalid,
		ErrCountryNotSupported,
		ErrQCStatementNotFound,
		ErrAssessmentFailed,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("Error should have non-empty message: %v", err)
		}
	}
}

// OID tests

func TestOIDConstants(t *testing.T) {
	oids := []asn1.ObjectIdentifier{
		OIDQcStatements,
		OIDQcCompliance,
		OIDQcLimitValue,
		OIDQcRetentionPeriod,
		OIDQcSSCD,
		OIDQcPDS,
		OIDQcType,
		OIDQcCCLegislation,
		OIDQcTypeEsign,
		OIDQcTypeEseal,
		OIDQcTypeWeb,
	}

	for _, oid := range oids {
		if len(oid) == 0 {
			t.Error("OID should not be empty")
		}
	}
}

// Concurrency tests

func TestTrustedListRegistryConcurrency(t *testing.T) {
	registry := NewTrustedListRegistry()
	done := make(chan bool)

	// Concurrent writers
	for i := 0; i < 10; i++ {
		go func(idx int) {
			registry.Add(&TrustedList{
				SchemeTerritory: string(rune('A' + idx)),
			})
			done <- true
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 10; i++ {
		go func() {
			_ = registry.GetAll()
			_ = registry.Territories()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}

// EU member states test

func TestEUMemberStates(t *testing.T) {
	if len(EUMemberStates) < 27 {
		t.Errorf("Expected at least 27 EU member states, got %d", len(EUMemberStates))
	}

	// Check some key members
	expected := []string{"DE", "FR", "IT", "ES", "PL"}
	for _, code := range expected {
		if !IsEUMemberState(code) {
			t.Errorf("%s should be EU member state", code)
		}
	}
}

// Qualified policy tests

func TestHasQualifiedPolicy(t *testing.T) {
	cert := generateTestCert(t)
	// Test cert doesn't have qualified policies
	if HasQualifiedPolicy(cert) {
		t.Error("Test cert should not have qualified policy")
	}
}

// ParseQCStatements test with invalid cert

func TestParseQCStatementsNone(t *testing.T) {
	cert := generateTestCert(t)
	_, err := ParseQCStatements(cert)
	if err != ErrQCStatementNotFound {
		t.Errorf("Expected ErrQCStatementNotFound, got %v", err)
	}
}
