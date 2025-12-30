// Package qualified provides tests for TSP registry and criteria types.
package qualified

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

// Helper to generate a test certificate
func generateTestCertForTSP(t *testing.T) *x509.Certificate {
	return generateTestCertWithName(t, "Test User", "Test Org")
}

func generateTestCertWithName(t *testing.T, commonName, organization string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{organization},
			Country:      []string{"DE"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
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

// Test QcCertType
func TestQcCertTypeFromURI(t *testing.T) {
	tests := []struct {
		uri      string
		expected QcCertType
		ok       bool
	}{
		{ForeSignaturesURI, QcCertTypeEsign, true},
		{ForeSealsURI, QcCertTypeEseal, true},
		{ForWebSiteAuthenticationURI, QcCertTypeWeb, true},
		{"http://unknown.uri", "", false},
	}

	for _, tt := range tests {
		result, ok := QcCertTypeFromURI(tt.uri)
		if ok != tt.ok {
			t.Errorf("QcCertTypeFromURI(%q) ok = %v, want %v", tt.uri, ok, tt.ok)
		}
		if result != tt.expected {
			t.Errorf("QcCertTypeFromURI(%q) = %v, want %v", tt.uri, result, tt.expected)
		}
	}
}

// Test Qualifier
func TestQualifierURI(t *testing.T) {
	tests := []struct {
		qualifier Qualifier
		expected  string
	}{
		{QualifierWithSSCD, SvcInfoExtURIBase + "/QCWithSSCD"},
		{QualifierNoSSCD, SvcInfoExtURIBase + "/QCNoSSCD"},
		{QualifierWithQSCD, SvcInfoExtURIBase + "/QCWithQSCD"},
		{QualifierNotQualified, SvcInfoExtURIBase + "/NotQualified"},
	}

	for _, tt := range tests {
		result := tt.qualifier.URI()
		if result != tt.expected {
			t.Errorf("Qualifier(%q).URI() = %q, want %q", tt.qualifier, result, tt.expected)
		}
	}
}

func TestQualifierFromURI(t *testing.T) {
	tests := []struct {
		uri      string
		expected Qualifier
		ok       bool
	}{
		{SvcInfoExtURIBase + "/QCWithSSCD", QualifierWithSSCD, true},
		{SvcInfoExtURIBase + "/QCNoSSCD", QualifierNoSSCD, true},
		{SvcInfoExtURIBase + "/NotQualified", QualifierNotQualified, true},
		{"http://unknown.uri", "", false},
	}

	for _, tt := range tests {
		result, ok := QualifierFromURI(tt.uri)
		if ok != tt.ok {
			t.Errorf("QualifierFromURI(%q) ok = %v, want %v", tt.uri, ok, tt.ok)
		}
		if result != tt.expected {
			t.Errorf("QualifierFromURI(%q) = %v, want %v", tt.uri, result, tt.expected)
		}
	}
}

// Test CriteriaList
func TestCriteriaListMatchesAll(t *testing.T) {
	cert := generateTestCertForTSP(t)

	// All criteria must match
	criteriaList := &CriteriaList{
		CombineAs: CriteriaCombinationAll,
		Criteria: []Criterion{
			&CertSubjectDNCriterion{RequiredRDNPartOIDs: map[string]bool{"2.5.4.3": true}}, // CN
		},
	}

	if !criteriaList.Matches(cert) {
		t.Error("Should match when all criteria are met")
	}
}

func TestCriteriaListMatchesAtLeastOne(t *testing.T) {
	cert := generateTestCertForTSP(t)

	criteriaList := &CriteriaList{
		CombineAs: CriteriaCombinationAtLeastOne,
		Criteria: []Criterion{
			&CertSubjectDNCriterion{RequiredRDNPartOIDs: map[string]bool{"1.2.3.4.5": true}}, // Missing
			&CertSubjectDNCriterion{RequiredRDNPartOIDs: map[string]bool{"2.5.4.3": true}},   // CN - present
		},
	}

	if !criteriaList.Matches(cert) {
		t.Error("Should match when at least one criterion is met")
	}
}

func TestCriteriaListMatchesNone(t *testing.T) {
	cert := generateTestCertForTSP(t)

	criteriaList := &CriteriaList{
		CombineAs: CriteriaCombinationNone,
		Criteria: []Criterion{
			&CertSubjectDNCriterion{RequiredRDNPartOIDs: map[string]bool{"1.2.3.4.5": true}}, // Missing
		},
	}

	if !criteriaList.Matches(cert) {
		t.Error("Should match when none of the criteria match")
	}
}

func TestEmptyCriteriaList(t *testing.T) {
	cert := generateTestCertForTSP(t)

	criteriaList := &CriteriaList{
		CombineAs: CriteriaCombinationAll,
		Criteria:  []Criterion{},
	}

	if !criteriaList.Matches(cert) {
		t.Error("Empty criteria list should match")
	}
}

// Test KeyUsageCriterion
func TestKeyUsageCriterion(t *testing.T) {
	cert := generateTestCertForTSP(t)

	criterion := &KeyUsageCriterion{
		Settings: KeyUsageConstraintsForCriteria{
			KeyUsage: map[string]bool{"digital_signature": true},
		},
	}

	if !criterion.Matches(cert) {
		t.Error("Should match certificate with digital signature key usage")
	}

	// Test forbidden key usage
	forbiddenCriterion := &KeyUsageCriterion{
		Settings: KeyUsageConstraintsForCriteria{
			KeyUsageForbidden: map[string]bool{"digital_signature": true},
		},
	}

	if forbiddenCriterion.Matches(cert) {
		t.Error("Should not match when forbidden key usage is present")
	}
}

// Test CertSubjectDNCriterion
func TestCertSubjectDNCriterion(t *testing.T) {
	cert := generateTestCertForTSP(t)

	// CN OID is 2.5.4.3
	criterion := &CertSubjectDNCriterion{
		RequiredRDNPartOIDs: map[string]bool{"2.5.4.3": true},
	}

	if !criterion.Matches(cert) {
		t.Error("Should match certificate with CN")
	}

	// Non-existent OID
	missingCriterion := &CertSubjectDNCriterion{
		RequiredRDNPartOIDs: map[string]bool{"1.2.3.4.5.6.7.8.9": true},
	}

	if missingCriterion.Matches(cert) {
		t.Error("Should not match certificate without required RDN part")
	}
}

// Test TSPRegistry
func TestTSPRegistryNew(t *testing.T) {
	registry := NewTSPRegistry()
	if registry == nil {
		t.Fatal("NewTSPRegistry() returned nil")
	}
	if registry.caCertToSI == nil || registry.tstCertToSI == nil {
		t.Error("Registry maps not initialized")
	}
}

func TestTSPRegistryRegisterCA(t *testing.T) {
	registry := NewTSPRegistry()
	cert := generateTestCertForTSP(t)

	info := CAServiceInformation{
		QualifiedServiceInformation: QualifiedServiceInformation{
			BaseInfo: BaseServiceInformation{
				ServiceType:   CAQCUri,
				ServiceName:   "Test CA",
				ValidFrom:     time.Now().Add(-24 * time.Hour),
				ProviderCerts: []*x509.Certificate{cert},
			},
		},
	}

	registry.RegisterCA(info)

	services := registry.ApplicableServiceDefinitions(cert, nil)
	if len(services) != 1 {
		t.Errorf("Expected 1 service, got %d", len(services))
	}
}

func TestTSPRegistryRegisterTST(t *testing.T) {
	registry := NewTSPRegistry()
	cert := generateTestCertForTSP(t)

	info := QTSTServiceInformation{
		QualifiedServiceInformation: QualifiedServiceInformation{
			BaseInfo: BaseServiceInformation{
				ServiceType:   QTSTUri,
				ServiceName:   "Test TSA",
				ValidFrom:     time.Now().Add(-24 * time.Hour),
				ProviderCerts: []*x509.Certificate{cert},
			},
		},
	}

	registry.RegisterTST(info)

	services := registry.ApplicableServiceDefinitions(cert, nil)
	if len(services) != 1 {
		t.Errorf("Expected 1 service, got %d", len(services))
	}
}

func TestTSPRegistryApplicableServiceDefinitionsWithMoment(t *testing.T) {
	registry := NewTSPRegistry()
	cert := generateTestCertForTSP(t)

	now := time.Now()
	validUntil := now.Add(24 * time.Hour)
	info := CAServiceInformation{
		QualifiedServiceInformation: QualifiedServiceInformation{
			BaseInfo: BaseServiceInformation{
				ServiceType:   CAQCUri,
				ServiceName:   "Test CA",
				ValidFrom:     now.Add(-24 * time.Hour),
				ValidUntil:    &validUntil,
				ProviderCerts: []*x509.Certificate{cert},
			},
		},
	}

	registry.RegisterCA(info)

	// Current time - should find service
	services := registry.ApplicableServiceDefinitions(cert, &now)
	if len(services) != 1 {
		t.Errorf("Expected 1 service at current time, got %d", len(services))
	}

	// Future time past validity - should not find service
	future := now.Add(48 * time.Hour)
	services = registry.ApplicableServiceDefinitions(cert, &future)
	if len(services) != 0 {
		t.Errorf("Expected 0 services after validity, got %d", len(services))
	}
}

func TestTSPRegistryKnownCertificateAuthorities(t *testing.T) {
	registry := NewTSPRegistry()
	cert := generateTestCertForTSP(t)

	info := CAServiceInformation{
		QualifiedServiceInformation: QualifiedServiceInformation{
			BaseInfo: BaseServiceInformation{
				ServiceType:   CAQCUri,
				ServiceName:   "Test CA",
				ValidFrom:     time.Now().Add(-24 * time.Hour),
				ProviderCerts: []*x509.Certificate{cert},
			},
		},
	}

	registry.RegisterCA(info)

	cas := registry.KnownCertificateAuthorities()
	if len(cas) != 1 {
		t.Errorf("Expected 1 CA, got %d", len(cas))
	}
}

func TestTSPRegistryKnownTimestampAuthorities(t *testing.T) {
	registry := NewTSPRegistry()
	cert := generateTestCertForTSP(t)

	info := QTSTServiceInformation{
		QualifiedServiceInformation: QualifiedServiceInformation{
			BaseInfo: BaseServiceInformation{
				ServiceType:   QTSTUri,
				ServiceName:   "Test TSA",
				ValidFrom:     time.Now().Add(-24 * time.Hour),
				ProviderCerts: []*x509.Certificate{cert},
			},
		},
	}

	registry.RegisterTST(info)

	tsas := registry.KnownTimestampAuthorities()
	if len(tsas) != 1 {
		t.Errorf("Expected 1 TSA, got %d", len(tsas))
	}
}

func TestTSPRegistryApplicableTSPsOnPath(t *testing.T) {
	registry := NewTSPRegistry()
	cert1 := generateTestCertForTSP(t)
	cert2 := generateTestCertForTSP(t)

	registry.RegisterCA(CAServiceInformation{
		QualifiedServiceInformation: QualifiedServiceInformation{
			BaseInfo: BaseServiceInformation{
				ServiceType:   CAQCUri,
				ServiceName:   "CA 1",
				ValidFrom:     time.Now().Add(-24 * time.Hour),
				ProviderCerts: []*x509.Certificate{cert1},
			},
		},
	})

	registry.RegisterCA(CAServiceInformation{
		QualifiedServiceInformation: QualifiedServiceInformation{
			BaseInfo: BaseServiceInformation{
				ServiceType:   CAQCUri,
				ServiceName:   "CA 2",
				ValidFrom:     time.Now().Add(-24 * time.Hour),
				ProviderCerts: []*x509.Certificate{cert2},
			},
		},
	})

	chain := []*x509.Certificate{cert1, cert2}
	services := registry.ApplicableTSPsOnPath(chain, time.Now())
	if len(services) != 2 {
		t.Errorf("Expected 2 services on path, got %d", len(services))
	}
}

// Test TSPTrustManager
func TestTSPTrustManager(t *testing.T) {
	registry := NewTSPRegistry()
	manager := NewTSPTrustManager(registry)

	if manager.Registry != registry {
		t.Error("Registry not set correctly")
	}
}

func TestTSPTrustManagerAsTrustAnchor(t *testing.T) {
	registry := NewTSPRegistry()
	cert := generateTestCertForTSP(t)

	registry.RegisterCA(CAServiceInformation{
		QualifiedServiceInformation: QualifiedServiceInformation{
			BaseInfo: BaseServiceInformation{
				ServiceType:   CAQCUri,
				ServiceName:   "Test CA",
				ValidFrom:     time.Now().Add(-24 * time.Hour),
				ProviderCerts: []*x509.Certificate{cert},
			},
		},
	})

	manager := NewTSPTrustManager(registry)
	anchor := manager.AsTrustAnchor(cert)

	if anchor == nil {
		t.Fatal("AsTrustAnchor returned nil")
	}
	if anchor.Quals.TrustedServiceType != TrustedServiceTypeCertificateAuthority {
		t.Errorf("Expected CA service type, got %v", anchor.Quals.TrustedServiceType)
	}
}

func TestTSPTrustManagerAsTrustAnchorNotFound(t *testing.T) {
	registry := NewTSPRegistry()
	manager := NewTSPTrustManager(registry)
	cert := generateTestCertForTSP(t)

	anchor := manager.AsTrustAnchor(cert)
	if anchor != nil {
		t.Error("Should return nil for unknown certificate")
	}
}

// Test AuthorityWithCert
func TestAuthorityWithCert(t *testing.T) {
	cert := generateTestCertForTSP(t)
	auth := NewAuthorityWithCert(cert)

	if auth.Certificate() != cert {
		t.Error("Certificate not returned correctly")
	}
}

func TestAuthorityWithCertIsPotentialIssuerOf(t *testing.T) {
	issuer := generateTestCertForTSP(t)
	auth := NewAuthorityWithCert(issuer)

	// Self-signed cert - issuer equals subject
	if !auth.IsPotentialIssuerOf(issuer) {
		t.Error("Self-signed cert should be potential issuer of itself")
	}

	// Generate a cert with different subject name
	other := generateTestCertWithName(t, "Other User", "Other Org")
	if auth.IsPotentialIssuerOf(other) {
		t.Error("Should not be potential issuer of unrelated cert")
	}
}

// Test TSPServiceParsingError
func TestTSPServiceParsingError(t *testing.T) {
	err := NewTSPServiceParsingError("test error")
	if err.Error() != "test error" {
		t.Errorf("Error message = %q, want 'test error'", err.Error())
	}
}

// Test URI constants
func TestURIConstants(t *testing.T) {
	if CAQCUri != "http://uri.etsi.org/TrstSvc/Svctype/CA/QC" {
		t.Errorf("CAQCUri = %q", CAQCUri)
	}
	if QTSTUri != "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST" {
		t.Errorf("QTSTUri = %q", QTSTUri)
	}
	if LOTLRule != "http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUlistofthelists" {
		t.Errorf("LOTLRule = %q", LOTLRule)
	}
}

// Test TrustedServiceType
func TestTrustedServiceType(t *testing.T) {
	tests := []struct {
		stype TrustedServiceType
		value int
	}{
		{TrustedServiceTypeUnsupported, 0},
		{TrustedServiceTypeCertificateAuthority, 1},
		{TrustedServiceTypeTimeStampingAuthority, 2},
	}

	for _, tt := range tests {
		if int(tt.stype) != tt.value {
			t.Errorf("TrustedServiceType %v = %d, want %d", tt.stype, tt.stype, tt.value)
		}
	}
}

// Concurrency test for TSPRegistry
func TestTSPRegistryConcurrency(t *testing.T) {
	registry := NewTSPRegistry()
	done := make(chan bool)

	// Concurrent CA registrations
	for i := 0; i < 10; i++ {
		go func() {
			cert := generateTestCertForTSP(t)
			registry.RegisterCA(CAServiceInformation{
				QualifiedServiceInformation: QualifiedServiceInformation{
					BaseInfo: BaseServiceInformation{
						ServiceType:   CAQCUri,
						ValidFrom:     time.Now(),
						ProviderCerts: []*x509.Certificate{cert},
					},
				},
			})
			done <- true
		}()
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			_ = registry.KnownCertificateAuthorities()
			_ = registry.KnownTimestampAuthorities()
			done <- true
		}()
	}

	// Wait for all
	for i := 0; i < 20; i++ {
		<-done
	}
}
