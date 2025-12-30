package attributes

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

func generateTestCert(t *testing.T) *x509.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Cert",
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
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

func TestCMSAttributesGet(t *testing.T) {
	attrs := CMSAttributes{
		{Type: OIDContentType, Values: asn1.RawValue{}},
		{Type: OIDMessageDigest, Values: asn1.RawValue{}},
	}

	// Find existing attribute
	attr := attrs.Get(OIDContentType)
	if attr == nil {
		t.Error("Expected to find OIDContentType")
	}

	// Find non-existing attribute
	attr = attrs.Get(OIDSigningTime)
	if attr != nil {
		t.Error("Should not find OIDSigningTime")
	}
}

func TestCMSAttributesHas(t *testing.T) {
	attrs := CMSAttributes{
		{Type: OIDContentType, Values: asn1.RawValue{}},
	}

	if !attrs.Has(OIDContentType) {
		t.Error("Expected Has(OIDContentType) to return true")
	}

	if attrs.Has(OIDMessageDigest) {
		t.Error("Expected Has(OIDMessageDigest) to return false")
	}
}

func TestAsSigningCertificateV2(t *testing.T) {
	cert := generateTestCert(t)

	sigCertV2 := AsSigningCertificateV2(cert)

	if sigCertV2 == nil {
		t.Fatal("AsSigningCertificateV2 returned nil")
	}

	if len(sigCertV2.Certs) != 1 {
		t.Errorf("Expected 1 cert, got %d", len(sigCertV2.Certs))
	}

	if len(sigCertV2.Certs[0].CertHash) != 32 { // SHA-256
		t.Errorf("Expected 32 byte hash, got %d bytes", len(sigCertV2.Certs[0].CertHash))
	}
}

func TestSigningCertificateV2Provider(t *testing.T) {
	cert := generateTestCert(t)
	provider := &SigningCertificateV2Provider{SigningCert: cert}

	if !provider.AttributeType().Equal(OIDSigningCertificateV2) {
		t.Error("Unexpected attribute type")
	}

	value, err := provider.BuildAttributeValue(false)
	if err != nil {
		t.Fatalf("BuildAttributeValue failed: %v", err)
	}

	sigCertV2, ok := value.(*SigningCertificateV2)
	if !ok {
		t.Fatal("Expected SigningCertificateV2 type")
	}

	if len(sigCertV2.Certs) != 1 {
		t.Errorf("Expected 1 cert, got %d", len(sigCertV2.Certs))
	}
}

func TestSigningTimeProvider(t *testing.T) {
	now := time.Now()
	provider := &SigningTimeProvider{Timestamp: now}

	if !provider.AttributeType().Equal(OIDSigningTime) {
		t.Error("Unexpected attribute type")
	}

	value, err := provider.BuildAttributeValue(false)
	if err != nil {
		t.Fatalf("BuildAttributeValue failed: %v", err)
	}

	timestamp, ok := value.(time.Time)
	if !ok {
		t.Fatal("Expected time.Time type")
	}

	if timestamp.Unix() != now.Unix() {
		t.Error("Timestamp mismatch")
	}
}

func TestCMSAlgorithmProtectionProvider(t *testing.T) {
	provider := &CMSAlgorithmProtectionProvider{
		DigestAlgo: "sha256",
		SignatureAlgo: AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // SHA256WithRSA
		},
	}

	if !provider.AttributeType().Equal(OIDCMSAlgorithmProtection) {
		t.Error("Unexpected attribute type")
	}

	value, err := provider.BuildAttributeValue(false)
	if err != nil {
		t.Fatalf("BuildAttributeValue failed: %v", err)
	}

	algProt, ok := value.(*CMSAlgorithmProtection)
	if !ok {
		t.Fatal("Expected CMSAlgorithmProtection type")
	}

	if !algProt.DigestAlgorithm.Algorithm.Equal(OIDSHA256) {
		t.Error("Unexpected digest algorithm")
	}
}

func TestAdobeRevinfoProvider(t *testing.T) {
	revinfo := &RevocationInfoArchival{
		CRL:  []asn1.RawValue{{FullBytes: []byte{0x30, 0x00}}},
		OCSP: []asn1.RawValue{{FullBytes: []byte{0x30, 0x01}}},
	}

	provider := &AdobeRevinfoProvider{Value: revinfo}

	if !provider.AttributeType().Equal(OIDAdobeRevocationInfoArchival) {
		t.Error("Unexpected attribute type")
	}

	value, err := provider.BuildAttributeValue(false)
	if err != nil {
		t.Fatalf("BuildAttributeValue failed: %v", err)
	}

	if value != revinfo {
		t.Error("Value should be the same RevocationInfoArchival")
	}
}

func TestDigestAlgorithmOID(t *testing.T) {
	tests := []struct {
		algo     string
		expected asn1.ObjectIdentifier
	}{
		{"sha256", OIDSHA256},
		{"SHA256", OIDSHA256},
		{"sha384", OIDSHA384},
		{"SHA384", OIDSHA384},
		{"sha512", OIDSHA512},
		{"SHA512", OIDSHA512},
		{"unknown", OIDSHA256}, // Default
	}

	for _, tt := range tests {
		result := DigestAlgorithmOID(tt.algo)
		if !result.Equal(tt.expected) {
			t.Errorf("DigestAlgorithmOID(%s) = %v, want %v", tt.algo, result, tt.expected)
		}
	}
}

func TestSimpleCMSAttribute(t *testing.T) {
	value := asn1.ObjectIdentifier{1, 2, 3, 4}
	attr, err := SimpleCMSAttribute(OIDContentType, value)
	if err != nil {
		t.Fatalf("SimpleCMSAttribute failed: %v", err)
	}

	if !attr.Type.Equal(OIDContentType) {
		t.Error("Unexpected attribute type")
	}
}

func TestNewRevocationInfoArchival(t *testing.T) {
	crls := [][]byte{{0x30, 0x00}, {0x30, 0x01}}
	ocsps := [][]byte{{0x30, 0x02}}

	ria := NewRevocationInfoArchival(crls, ocsps)

	if len(ria.CRL) != 2 {
		t.Errorf("Expected 2 CRLs, got %d", len(ria.CRL))
	}

	if len(ria.OCSP) != 1 {
		t.Errorf("Expected 1 OCSP, got %d", len(ria.OCSP))
	}
}

func TestSigningCertificateV2Marshal(t *testing.T) {
	cert := generateTestCert(t)
	sigCertV2 := AsSigningCertificateV2(cert)

	data, err := sigCertV2.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshal returned empty data")
	}
}

func TestCMSAlgorithmProtectionMarshal(t *testing.T) {
	algProt := &CMSAlgorithmProtection{
		DigestAlgorithm: AlgorithmIdentifier{Algorithm: OIDSHA256},
		SignatureAlgorithm: AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		},
	}

	data, err := algProt.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshal returned empty data")
	}
}

func TestRevocationInfoArchivalMarshal(t *testing.T) {
	ria := NewRevocationInfoArchival(
		[][]byte{{0x30, 0x00}},
		[][]byte{{0x30, 0x01}},
	)

	data, err := ria.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshal returned empty data")
	}
}

func TestCMSAttributeMarshal(t *testing.T) {
	attr := &CMSAttribute{
		Type:   OIDContentType,
		Values: asn1.RawValue{FullBytes: []byte{0x31, 0x00}},
	}

	data, err := attr.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshal returned empty data")
	}
}

func TestOIDConstants(t *testing.T) {
	// Verify OID constants are properly defined
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"OIDContentType", OIDContentType},
		{"OIDMessageDigest", OIDMessageDigest},
		{"OIDSigningTime", OIDSigningTime},
		{"OIDSignatureTimeStampToken", OIDSignatureTimeStampToken},
		{"OIDSigningCertificateV2", OIDSigningCertificateV2},
		{"OIDCMSAlgorithmProtection", OIDCMSAlgorithmProtection},
		{"OIDAdobeRevocationInfoArchival", OIDAdobeRevocationInfoArchival},
		{"OIDSHA256", OIDSHA256},
		{"OIDSHA384", OIDSHA384},
		{"OIDSHA512", OIDSHA512},
	}

	for _, tt := range tests {
		if len(tt.oid) == 0 {
			t.Errorf("%s OID is empty", tt.name)
		}
	}
}

func TestSignedAttributeProviderSpec(t *testing.T) {
	cert := generateTestCert(t)

	spec := &SignedAttributeProviderSpec{
		Providers: []AttributeProvider{
			&SigningCertificateV2Provider{SigningCert: cert},
			&SigningTimeProvider{Timestamp: time.Now()},
		},
	}

	attrs, err := spec.BuildSignedAttributes([]byte("digest"), "sha256", false)
	if err != nil {
		t.Fatalf("BuildSignedAttributes failed: %v", err)
	}

	if len(attrs) != 2 {
		t.Errorf("Expected 2 attributes, got %d", len(attrs))
	}
}

func TestESSCertIDv2(t *testing.T) {
	certID := ESSCertIDv2{
		HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDSHA256},
		CertHash:      make([]byte, 32),
	}

	if len(certID.CertHash) != 32 {
		t.Error("Unexpected cert hash length")
	}
}

func TestPolicyInformation(t *testing.T) {
	policy := PolicyInformation{
		PolicyIdentifier: asn1.ObjectIdentifier{1, 2, 3, 4},
	}

	if len(policy.PolicyIdentifier) != 4 {
		t.Error("Unexpected policy identifier")
	}
}

func TestContentInfo(t *testing.T) {
	ci := ContentInfo{
		ContentType: OIDSignedData,
	}

	if !ci.ContentType.Equal(OIDSignedData) {
		t.Error("Unexpected content type")
	}
}

func TestIssuerSerial(t *testing.T) {
	is := IssuerSerial{
		Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
		SerialNumber: asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x01}},
	}

	if len(is.Issuer.FullBytes) == 0 {
		t.Error("Issuer should not be empty")
	}
}
