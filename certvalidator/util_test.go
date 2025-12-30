package certvalidator

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

func createTestCertWithExtensions() *x509.Certificate {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Cert",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
		AuthorityKeyId:        []byte{5, 6, 7, 8},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{"example.com", "www.example.com"},
		EmailAddresses:        []string{"test@example.com"},
		CRLDistributionPoints: []string{"http://crl.example.com/crl.pem"},
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://ca.example.com/ca.crt"},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{{2, 16, 840, 1, 101, 3, 2, 1, 48, 1}},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	return cert
}

func TestGetIssuerDN(t *testing.T) {
	// Create a CA certificate
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	// Create a leaf certificate signed by CA
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	issuer := GetIssuerDN(leafCert)
	if issuer.CommonName != "Test CA" {
		t.Errorf("expected 'Test CA', got %s", issuer.CommonName)
	}
}

func TestCertIssuerSerial(t *testing.T) {
	cert := createTestCertWithExtensions()
	is := CertIssuerSerial(cert)
	if len(is) == 0 {
		t.Error("expected non-empty issuer serial")
	}
}

func TestGetCRLDistributionPoints(t *testing.T) {
	cert := createTestCertWithExtensions()
	dps := GetCRLDistributionPoints(cert)
	if len(dps) != 1 {
		t.Errorf("expected 1 CRL DP, got %d", len(dps))
	}
	if dps[0].URL != "http://crl.example.com/crl.pem" {
		t.Errorf("expected 'http://crl.example.com/crl.pem', got %s", dps[0].URL)
	}
}

func TestGetRelevantCRLDPs(t *testing.T) {
	cert := createTestCertWithExtensions()

	t.Run("Without deltas", func(t *testing.T) {
		dps := GetRelevantCRLDPs(cert, false)
		if len(dps) != 1 {
			t.Errorf("expected 1 CRL DP, got %d", len(dps))
		}
	})

	t.Run("With deltas", func(t *testing.T) {
		dps := GetRelevantCRLDPs(cert, true)
		// Delta CRLs aren't exposed by Go's x509 package
		if len(dps) < 1 {
			t.Errorf("expected at least 1 CRL DP, got %d", len(dps))
		}
	})
}

func TestGetOCSPURLs(t *testing.T) {
	cert := createTestCertWithExtensions()
	urls := GetOCSPURLs(cert)
	if len(urls) != 1 {
		t.Errorf("expected 1 OCSP URL, got %d", len(urls))
	}
	if urls[0] != "http://ocsp.example.com" {
		t.Errorf("expected 'http://ocsp.example.com', got %s", urls[0])
	}
}

func TestGetDeclaredRevInfo(t *testing.T) {
	cert := createTestCertWithExtensions()
	info := GetDeclaredRevInfo(cert)
	if !info.HasCRL {
		t.Error("expected HasCRL to be true")
	}
	if !info.HasOCSP {
		t.Error("expected HasOCSP to be true")
	}
}

func TestIsHTTPURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"http://example.com", true},
		{"https://example.com", true},
		{"HTTP://EXAMPLE.COM", true},
		{"HTTPS://EXAMPLE.COM", true},
		{"ftp://example.com", false},
		{"ldap://example.com", false},
		{"file:///path/to/file", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if isHTTPURL(tt.url) != tt.expected {
				t.Errorf("expected %v for %s", tt.expected, tt.url)
			}
		})
	}
}

func TestParseURL(t *testing.T) {
	t.Run("Valid URL", func(t *testing.T) {
		u, err := ParseURL("http://example.com/path")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u.Host != "example.com" {
			t.Errorf("expected 'example.com', got %s", u.Host)
		}
	})

	t.Run("Invalid URL", func(t *testing.T) {
		_, err := ParseURL("://invalid")
		if err == nil {
			t.Error("expected error for invalid URL")
		}
	})
}

func TestCertificateFingerprint(t *testing.T) {
	cert := createTestCertWithExtensions()
	fp := CertificateFingerprint(cert)
	if len(fp) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(fp))
	}
}

func TestCompareCertificates(t *testing.T) {
	cert1 := createTestCertWithExtensions()
	cert2 := createTestCertWithExtensions()

	t.Run("Same certificate", func(t *testing.T) {
		if !CompareCertificates(cert1, cert1) {
			t.Error("expected certificates to be equal")
		}
	})

	t.Run("Different certificates", func(t *testing.T) {
		// Different certs will have different serial numbers
		if CompareCertificates(cert1, cert2) {
			t.Error("expected certificates to be different")
		}
	})
}

func TestIsSelfSigned(t *testing.T) {
	t.Run("Self-signed", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Self Signed"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
			IsCA:         true,
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		cert, _ := x509.ParseCertificate(certDER)

		if !IsSelfSigned(cert) {
			t.Error("expected to be self-signed")
		}
	})

	t.Run("Not self-signed", func(t *testing.T) {
		// Create a CA first
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "CA"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
			IsCA:         true,
		}
		caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		caCert, _ := x509.ParseCertificate(caDER)

		// Create a leaf signed by the CA
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leafTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "Leaf"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}
		leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
		leafCert, _ := x509.ParseCertificate(leafDER)

		if IsSelfSigned(leafCert) {
			t.Error("expected not to be self-signed")
		}
	})
}

func TestIsSelfIssued(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Self Issued"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	if !IsSelfIssued(cert) {
		t.Error("expected to be self-issued")
	}
}

func TestGetAuthorityInfoAccessOCSP(t *testing.T) {
	cert := createTestCertWithExtensions()
	urls := GetAuthorityInfoAccessOCSP(cert)
	if len(urls) != 1 {
		t.Errorf("expected 1 OCSP URL, got %d", len(urls))
	}
}

func TestGetAuthorityInfoAccessIssuers(t *testing.T) {
	cert := createTestCertWithExtensions()
	urls := GetAuthorityInfoAccessIssuers(cert)
	if len(urls) != 1 {
		t.Errorf("expected 1 issuer URL, got %d", len(urls))
	}
}

func TestHashAlgorithmName(t *testing.T) {
	tests := []struct {
		oid      asn1.ObjectIdentifier
		expected string
	}{
		{OIDSHA1, "sha1"},
		{OIDSHA256, "sha256"},
		{OIDSHA384, "sha384"},
		{OIDSHA512, "sha512"},
		{asn1.ObjectIdentifier{1, 2, 3}, "1.2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if HashAlgorithmName(tt.oid) != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, HashAlgorithmName(tt.oid))
			}
		})
	}
}

func TestNormalizeDN(t *testing.T) {
	name := pkix.Name{
		CommonName:   "Test Cert",
		Organization: []string{"TEST ORG"},
	}
	normalized := NormalizeDN(name)
	if normalized == "" {
		t.Error("expected non-empty normalized DN")
	}
}

func TestCompareDN(t *testing.T) {
	name1 := pkix.Name{CommonName: "Test"}
	name2 := pkix.Name{CommonName: "TEST"}
	name3 := pkix.Name{CommonName: "Other"}

	if !CompareDN(name1, name2) {
		t.Error("expected case-insensitive match")
	}
	if CompareDN(name1, name3) {
		t.Error("expected no match for different names")
	}
}

func TestExtractExtension(t *testing.T) {
	cert := createTestCertWithExtensions()

	t.Run("Existing extension", func(t *testing.T) {
		// Basic constraints OID
		oid := asn1.ObjectIdentifier{2, 5, 29, 19}
		data, found := ExtractExtension(cert, oid)
		if !found {
			t.Error("expected to find basic constraints")
		}
		if len(data) == 0 {
			t.Error("expected non-empty extension data")
		}
	})

	t.Run("Non-existing extension", func(t *testing.T) {
		oid := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
		_, found := ExtractExtension(cert, oid)
		if found {
			t.Error("expected not to find unknown extension")
		}
	})
}

func TestHasExtension(t *testing.T) {
	cert := createTestCertWithExtensions()

	t.Run("Has basic constraints", func(t *testing.T) {
		oid := asn1.ObjectIdentifier{2, 5, 29, 19}
		if !HasExtension(cert, oid) {
			t.Error("expected to have basic constraints")
		}
	})

	t.Run("Does not have unknown", func(t *testing.T) {
		oid := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
		if HasExtension(cert, oid) {
			t.Error("expected not to have unknown extension")
		}
	})
}

func TestGetSubjectAltNames(t *testing.T) {
	cert := createTestCertWithExtensions()
	sans := GetSubjectAltNames(cert)

	if len(sans.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(sans.DNSNames))
	}
	if len(sans.EmailAddresses) != 1 {
		t.Errorf("expected 1 email address, got %d", len(sans.EmailAddresses))
	}
}

func TestCertPathLength(t *testing.T) {
	t.Run("With path length", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "CA"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLen:            2,
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		cert, _ := x509.ParseCertificate(certDER)

		if CertPathLength(cert) != 2 {
			t.Errorf("expected 2, got %d", CertPathLength(cert))
		}
	})

	t.Run("Without path length", func(t *testing.T) {
		cert := createTestCertWithExtensions()
		if CertPathLength(cert) != -1 {
			t.Errorf("expected -1, got %d", CertPathLength(cert))
		}
	})
}

func TestIsCAConstraint(t *testing.T) {
	t.Run("CA certificate", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "CA"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		cert, _ := x509.ParseCertificate(certDER)

		if !IsCAConstraint(cert) {
			t.Error("expected to be CA")
		}
	})

	t.Run("Non-CA certificate", func(t *testing.T) {
		cert := createTestCertWithExtensions()
		if IsCAConstraint(cert) {
			t.Error("expected not to be CA")
		}
	})
}

func TestGetKeyUsage(t *testing.T) {
	cert := createTestCertWithExtensions()
	usages := GetKeyUsage(cert)

	hasDigitalSignature := false
	hasKeyEncipherment := false
	for _, u := range usages {
		if u == "digitalSignature" {
			hasDigitalSignature = true
		}
		if u == "keyEncipherment" {
			hasKeyEncipherment = true
		}
	}

	if !hasDigitalSignature {
		t.Error("expected digitalSignature usage")
	}
	if !hasKeyEncipherment {
		t.Error("expected keyEncipherment usage")
	}
}

func TestGetExtKeyUsage(t *testing.T) {
	cert := createTestCertWithExtensions()
	usages := GetExtKeyUsage(cert)

	hasServerAuth := false
	hasClientAuth := false
	for _, u := range usages {
		if u == "serverAuth" {
			hasServerAuth = true
		}
		if u == "clientAuth" {
			hasClientAuth = true
		}
	}

	if !hasServerAuth {
		t.Error("expected serverAuth usage")
	}
	if !hasClientAuth {
		t.Error("expected clientAuth usage")
	}
}

func TestIssuedBy(t *testing.T) {
	caCert, caKey := createTestCertificate("CA", true)

	leafTemplate := &x509.Certificate{
		SerialNumber:   big.NewInt(2),
		Subject:        pkix.Name{CommonName: "Leaf"},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour),
		AuthorityKeyId: caCert.SubjectKeyId,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &caKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	t.Run("Issued by CA", func(t *testing.T) {
		if !IssuedBy(leafCert, caCert) {
			t.Error("expected to be issued by CA")
		}
	})

	t.Run("Not issued by other", func(t *testing.T) {
		otherCert, _ := createTestCertificate("Other CA", true)
		if IssuedBy(leafCert, otherCert) {
			t.Error("expected not to be issued by other CA")
		}
	})
}
