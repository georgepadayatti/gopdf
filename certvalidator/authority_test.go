package certvalidator

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

func TestTrustedServiceType(t *testing.T) {
	tests := []struct {
		serviceType TrustedServiceType
		expected    string
	}{
		{TrustedServiceUnspecified, "unspecified"},
		{TrustedServiceUnsupported, "unsupported"},
		{TrustedServiceCA, "certificate_authority"},
		{TrustedServiceTSA, "time_stamping_authority"},
		{TrustedServiceType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.serviceType.String() != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.serviceType.String())
			}
		})
	}
}

func TestTrustQualifiers(t *testing.T) {
	t.Run("NewTrustQualifiers", func(t *testing.T) {
		quals := NewTrustQualifiers()
		if quals.MaxPathLength != -1 {
			t.Errorf("expected -1, got %d", quals.MaxPathLength)
		}
		if quals.MaxAAPathLength != -1 {
			t.Errorf("expected -1, got %d", quals.MaxAAPathLength)
		}
		if quals.TrustedServiceType != TrustedServiceUnspecified {
			t.Errorf("expected unspecified, got %v", quals.TrustedServiceType)
		}
	})

	t.Run("IsValidAt", func(t *testing.T) {
		now := time.Now()
		past := now.Add(-time.Hour)
		future := now.Add(time.Hour)

		quals := &TrustQualifiers{
			ValidFrom:  &past,
			ValidUntil: &future,
		}

		if !quals.IsValidAt(now) {
			t.Error("expected valid at current time")
		}

		veryPast := now.Add(-2 * time.Hour)
		if quals.IsValidAt(veryPast) {
			t.Error("expected invalid before ValidFrom")
		}

		veryFuture := now.Add(2 * time.Hour)
		if quals.IsValidAt(veryFuture) {
			t.Error("expected invalid after ValidUntil")
		}
	})

	t.Run("IsValidAt no bounds", func(t *testing.T) {
		quals := NewTrustQualifiers()
		if !quals.IsValidAt(time.Now()) {
			t.Error("expected valid with no bounds")
		}
	})
}

func createTestCertificate(subject string, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}

	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.MaxPathLen = 1
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	return cert, privateKey
}

func TestAuthorityWithCert(t *testing.T) {
	cert, _ := createTestCertificate("Test CA", true)

	t.Run("NewAuthorityWithCert", func(t *testing.T) {
		authority := NewAuthorityWithCert(cert)
		if authority == nil {
			t.Fatal("expected non-nil authority")
		}
	})

	t.Run("Name", func(t *testing.T) {
		authority := NewAuthorityWithCert(cert)
		if authority.Name().CommonName != "Test CA" {
			t.Errorf("expected 'Test CA', got %s", authority.Name().CommonName)
		}
	})

	t.Run("PublicKey", func(t *testing.T) {
		authority := NewAuthorityWithCert(cert)
		if authority.PublicKey() == nil {
			t.Error("expected non-nil public key")
		}
	})

	t.Run("KeyID", func(t *testing.T) {
		authority := NewAuthorityWithCert(cert)
		if len(authority.KeyID()) == 0 {
			t.Error("expected non-empty key ID")
		}
	})

	t.Run("Hashable", func(t *testing.T) {
		authority := NewAuthorityWithCert(cert)
		hash := authority.Hashable()
		if len(hash) == 0 {
			t.Error("expected non-empty hash")
		}
	})

	t.Run("Certificate", func(t *testing.T) {
		authority := NewAuthorityWithCert(cert)
		if authority.Certificate() != cert {
			t.Error("expected same certificate")
		}
	})
}

func TestAuthorityWithCertIsPotentialIssuerOf(t *testing.T) {
	caCert, caKey := createTestCertificate("Test CA", true)
	authority := NewAuthorityWithCert(caCert)

	// Create a certificate issued by the CA
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Leaf Cert",
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		AuthorityKeyId: caCert.SubjectKeyId,
	}

	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &caKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	t.Run("Valid issuer", func(t *testing.T) {
		if !authority.IsPotentialIssuerOf(leafCert) {
			t.Error("expected to be potential issuer")
		}
	})

	t.Run("Wrong issuer name", func(t *testing.T) {
		otherCert, _ := createTestCertificate("Other CA", true)
		otherAuthority := NewAuthorityWithCert(otherCert)
		if otherAuthority.IsPotentialIssuerOf(leafCert) {
			t.Error("expected not to be potential issuer")
		}
	})
}

func TestNamedKeyAuthority(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	name := pkix.Name{CommonName: "Named Authority"}

	t.Run("NewNamedKeyAuthority", func(t *testing.T) {
		authority := NewNamedKeyAuthority(name, &privateKey.PublicKey)
		if authority == nil {
			t.Fatal("expected non-nil authority")
		}
	})

	t.Run("Name", func(t *testing.T) {
		authority := NewNamedKeyAuthority(name, &privateKey.PublicKey)
		if authority.Name().CommonName != "Named Authority" {
			t.Errorf("expected 'Named Authority', got %s", authority.Name().CommonName)
		}
	})

	t.Run("PublicKey", func(t *testing.T) {
		authority := NewNamedKeyAuthority(name, &privateKey.PublicKey)
		if authority.PublicKey() == nil {
			t.Error("expected non-nil public key")
		}
	})

	t.Run("KeyID returns nil", func(t *testing.T) {
		authority := NewNamedKeyAuthority(name, &privateKey.PublicKey)
		if authority.KeyID() != nil {
			t.Error("expected nil key ID")
		}
	})

	t.Run("Hashable", func(t *testing.T) {
		authority := NewNamedKeyAuthority(name, &privateKey.PublicKey)
		hash := authority.Hashable()
		if len(hash) == 0 {
			t.Error("expected non-empty hash")
		}
	})
}

func TestTrustAnchor(t *testing.T) {
	cert, _ := createTestCertificate("Trust Anchor", true)
	authority := NewAuthorityWithCert(cert)

	t.Run("NewTrustAnchor", func(t *testing.T) {
		anchor := NewTrustAnchor(authority, nil)
		if anchor == nil {
			t.Fatal("expected non-nil anchor")
		}
	})

	t.Run("Authority", func(t *testing.T) {
		anchor := NewTrustAnchor(authority, nil)
		if anchor.Authority() != authority {
			t.Error("expected same authority")
		}
	})

	t.Run("TrustQualifiers default", func(t *testing.T) {
		anchor := NewTrustAnchor(authority, nil)
		quals := anchor.TrustQualifiers()
		if quals == nil {
			t.Fatal("expected non-nil qualifiers")
		}
		if quals.MaxPathLength != -1 {
			t.Errorf("expected -1, got %d", quals.MaxPathLength)
		}
	})

	t.Run("TrustQualifiers custom", func(t *testing.T) {
		quals := &TrustQualifiers{MaxPathLength: 5}
		anchor := NewTrustAnchor(authority, quals)
		if anchor.TrustQualifiers().MaxPathLength != 5 {
			t.Errorf("expected 5, got %d", anchor.TrustQualifiers().MaxPathLength)
		}
	})

	t.Run("Equals", func(t *testing.T) {
		anchor1 := NewTrustAnchor(authority, nil)
		anchor2 := NewTrustAnchor(authority, nil)
		if !anchor1.Equals(anchor2) {
			t.Error("expected anchors to be equal")
		}

		otherCert, _ := createTestCertificate("Other Anchor", true)
		otherAuthority := NewAuthorityWithCert(otherCert)
		anchor3 := NewTrustAnchor(otherAuthority, nil)
		if anchor1.Equals(anchor3) {
			t.Error("expected anchors to not be equal")
		}
	})
}

func TestCertTrustAnchor(t *testing.T) {
	cert, _ := createTestCertificate("Cert Trust Anchor", true)

	t.Run("NewCertTrustAnchor", func(t *testing.T) {
		anchor := NewCertTrustAnchor(cert, nil, false)
		if anchor == nil {
			t.Fatal("expected non-nil anchor")
		}
	})

	t.Run("Certificate", func(t *testing.T) {
		anchor := NewCertTrustAnchor(cert, nil, false)
		if anchor.Certificate() != cert {
			t.Error("expected same certificate")
		}
	})

	t.Run("TrustQualifiers with derive", func(t *testing.T) {
		anchor := NewCertTrustAnchor(cert, nil, true)
		quals := anchor.TrustQualifiers()
		if quals == nil {
			t.Fatal("expected non-nil qualifiers")
		}
		// Should have derived from cert
		if quals.TrustedServiceType != TrustedServiceCA {
			t.Errorf("expected CA service type, got %v", quals.TrustedServiceType)
		}
	})

	t.Run("TrustQualifiers without derive", func(t *testing.T) {
		anchor := NewCertTrustAnchor(cert, nil, false)
		quals := anchor.TrustQualifiers()
		// Should be default
		if quals.TrustedServiceType != TrustedServiceUnspecified {
			t.Errorf("expected unspecified, got %v", quals.TrustedServiceType)
		}
	})

	t.Run("TrustQualifiers explicit", func(t *testing.T) {
		explicitQuals := &TrustQualifiers{
			TrustedServiceType: TrustedServiceTSA,
		}
		anchor := NewCertTrustAnchor(cert, explicitQuals, true)
		quals := anchor.TrustQualifiers()
		if quals.TrustedServiceType != TrustedServiceTSA {
			t.Errorf("expected TSA, got %v", quals.TrustedServiceType)
		}
	})
}

func TestDeriveQualsFromCert(t *testing.T) {
	t.Run("CA certificate", func(t *testing.T) {
		cert, _ := createTestCertificate("CA", true)
		quals := DeriveQualsFromCert(cert)

		if quals.TrustedServiceType != TrustedServiceCA {
			t.Errorf("expected CA, got %v", quals.TrustedServiceType)
		}
		if quals.ValidFrom == nil {
			t.Error("expected ValidFrom to be set")
		}
		if quals.ValidUntil == nil {
			t.Error("expected ValidUntil to be set")
		}
	})

	t.Run("Non-CA certificate", func(t *testing.T) {
		cert, _ := createTestCertificate("Leaf", false)
		quals := DeriveQualsFromCert(cert)

		if quals.TrustedServiceType != TrustedServiceUnsupported {
			t.Errorf("expected Unsupported, got %v", quals.TrustedServiceType)
		}
	})
}

func TestTrustAnchorStore(t *testing.T) {
	cert1, _ := createTestCertificate("CA 1", true)
	cert2, _ := createTestCertificate("CA 2", true)

	t.Run("NewTrustAnchorStore", func(t *testing.T) {
		store := NewTrustAnchorStore()
		if store == nil {
			t.Fatal("expected non-nil store")
		}
		if store.Count() != 0 {
			t.Errorf("expected 0, got %d", store.Count())
		}
	})

	t.Run("AddCertificate", func(t *testing.T) {
		store := NewTrustAnchorStore()
		store.AddCertificate(cert1, false)
		if store.Count() != 1 {
			t.Errorf("expected 1, got %d", store.Count())
		}
	})

	t.Run("Add", func(t *testing.T) {
		store := NewTrustAnchorStore()
		anchor := NewCertTrustAnchor(cert1, nil, false)
		store.Add(anchor)
		if store.Count() != 1 {
			t.Errorf("expected 1, got %d", store.Count())
		}
	})

	t.Run("All", func(t *testing.T) {
		store := NewTrustAnchorStore()
		store.AddCertificate(cert1, false)
		store.AddCertificate(cert2, false)
		all := store.All()
		if len(all) != 2 {
			t.Errorf("expected 2, got %d", len(all))
		}
	})

	t.Run("ToCertPool", func(t *testing.T) {
		store := NewTrustAnchorStore()
		store.AddCertificate(cert1, false)
		store.AddCertificate(cert2, false)
		pool := store.ToCertPool()
		if pool == nil {
			t.Fatal("expected non-nil pool")
		}
	})

	t.Run("FindPotentialIssuers", func(t *testing.T) {
		caCert, caKey := createTestCertificate("Test CA", true)
		store := NewTrustAnchorStore()
		store.AddCertificate(caCert, false)
		store.AddCertificate(cert2, false)

		// Create a leaf certificate
		leafTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{
				CommonName: "Leaf Cert",
			},
			NotBefore:      time.Now(),
			NotAfter:       time.Now().Add(365 * 24 * time.Hour),
			AuthorityKeyId: caCert.SubjectKeyId,
		}

		leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &caKey.PublicKey, caKey)
		leafCert, _ := x509.ParseCertificate(leafDER)

		issuers := store.FindPotentialIssuers(leafCert)
		if len(issuers) != 1 {
			t.Errorf("expected 1 issuer, got %d", len(issuers))
		}
	})
}

func TestBaseAuthority(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	name := pkix.Name{CommonName: "Base Authority"}

	t.Run("Name", func(t *testing.T) {
		ba := &BaseAuthority{name: name}
		if ba.Name().CommonName != "Base Authority" {
			t.Errorf("expected 'Base Authority', got %s", ba.Name().CommonName)
		}
	})

	t.Run("PublicKey", func(t *testing.T) {
		ba := &BaseAuthority{publicKey: &privateKey.PublicKey}
		if ba.PublicKey() == nil {
			t.Error("expected non-nil public key")
		}
	})

	t.Run("KeyID", func(t *testing.T) {
		keyID := []byte{1, 2, 3}
		ba := &BaseAuthority{keyID: keyID}
		if len(ba.KeyID()) != 3 {
			t.Errorf("expected 3, got %d", len(ba.KeyID()))
		}
	})

	t.Run("Hashable", func(t *testing.T) {
		ba := &BaseAuthority{name: name}
		hash := ba.Hashable()
		if len(hash) == 0 {
			t.Error("expected non-empty hash")
		}
	})
}
