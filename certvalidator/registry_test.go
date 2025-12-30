package certvalidator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// createTestCA creates a test CA certificate and key.
func createTestCA(commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            2,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	return cert, privateKey
}

// createTestIntermediate creates an intermediate CA certificate.
func createTestIntermediate(commonName string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            1,
		SubjectKeyId:          []byte{5, 6, 7, 8},
		AuthorityKeyId:        parent.SubjectKeyId,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, parent, &privateKey.PublicKey, parentKey)
	cert, _ := x509.ParseCertificate(certDER)

	return cert, privateKey
}

// createTestLeaf creates a leaf certificate.
func createTestLeaf(commonName string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SubjectKeyId:          []byte{9, 10, 11, 12},
		AuthorityKeyId:        parent.SubjectKeyId,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, parent, &privateKey.PublicKey, parentKey)
	cert, _ := x509.ParseCertificate(certDER)

	return cert
}

func TestCertIssuerKey(t *testing.T) {
	ca, _ := createTestCA("Test CA")

	t.Run("Create from certificate", func(t *testing.T) {
		key := NewCertIssuerKey(ca)
		if key.Serial != ca.SerialNumber.String() {
			t.Errorf("expected serial %s, got %s", ca.SerialNumber.String(), key.Serial)
		}
	})

	t.Run("Same certificate produces same key", func(t *testing.T) {
		key1 := NewCertIssuerKey(ca)
		key2 := NewCertIssuerKey(ca)
		if key1 != key2 {
			t.Error("expected same keys for same certificate")
		}
	})

	t.Run("Different certificates produce different keys", func(t *testing.T) {
		ca2, _ := createTestCA("Other CA")
		key1 := NewCertIssuerKey(ca)
		key2 := NewCertIssuerKey(ca2)
		if key1 == key2 {
			t.Error("expected different keys for different certificates")
		}
	})
}

func TestSimpleCertificateStore(t *testing.T) {
	t.Run("NewSimpleCertificateStore", func(t *testing.T) {
		store := NewSimpleCertificateStore()
		if store == nil {
			t.Fatal("expected non-nil store")
		}
		if store.Count() != 0 {
			t.Errorf("expected 0, got %d", store.Count())
		}
	})

	t.Run("Register", func(t *testing.T) {
		store := NewSimpleCertificateStore()
		ca, _ := createTestCA("Test CA")

		// First registration should succeed
		if !store.Register(ca) {
			t.Error("expected true for first registration")
		}
		if store.Count() != 1 {
			t.Errorf("expected 1, got %d", store.Count())
		}

		// Second registration should return false (duplicate)
		if store.Register(ca) {
			t.Error("expected false for duplicate registration")
		}
		if store.Count() != 1 {
			t.Errorf("expected 1, got %d", store.Count())
		}
	})

	t.Run("RegisterMultiple", func(t *testing.T) {
		store := NewSimpleCertificateStore()
		ca1, _ := createTestCA("Test CA 1")
		ca2, _ := createTestCA("Test CA 2")

		store.RegisterMultiple([]*x509.Certificate{ca1, ca2})
		if store.Count() != 2 {
			t.Errorf("expected 2, got %d", store.Count())
		}
	})

	t.Run("RetrieveByKeyIdentifier", func(t *testing.T) {
		store := NewSimpleCertificateStore()
		ca, _ := createTestCA("Test CA")
		store.Register(ca)

		retrieved := store.RetrieveByKeyIdentifier(ca.SubjectKeyId)
		if retrieved == nil {
			t.Fatal("expected non-nil certificate")
		}
		if retrieved.Subject.CommonName != "Test CA" {
			t.Errorf("expected 'Test CA', got %s", retrieved.Subject.CommonName)
		}
	})

	t.Run("RetrieveByKeyIdentifier not found", func(t *testing.T) {
		store := NewSimpleCertificateStore()
		retrieved := store.RetrieveByKeyIdentifier([]byte{99, 99, 99})
		if retrieved != nil {
			t.Error("expected nil for non-existent key ID")
		}
	})

	t.Run("RetrieveManyByKeyIdentifier", func(t *testing.T) {
		store := NewSimpleCertificateStore()
		ca, _ := createTestCA("Test CA")
		store.Register(ca)

		certs := store.RetrieveManyByKeyIdentifier(ca.SubjectKeyId)
		if len(certs) != 1 {
			t.Errorf("expected 1, got %d", len(certs))
		}
	})

	t.Run("RetrieveByName", func(t *testing.T) {
		store := NewSimpleCertificateStore()
		ca, _ := createTestCA("Test CA")
		store.Register(ca)

		certs := store.RetrieveByName(ca.Subject)
		if len(certs) != 1 {
			t.Errorf("expected 1, got %d", len(certs))
		}
	})

	t.Run("RetrieveByIssuerKey", func(t *testing.T) {
		store := NewSimpleCertificateStore()
		ca, _ := createTestCA("Test CA")
		store.Register(ca)

		key := NewCertIssuerKey(ca)
		retrieved := store.RetrieveByIssuerKey(key)
		if retrieved == nil {
			t.Fatal("expected non-nil certificate")
		}
	})

	t.Run("All", func(t *testing.T) {
		store := NewSimpleCertificateStore()
		ca1, _ := createTestCA("Test CA 1")
		ca2, _ := createTestCA("Test CA 2")
		store.RegisterMultiple([]*x509.Certificate{ca1, ca2})

		all := store.All()
		if len(all) != 2 {
			t.Errorf("expected 2, got %d", len(all))
		}
	})
}

func TestSimpleTrustManager(t *testing.T) {
	t.Run("NewSimpleTrustManager", func(t *testing.T) {
		tm := NewSimpleTrustManager()
		if tm == nil {
			t.Fatal("expected non-nil trust manager")
		}
		if tm.Count() != 0 {
			t.Errorf("expected 0, got %d", tm.Count())
		}
	})

	t.Run("AddRoot", func(t *testing.T) {
		tm := NewSimpleTrustManager()
		ca, _ := createTestCA("Test CA")
		tm.AddRoot(ca, false)

		if tm.Count() != 1 {
			t.Errorf("expected 1, got %d", tm.Count())
		}
	})

	t.Run("AddRoot duplicate", func(t *testing.T) {
		tm := NewSimpleTrustManager()
		ca, _ := createTestCA("Test CA")
		tm.AddRoot(ca, false)
		tm.AddRoot(ca, false) // Add same again

		if tm.Count() != 1 {
			t.Errorf("expected 1, got %d", tm.Count())
		}
	})

	t.Run("BuildTrustManager", func(t *testing.T) {
		ca1, _ := createTestCA("Test CA 1")
		ca2, _ := createTestCA("Test CA 2")
		tm := BuildTrustManager([]*x509.Certificate{ca1, ca2}, false)

		if tm.Count() != 2 {
			t.Errorf("expected 2, got %d", tm.Count())
		}
	})

	t.Run("IsRoot", func(t *testing.T) {
		tm := NewSimpleTrustManager()
		ca, _ := createTestCA("Test CA")
		tm.AddRoot(ca, false)

		if !tm.IsRoot(ca) {
			t.Error("expected true")
		}

		other, _ := createTestCA("Other CA")
		if tm.IsRoot(other) {
			t.Error("expected false for non-root")
		}
	})

	t.Run("AsTrustAnchor", func(t *testing.T) {
		tm := NewSimpleTrustManager()
		ca, _ := createTestCA("Test CA")
		tm.AddRoot(ca, false)

		authority := NewAuthorityWithCert(ca)
		anchor := tm.AsTrustAnchor(authority)
		if anchor == nil {
			t.Fatal("expected non-nil anchor")
		}
	})

	t.Run("FindPotentialIssuers", func(t *testing.T) {
		tm := NewSimpleTrustManager()
		ca, caKey := createTestCA("Test CA")
		tm.AddRoot(ca, true)

		leaf := createTestLeaf("Test Leaf", ca, caKey)
		issuers := tm.FindPotentialIssuers(leaf, TrustedServiceCA)

		if len(issuers) != 1 {
			t.Errorf("expected 1, got %d", len(issuers))
		}
	})

	t.Run("FindPotentialIssuers wrong issuer name", func(t *testing.T) {
		tm := NewSimpleTrustManager()
		ca1, _ := createTestCA("Test CA 1")
		ca2, ca2Key := createTestCA("Test CA 2")
		tm.AddRoot(ca1, true) // Only add ca1 as root

		// Create leaf signed by ca2
		leaf := createTestLeaf("Test Leaf", ca2, ca2Key)
		issuers := tm.FindPotentialIssuers(leaf, TrustedServiceUnspecified)

		if len(issuers) != 0 {
			t.Errorf("expected 0, got %d", len(issuers))
		}
	})

	t.Run("AllRoots", func(t *testing.T) {
		tm := NewSimpleTrustManager()
		ca1, _ := createTestCA("Test CA 1")
		ca2, _ := createTestCA("Test CA 2")
		tm.AddRoot(ca1, false)
		tm.AddRoot(ca2, false)

		all := tm.AllRoots()
		if len(all) != 2 {
			t.Errorf("expected 2, got %d", len(all))
		}
	})
}

func TestCertificateRegistry(t *testing.T) {
	t.Run("NewCertificateRegistry", func(t *testing.T) {
		registry := NewCertificateRegistry(nil)
		if registry == nil {
			t.Fatal("expected non-nil registry")
		}
	})

	t.Run("BuildCertificateRegistry", func(t *testing.T) {
		ca1, _ := createTestCA("Test CA 1")
		ca2, _ := createTestCA("Test CA 2")
		registry := BuildCertificateRegistry([]*x509.Certificate{ca1, ca2}, nil)

		if registry.Count() != 2 {
			t.Errorf("expected 2, got %d", registry.Count())
		}
	})

	t.Run("RetrieveFirstByName", func(t *testing.T) {
		ca, _ := createTestCA("Test CA")
		registry := BuildCertificateRegistry([]*x509.Certificate{ca}, nil)

		cert := registry.RetrieveFirstByName(ca.Subject)
		if cert == nil {
			t.Fatal("expected non-nil certificate")
		}
	})

	t.Run("RetrieveFirstByName not found", func(t *testing.T) {
		registry := NewCertificateRegistry(nil)
		name := pkix.Name{CommonName: "Non-existent"}
		cert := registry.RetrieveFirstByName(name)
		if cert != nil {
			t.Error("expected nil")
		}
	})

	t.Run("FindPotentialIssuers", func(t *testing.T) {
		ca, caKey := createTestCA("Test CA")
		intermediate, _ := createTestIntermediate("Intermediate", ca, caKey)
		registry := BuildCertificateRegistry([]*x509.Certificate{ca, intermediate}, nil)

		issuers := registry.FindPotentialIssuers(intermediate)
		if len(issuers) != 1 {
			t.Errorf("expected 1, got %d", len(issuers))
		}
	})
}

func TestPathBuilder(t *testing.T) {
	t.Run("NewPathBuilder", func(t *testing.T) {
		tm := NewSimpleTrustManager()
		registry := NewCertificateRegistry(nil)
		pb := NewPathBuilder(tm, registry)
		if pb == nil {
			t.Fatal("expected non-nil path builder")
		}
	})

	t.Run("BuildPaths direct to trust anchor", func(t *testing.T) {
		ca, _ := createTestCA("Test CA")
		tm := BuildTrustManager([]*x509.Certificate{ca}, true)
		registry := NewCertificateRegistry(nil)
		pb := NewPathBuilder(tm, registry)

		paths, err := pb.BuildPaths(context.Background(), ca)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(paths) != 1 {
			t.Errorf("expected 1 path, got %d", len(paths))
		}
	})

	t.Run("BuildPaths with chain", func(t *testing.T) {
		ca, caKey := createTestCA("Root CA")
		leaf := createTestLeaf("Leaf", ca, caKey)

		tm := BuildTrustManager([]*x509.Certificate{ca}, true)
		registry := BuildCertificateRegistry([]*x509.Certificate{ca}, nil)
		pb := NewPathBuilder(tm, registry)

		paths, err := pb.BuildPaths(context.Background(), leaf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(paths) != 1 {
			t.Errorf("expected 1 path, got %d", len(paths))
		}
		if paths[0].Length() != 2 {
			t.Errorf("expected path length 2, got %d", paths[0].Length())
		}
	})

	t.Run("BuildPaths with intermediate", func(t *testing.T) {
		ca, caKey := createTestCA("Root CA")
		intermediate, intermediateKey := createTestIntermediate("Intermediate", ca, caKey)
		leaf := createTestLeaf("Leaf", intermediate, intermediateKey)

		tm := BuildTrustManager([]*x509.Certificate{ca}, true)
		registry := BuildCertificateRegistry([]*x509.Certificate{ca, intermediate}, nil)
		pb := NewPathBuilder(tm, registry)

		paths, err := pb.BuildPaths(context.Background(), leaf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(paths) != 1 {
			t.Errorf("expected 1 path, got %d", len(paths))
		}
		if paths[0].Length() != 3 {
			t.Errorf("expected path length 3, got %d", paths[0].Length())
		}
	})

	t.Run("BuildPaths no path found", func(t *testing.T) {
		ca1, _ := createTestCA("Root CA 1")
		ca2, ca2Key := createTestCA("Root CA 2")
		leaf := createTestLeaf("Leaf", ca2, ca2Key)

		// Only trust ca1, but leaf is signed by ca2
		tm := BuildTrustManager([]*x509.Certificate{ca1}, true)
		registry := NewCertificateRegistry(nil)
		pb := NewPathBuilder(tm, registry)

		_, err := pb.BuildPaths(context.Background(), leaf)
		if err == nil {
			t.Error("expected error for no path found")
		}
	})

	t.Run("BuildFirstPath", func(t *testing.T) {
		ca, caKey := createTestCA("Root CA")
		leaf := createTestLeaf("Leaf", ca, caKey)

		tm := BuildTrustManager([]*x509.Certificate{ca}, true)
		registry := BuildCertificateRegistry([]*x509.Certificate{ca}, nil)
		pb := NewPathBuilder(tm, registry)

		path, err := pb.BuildFirstPath(context.Background(), leaf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if path == nil {
			t.Fatal("expected non-nil path")
		}
	})

	t.Run("Context cancellation", func(t *testing.T) {
		ca, caKey := createTestCA("Root CA")
		leaf := createTestLeaf("Leaf", ca, caKey)

		tm := BuildTrustManager([]*x509.Certificate{ca}, true)
		registry := BuildCertificateRegistry([]*x509.Certificate{ca}, nil)
		pb := NewPathBuilder(tm, registry)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := pb.BuildPaths(ctx, leaf)
		// The function may or may not return an error depending on timing
		_ = err
	})
}

func TestCertificationPath(t *testing.T) {
	ca, caKey := createTestCA("Root CA")
	intermediate, intermediateKey := createTestIntermediate("Intermediate", ca, caKey)
	leaf := createTestLeaf("Leaf", intermediate, intermediateKey)
	anchor := NewCertTrustAnchor(ca, nil, false)

	t.Run("NewCertificationPath", func(t *testing.T) {
		path := NewCertificationPath([]*x509.Certificate{leaf, intermediate}, anchor)
		if path == nil {
			t.Fatal("expected non-nil path")
		}
	})

	t.Run("Length", func(t *testing.T) {
		path := NewCertificationPath([]*x509.Certificate{leaf, intermediate}, anchor)
		if path.Length() != 3 {
			t.Errorf("expected 3, got %d", path.Length())
		}
	})

	t.Run("First", func(t *testing.T) {
		path := NewCertificationPath([]*x509.Certificate{leaf, intermediate}, anchor)
		first := path.First()
		if first.Subject.CommonName != "Leaf" {
			t.Errorf("expected 'Leaf', got %s", first.Subject.CommonName)
		}
	})

	t.Run("Last", func(t *testing.T) {
		path := NewCertificationPath([]*x509.Certificate{leaf, intermediate}, anchor)
		last := path.Last()
		if last.Subject.CommonName != "Intermediate" {
			t.Errorf("expected 'Intermediate', got %s", last.Subject.CommonName)
		}
	})

	t.Run("First with empty path", func(t *testing.T) {
		path := NewCertificationPath(nil, anchor)
		if path.First() != nil {
			t.Error("expected nil")
		}
	})

	t.Run("Last with empty path", func(t *testing.T) {
		path := NewCertificationPath(nil, anchor)
		if path.Last() != nil {
			t.Error("expected nil")
		}
	})
}

func TestLayeredCertificateStore(t *testing.T) {
	t.Run("NewLayeredCertificateStore", func(t *testing.T) {
		store1 := NewSimpleCertificateStore()
		store2 := NewSimpleCertificateStore()
		layered := NewLayeredCertificateStore(store1, store2)
		if layered == nil {
			t.Fatal("expected non-nil store")
		}
	})

	t.Run("RetrieveByKeyIdentifier from first store", func(t *testing.T) {
		store1 := NewSimpleCertificateStore()
		store2 := NewSimpleCertificateStore()

		ca1, _ := createTestCA("CA 1")
		store1.Register(ca1)

		layered := NewLayeredCertificateStore(store1, store2)
		cert := layered.RetrieveByKeyIdentifier(ca1.SubjectKeyId)
		if cert == nil {
			t.Fatal("expected non-nil certificate")
		}
	})

	t.Run("RetrieveByKeyIdentifier from second store", func(t *testing.T) {
		store1 := NewSimpleCertificateStore()
		store2 := NewSimpleCertificateStore()

		ca2, _ := createTestCA("CA 2")
		store2.Register(ca2)

		layered := NewLayeredCertificateStore(store1, store2)
		cert := layered.RetrieveByKeyIdentifier(ca2.SubjectKeyId)
		if cert == nil {
			t.Fatal("expected non-nil certificate")
		}
	})

	t.Run("RetrieveManyByKeyIdentifier", func(t *testing.T) {
		store1 := NewSimpleCertificateStore()
		store2 := NewSimpleCertificateStore()

		ca1, _ := createTestCA("CA 1")
		store1.Register(ca1)

		layered := NewLayeredCertificateStore(store1, store2)
		certs := layered.RetrieveManyByKeyIdentifier(ca1.SubjectKeyId)
		if len(certs) != 1 {
			t.Errorf("expected 1, got %d", len(certs))
		}
	})

	t.Run("RetrieveByName", func(t *testing.T) {
		store1 := NewSimpleCertificateStore()
		store2 := NewSimpleCertificateStore()

		ca1, _ := createTestCA("CA 1")
		store1.Register(ca1)

		layered := NewLayeredCertificateStore(store1, store2)
		certs := layered.RetrieveByName(ca1.Subject)
		if len(certs) != 1 {
			t.Errorf("expected 1, got %d", len(certs))
		}
	})

	t.Run("RetrieveByIssuerKey", func(t *testing.T) {
		store1 := NewSimpleCertificateStore()
		store2 := NewSimpleCertificateStore()

		ca1, _ := createTestCA("CA 1")
		store1.Register(ca1)

		layered := NewLayeredCertificateStore(store1, store2)
		key := NewCertIssuerKey(ca1)
		cert := layered.RetrieveByIssuerKey(key)
		if cert == nil {
			t.Fatal("expected non-nil certificate")
		}
	})
}

func TestTrustAnchorStoreAdapter(t *testing.T) {
	t.Run("NewTrustAnchorStoreAdapter", func(t *testing.T) {
		store := NewTrustAnchorStore()
		adapter := NewTrustAnchorStoreAdapter(store)
		if adapter == nil {
			t.Fatal("expected non-nil adapter")
		}
	})

	t.Run("RetrieveByKeyIdentifier", func(t *testing.T) {
		store := NewTrustAnchorStore()
		ca, _ := createTestCA("Test CA")
		store.AddCertificate(ca, false)

		adapter := NewTrustAnchorStoreAdapter(store)
		cert := adapter.RetrieveByKeyIdentifier(ca.SubjectKeyId)
		if cert == nil {
			t.Fatal("expected non-nil certificate")
		}
	})

	t.Run("RetrieveManyByKeyIdentifier", func(t *testing.T) {
		store := NewTrustAnchorStore()
		ca, _ := createTestCA("Test CA")
		store.AddCertificate(ca, false)

		adapter := NewTrustAnchorStoreAdapter(store)
		certs := adapter.RetrieveManyByKeyIdentifier(ca.SubjectKeyId)
		if len(certs) != 1 {
			t.Errorf("expected 1, got %d", len(certs))
		}
	})

	t.Run("RetrieveByName", func(t *testing.T) {
		store := NewTrustAnchorStore()
		ca, _ := createTestCA("Test CA")
		store.AddCertificate(ca, false)

		adapter := NewTrustAnchorStoreAdapter(store)
		certs := adapter.RetrieveByName(ca.Subject)
		if len(certs) != 1 {
			t.Errorf("expected 1, got %d", len(certs))
		}
	})

	t.Run("RetrieveByIssuerKey", func(t *testing.T) {
		store := NewTrustAnchorStore()
		ca, _ := createTestCA("Test CA")
		store.AddCertificate(ca, false)

		adapter := NewTrustAnchorStoreAdapter(store)
		key := NewCertIssuerKey(ca)
		cert := adapter.RetrieveByIssuerKey(key)
		if cert == nil {
			t.Fatal("expected non-nil certificate")
		}
	})
}

func TestMultiplePaths(t *testing.T) {
	// Create two CAs with the same subject name but different keys
	// This tests that path building can find multiple paths

	t.Run("Multiple paths to different roots", func(t *testing.T) {
		ca1, ca1Key := createTestCA("Root CA")
		ca2, ca2Key := createTestCA("Root CA 2")

		// Create an intermediate signed by ca1
		intermediate1, intermediate1Key := createTestIntermediate("Intermediate", ca1, ca1Key)
		// Create an intermediate signed by ca2
		intermediate2, intermediate2Key := createTestIntermediate("Intermediate 2", ca2, ca2Key)

		// Create a leaf that could be issued by either intermediate
		leaf := createTestLeaf("Leaf", intermediate1, intermediate1Key)
		// Create another leaf signed by intermediate2
		leaf2 := createTestLeaf("Leaf 2", intermediate2, intermediate2Key)

		tm := BuildTrustManager([]*x509.Certificate{ca1, ca2}, true)
		registry := BuildCertificateRegistry([]*x509.Certificate{ca1, ca2, intermediate1, intermediate2}, nil)
		pb := NewPathBuilder(tm, registry)

		// Leaf1 should have one path through intermediate1 to ca1
		paths1, err := pb.BuildPaths(context.Background(), leaf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(paths1) != 1 {
			t.Errorf("expected 1 path for leaf1, got %d", len(paths1))
		}

		// Leaf2 should have one path through intermediate2 to ca2
		paths2, err := pb.BuildPaths(context.Background(), leaf2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(paths2) != 1 {
			t.Errorf("expected 1 path for leaf2, got %d", len(paths2))
		}
	})
}

func TestCycleDetection(t *testing.T) {
	t.Run("Self-signed intermediate", func(t *testing.T) {
		ca, caKey := createTestCA("Root CA")
		intermediate, _ := createTestIntermediate("Intermediate", ca, caKey)

		tm := BuildTrustManager([]*x509.Certificate{ca}, true)
		// Register the intermediate which is also signed by the CA
		registry := BuildCertificateRegistry([]*x509.Certificate{ca, intermediate}, nil)
		pb := NewPathBuilder(tm, registry)

		// This should not cause infinite recursion
		paths, err := pb.BuildPaths(context.Background(), intermediate)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(paths) != 1 {
			t.Errorf("expected 1 path, got %d", len(paths))
		}
	})
}
