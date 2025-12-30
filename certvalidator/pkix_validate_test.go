// Package certvalidator provides X.509 certificate path validation.
// This file contains tests for RFC 5280 PKIX certification path validation.
package certvalidator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// Helper to generate test certificate chain
func generatePKIXTestCertChain(t *testing.T) (*x509.Certificate, *x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate root CA key
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	// Generate intermediate CA key
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate intermediate key: %v", err)
	}

	// Generate leaf key
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate leaf key: %v", err)
	}

	now := time.Now()

	// Create root certificate
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		t.Fatalf("Failed to parse root certificate: %v", err)
	}

	// Create intermediate certificate
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	intermediateCertDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}
	intermediateCert, err := x509.ParseCertificate(intermediateCertDER)
	if err != nil {
		t.Fatalf("Failed to parse intermediate certificate: %v", err)
	}

	// Create leaf certificate
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"test.example.com", "www.example.com"},
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	return rootCert, intermediateCert, leafCert, rootKey
}

// Helper to create a SimpleTrustManager with a root certificate
func createTrustManagerWithRoot(rootCert *x509.Certificate) *SimpleTrustManager {
	tm := NewSimpleTrustManager()
	tm.AddRoot(rootCert, true)
	return tm
}

func TestRevocationModeString(t *testing.T) {
	tests := []struct {
		mode     RevocationMode
		expected string
	}{
		{RevocationSoftFail, "soft-fail"},
		{RevocationHardFail, "hard-fail"},
		{RevocationRequire, "require"},
		{RevocationMode(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.expected {
				t.Errorf("RevocationMode.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewPKIXValidationConfig(t *testing.T) {
	rootCert, _, _, _ := generatePKIXTestCertChain(t)
	trustManager := createTrustManagerWithRoot(rootCert)

	config := NewPKIXValidationConfig(trustManager)

	if config.TrustManager == nil {
		t.Error("TrustManager should not be nil")
	}
	if config.RevocationMode != RevocationSoftFail {
		t.Errorf("RevocationMode = %v, want %v", config.RevocationMode, RevocationSoftFail)
	}
	if config.MaxPathLength != 10 {
		t.Errorf("MaxPathLength = %d, want 10", config.MaxPathLength)
	}
	if config.AlgorithmPolicy == nil {
		t.Error("AlgorithmPolicy should not be nil")
	}
	if config.TimeTolerance != time.Minute {
		t.Errorf("TimeTolerance = %v, want %v", config.TimeTolerance, time.Minute)
	}
}

func TestNewPKIXPathValidationState(t *testing.T) {
	rootCert, _, _, _ := generatePKIXTestCertChain(t)
	trustManager := createTrustManagerWithRoot(rootCert)

	config := NewPKIXValidationConfig(trustManager)
	pathLength := 3

	state := NewPKIXPathValidationState(config, pathLength)

	if state.PathLength != pathLength {
		t.Errorf("PathLength = %d, want %d", state.PathLength, pathLength)
	}
	if state.ExplicitPolicy != pathLength+1 {
		t.Errorf("ExplicitPolicy = %d, want %d", state.ExplicitPolicy, pathLength+1)
	}
	if state.InhibitAnyPolicy != pathLength+1 {
		t.Errorf("InhibitAnyPolicy = %d, want %d", state.InhibitAnyPolicy, pathLength+1)
	}
	if state.PolicyMapping != pathLength+1 {
		t.Errorf("PolicyMapping = %d, want %d", state.PolicyMapping, pathLength+1)
	}
	if state.ValidPolicyTree == nil {
		t.Error("ValidPolicyTree should not be nil")
	}
}

func TestPKIXPathValidationStateWithPKIXParams(t *testing.T) {
	rootCert, _, _, _ := generatePKIXTestCertChain(t)
	trustManager := createTrustManagerWithRoot(rootCert)

	config := NewPKIXValidationConfig(trustManager)
	config.PKIXParams = &PKIXValidationParams{
		InitialExplicitPolicy:       true,
		InitialAnyPolicyInhibit:     true,
		InitialPolicyMappingInhibit: true,
	}

	state := NewPKIXPathValidationState(config, 3)

	if state.ExplicitPolicy != 0 {
		t.Errorf("ExplicitPolicy = %d, want 0", state.ExplicitPolicy)
	}
	if state.InhibitAnyPolicy != 0 {
		t.Errorf("InhibitAnyPolicy = %d, want 0", state.InhibitAnyPolicy)
	}
	if state.PolicyMapping != 0 {
		t.Errorf("PolicyMapping = %d, want 0", state.PolicyMapping)
	}
}

func TestPKIXInitFromTrustAnchor(t *testing.T) {
	rootCert, _, _, _ := generatePKIXTestCertChain(t)
	trustManager := createTrustManagerWithRoot(rootCert)

	config := NewPKIXValidationConfig(trustManager)
	state := NewPKIXPathValidationState(config, 3)

	anchor := NewCertTrustAnchor(rootCert, nil, true)

	err := state.InitFromTrustAnchor(anchor)
	if err != nil {
		t.Fatalf("InitFromTrustAnchor failed: %v", err)
	}

	if state.WorkingPublicKey == nil {
		t.Error("WorkingPublicKey should be set from anchor")
	}
	if state.WorkingIssuerName.CommonName != rootCert.Subject.CommonName {
		t.Errorf("WorkingIssuerName.CommonName = %s, want %s",
			state.WorkingIssuerName.CommonName, rootCert.Subject.CommonName)
	}
}

func TestPKIXCheckValidity(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name           string
		notBefore      time.Time
		notAfter       time.Time
		validationTime time.Time
		tolerance      time.Duration
		expectError    bool
	}{
		{
			name:           "Valid certificate",
			notBefore:      now.Add(-time.Hour),
			notAfter:       now.Add(time.Hour),
			validationTime: now,
			tolerance:      time.Minute,
			expectError:    false,
		},
		{
			name:           "Not yet valid",
			notBefore:      now.Add(time.Hour),
			notAfter:       now.Add(2 * time.Hour),
			validationTime: now,
			tolerance:      time.Minute,
			expectError:    true,
		},
		{
			name:           "Expired",
			notBefore:      now.Add(-2 * time.Hour),
			notAfter:       now.Add(-time.Hour),
			validationTime: now,
			tolerance:      time.Minute,
			expectError:    true,
		},
		{
			name:           "Within tolerance - not yet valid",
			notBefore:      now.Add(30 * time.Second),
			notAfter:       now.Add(time.Hour),
			validationTime: now,
			tolerance:      time.Minute,
			expectError:    false,
		},
		{
			name:           "Within tolerance - expired",
			notBefore:      now.Add(-time.Hour),
			notAfter:       now.Add(-30 * time.Second),
			validationTime: now,
			tolerance:      time.Minute,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootCert, _, _, _ := generatePKIXTestCertChain(t)
			trustManager := createTrustManagerWithRoot(rootCert)

			config := NewPKIXValidationConfig(trustManager)
			config.ValidationTime = tt.validationTime
			config.TimeTolerance = tt.tolerance

			state := NewPKIXPathValidationState(config, 1)

			// Create a test certificate with the specified validity
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			template := &x509.Certificate{
				SerialNumber: big.NewInt(100),
				Subject:      pkix.Name{CommonName: "Test"},
				NotBefore:    tt.notBefore,
				NotAfter:     tt.notAfter,
			}
			certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			cert, _ := x509.ParseCertificate(certDER)

			err := state.checkValidity(cert, true)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestPKIXNameConstraints(t *testing.T) {
	t.Run("NewNameConstraints", func(t *testing.T) {
		nc := NewNameConstraints()
		if nc == nil {
			t.Error("NewNameConstraints returned nil")
		}
	})

	t.Run("CheckPermittedDNS", func(t *testing.T) {
		nc := NewNameConstraints()
		nc.PermittedDNSDomains = []string{".example.com"}

		tests := []struct {
			name        string
			dns         string
			expectError bool
		}{
			{"Permitted subdomain", "sub.example.com", false},
			{"Not permitted", "example.org", true},
			{"Empty constraints allows all", "", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.name == "Empty constraints allows all" {
					nc2 := NewNameConstraints() // No constraints
					err := nc2.CheckPermittedDNS("anything.com")
					if err != nil {
						t.Errorf("Expected no error for unconstrained, got %v", err)
					}
					return
				}

				err := nc.CheckPermittedDNS(tt.dns)
				if tt.expectError && err == nil {
					t.Error("Expected error but got none")
				}
				if !tt.expectError && err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("IsExcludedDNS", func(t *testing.T) {
		nc := NewNameConstraints()
		nc.ExcludedDNSDomains = []string{".evil.com"}

		if !nc.IsExcludedDNS("www.evil.com") {
			t.Error("Should be excluded")
		}
		if nc.IsExcludedDNS("www.good.com") {
			t.Error("Should not be excluded")
		}
	})

	t.Run("CheckPermittedEmail", func(t *testing.T) {
		nc := NewNameConstraints()
		nc.PermittedEmailAddresses = []string{".example.com"}

		if err := nc.CheckPermittedEmail("user@sub.example.com"); err != nil {
			t.Errorf("Should be permitted: %v", err)
		}
	})

	t.Run("Intersect", func(t *testing.T) {
		nc1 := NewNameConstraints()
		nc1.PermittedDNSDomains = []string{".example.com", ".test.com"}

		nc2 := NewNameConstraints()
		nc2.PermittedDNSDomains = []string{".example.com"}

		result := nc1.Intersect(nc2)
		if len(result.PermittedDNSDomains) != 1 {
			t.Errorf("Expected 1 permitted domain, got %d", len(result.PermittedDNSDomains))
		}
	})

	t.Run("Union", func(t *testing.T) {
		nc1 := NewNameConstraints()
		nc1.ExcludedDNSDomains = []string{".evil.com"}

		nc2 := NewNameConstraints()
		nc2.ExcludedDNSDomains = []string{".bad.com"}

		result := nc1.Union(nc2)
		if len(result.ExcludedDNSDomains) != 2 {
			t.Errorf("Expected 2 excluded domains, got %d", len(result.ExcludedDNSDomains))
		}
	})
}

func TestPKIXMatchesDNSConstraint(t *testing.T) {
	tests := []struct {
		name       string
		dns        string
		constraint string
		matches    bool
	}{
		{"Empty constraint matches all", "anything.com", "", true},
		{"Exact match", "example.com", "example.com", true},
		{"Subdomain match", "sub.example.com", ".example.com", true},
		{"No match", "example.org", ".example.com", false},
		{"Too short for subdomain", "a.com", ".example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesDNSConstraint(tt.dns, tt.constraint); got != tt.matches {
				t.Errorf("matchesDNSConstraint(%s, %s) = %v, want %v",
					tt.dns, tt.constraint, got, tt.matches)
			}
		})
	}
}

func TestPKIXMatchesEmailConstraint(t *testing.T) {
	tests := []struct {
		name       string
		email      string
		constraint string
		matches    bool
	}{
		{"Empty constraint matches all", "user@example.com", "", true},
		{"Exact match", "user@example.com", "user@example.com", true},
		{"Domain constraint", "user@sub.example.com", ".example.com", true},
		{"Full domain match", "user@example.com", "@example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesEmailConstraint(tt.email, tt.constraint); got != tt.matches {
				t.Errorf("matchesEmailConstraint(%s, %s) = %v, want %v",
					tt.email, tt.constraint, got, tt.matches)
			}
		})
	}
}

func TestPKIXIsSelfIssued(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()

	t.Run("Self-issued certificate", func(t *testing.T) {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Same"},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		if !isSelfIssued(cert) {
			t.Error("Should be self-issued")
		}
	})
}

func TestPKIXPathValidator(t *testing.T) {
	rootCert, intermediateCert, leafCert, _ := generatePKIXTestCertChain(t)

	t.Run("NewPKIXPathValidator", func(t *testing.T) {
		trustManager := createTrustManagerWithRoot(rootCert)

		config := NewPKIXValidationConfig(trustManager)
		validator := NewPKIXPathValidator(config)

		if validator == nil {
			t.Error("NewPKIXPathValidator returned nil")
		}
		if validator.Config != config {
			t.Error("Config not set correctly")
		}
	})

	t.Run("ValidatePath with valid chain", func(t *testing.T) {
		trustManager := createTrustManagerWithRoot(rootCert)

		config := NewPKIXValidationConfig(trustManager)
		config.SkipRevocation = true
		validator := NewPKIXPathValidator(config)

		anchor := NewCertTrustAnchor(rootCert, nil, true)
		path := &CertificationPath{
			TrustAnchor:  anchor,
			Certificates: []*x509.Certificate{leafCert, intermediateCert},
		}

		result, err := validator.ValidatePath(path)
		if err != nil {
			t.Fatalf("ValidatePath returned error: %v", err)
		}
		if !result.Valid {
			t.Errorf("Validation should succeed, errors: %v", result.Errors)
		}
	})

	t.Run("ValidatePath with nil path", func(t *testing.T) {
		trustManager := createTrustManagerWithRoot(rootCert)

		config := NewPKIXValidationConfig(trustManager)
		validator := NewPKIXPathValidator(config)

		_, err := validator.ValidatePath(nil)
		if err == nil {
			t.Error("Expected error for nil path")
		}
	})

	t.Run("ValidatePath with expired certificate", func(t *testing.T) {
		trustManager := createTrustManagerWithRoot(rootCert)

		config := NewPKIXValidationConfig(trustManager)
		config.SkipRevocation = true
		config.ValidationTime = time.Now().Add(100 * 24 * time.Hour) // Future
		validator := NewPKIXPathValidator(config)

		anchor := NewCertTrustAnchor(rootCert, nil, true)
		path := &CertificationPath{
			TrustAnchor:  anchor,
			Certificates: []*x509.Certificate{leafCert, intermediateCert},
		}

		result, err := validator.ValidatePath(path)
		if err != nil {
			t.Fatalf("ValidatePath returned error: %v", err)
		}
		if result.Valid {
			t.Error("Validation should fail for expired certificates")
		}
	})
}

func TestPKIXValidationResult(t *testing.T) {
	result := &PKIXValidationResult{
		Valid:         true,
		ValidPolicies: []string{"1.2.3.4", "5.6.7.8"},
		Errors:        nil,
		Warnings:      []string{"test warning"},
	}

	if !result.Valid {
		t.Error("Result should be valid")
	}
	if len(result.ValidPolicies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(result.ValidPolicies))
	}
	if len(result.Warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d", len(result.Warnings))
	}
}

func TestX509SignatureToSignedDigest(t *testing.T) {
	tests := []struct {
		name     string
		algo     x509.SignatureAlgorithm
		expected asn1.ObjectIdentifier
	}{
		{"SHA256WithRSA", x509.SHA256WithRSA, OIDRSAWithSHA256},
		{"SHA384WithRSA", x509.SHA384WithRSA, OIDRSAWithSHA384},
		{"SHA512WithRSA", x509.SHA512WithRSA, OIDRSAWithSHA512},
		{"SHA1WithRSA", x509.SHA1WithRSA, OIDRSAWithSHA1},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, OIDECDSAWithSHA256},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, OIDECDSAWithSHA384},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, OIDECDSAWithSHA512},
		{"PureEd25519", x509.PureEd25519, OIDEd25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := x509SignatureToSignedDigest(tt.algo)
			if result == nil {
				t.Fatal("Result should not be nil")
			}
			if !result.Algorithm.Equal(tt.expected) {
				t.Errorf("Algorithm = %v, want %v", result.Algorithm, tt.expected)
			}
		})
	}
}

func TestPKIXProcessCertificatePolicies(t *testing.T) {
	rootCert, _, _, _ := generatePKIXTestCertChain(t)
	trustManager := createTrustManagerWithRoot(rootCert)

	config := NewPKIXValidationConfig(trustManager)
	state := NewPKIXPathValidationState(config, 2)

	t.Run("With nil policy tree", func(t *testing.T) {
		state.ValidPolicyTree = nil
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Test"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		err := state.processCertificatePolicies(cert)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("With empty policies", func(t *testing.T) {
		state.ValidPolicyTree = NewPolicyTreeRoot()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Test"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			// No PolicyIdentifiers
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		err := state.processCertificatePolicies(cert)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if state.ValidPolicyTree != nil {
			t.Error("Policy tree should be nil after processing cert with no policies")
		}
	})
}

func TestPKIXPrepareNextCertificate(t *testing.T) {
	rootCert, intermediateCert, _, _ := generatePKIXTestCertChain(t)
	trustManager := createTrustManagerWithRoot(rootCert)

	config := NewPKIXValidationConfig(trustManager)
	state := NewPKIXPathValidationState(config, 2)
	state.WorkingPublicKey = rootCert.PublicKey
	state.WorkingIssuerName = rootCert.Subject

	t.Run("Valid intermediate CA", func(t *testing.T) {
		err := state.prepareNextCertificate(intermediateCert)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if state.WorkingIssuerName.CommonName != intermediateCert.Subject.CommonName {
			t.Error("Working issuer name should be updated")
		}
	})

	t.Run("Non-CA certificate fails", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Not CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  false, // Not a CA
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		err := state.prepareNextCertificate(cert)
		if err == nil {
			t.Error("Should fail for non-CA certificate")
		}
	})
}

func TestPKIXProcessNameConstraints(t *testing.T) {
	rootCert, _, _, _ := generatePKIXTestCertChain(t)
	trustManager := createTrustManagerWithRoot(rootCert)

	config := NewPKIXValidationConfig(trustManager)
	state := NewPKIXPathValidationState(config, 2)

	t.Run("Certificate with permitted subtrees", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			PermittedDNSDomains:   []string{".example.com"},
			PermittedIPRanges:     []*net.IPNet{{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)}},
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		err := state.processNameConstraints(cert)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if state.PermittedSubtrees == nil {
			t.Error("PermittedSubtrees should be set")
		}
	})

	t.Run("Certificate with excluded subtrees", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			ExcludedDNSDomains:    []string{".evil.com"},
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)

		// Reset state
		state.ExcludedSubtrees = nil

		err := state.processNameConstraints(cert)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if state.ExcludedSubtrees == nil {
			t.Error("ExcludedSubtrees should be set")
		}
	})
}

func TestPKIXWrapUp(t *testing.T) {
	rootCert, _, _, _ := generatePKIXTestCertChain(t)
	trustManager := createTrustManagerWithRoot(rootCert)

	config := NewPKIXValidationConfig(trustManager)
	state := NewPKIXPathValidationState(config, 2)

	t.Run("Basic wrap up", func(t *testing.T) {
		result, err := state.WrapUp(rootCert)
		if err != nil {
			t.Fatalf("WrapUp returned error: %v", err)
		}
		if result == nil {
			t.Fatal("Result should not be nil")
		}
	})

	t.Run("With explicit policy required and empty tree", func(t *testing.T) {
		state2 := NewPKIXPathValidationState(config, 2)
		state2.ExplicitPolicy = 0
		state2.ValidPolicyTree = nil

		result, err := state2.WrapUp(rootCert)
		if err != nil {
			t.Fatalf("WrapUp returned error: %v", err)
		}
		if result.Valid {
			t.Error("Should be invalid when explicit policy required and tree is empty")
		}
	})
}

func TestPKIXIntersectStrings(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected int
	}{
		{"Both empty", nil, nil, 0},
		{"A empty", nil, []string{"x"}, 0},
		{"B empty", []string{"x"}, nil, 0},
		{"No intersection", []string{"a", "b"}, []string{"c", "d"}, 0},
		{"Full intersection", []string{"a", "b"}, []string{"a", "b"}, 2},
		{"Partial intersection", []string{"a", "b", "c"}, []string{"b", "c", "d"}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := intersectStrings(tt.a, tt.b)
			if len(result) != tt.expected {
				t.Errorf("intersectStrings() returned %d items, want %d", len(result), tt.expected)
			}
		})
	}
}

func TestPKIXCheckRevocation(t *testing.T) {
	rootCert, _, leafCert, _ := generatePKIXTestCertChain(t)
	trustManager := createTrustManagerWithRoot(rootCert)

	t.Run("Skip with whitelist", func(t *testing.T) {
		fingerprint := CertificateFingerprint(leafCert)
		config := NewPKIXValidationConfig(trustManager)
		config.WhitelistedCerts = map[string]bool{
			fmt.Sprintf("%x", fingerprint): true,
		}
		validator := NewPKIXPathValidator(config)

		state := NewPKIXPathValidationState(config, 1)
		err := validator.checkRevocation(leafCert, state, true)
		if err != nil {
			t.Errorf("Should not error for whitelisted cert: %v", err)
		}
	})

	t.Run("Normal certificate", func(t *testing.T) {
		config := NewPKIXValidationConfig(trustManager)
		validator := NewPKIXPathValidator(config)

		state := NewPKIXPathValidationState(config, 1)
		err := validator.checkRevocation(leafCert, state, true)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}
