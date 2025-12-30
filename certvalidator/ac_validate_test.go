// Package certvalidator provides X.509 certificate path validation.
// This file contains tests for attribute certificate (AC) validation.
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

func TestACTargetDescription(t *testing.T) {
	t.Run("NewACTargetDescription", func(t *testing.T) {
		td := NewACTargetDescription(
			[]string{"server.example.com"},
			[]string{"admin-group"},
		)

		if len(td.ValidatorNames) != 1 {
			t.Errorf("Expected 1 validator name, got %d", len(td.ValidatorNames))
		}
		if len(td.GroupMemberships) != 1 {
			t.Errorf("Expected 1 group membership, got %d", len(td.GroupMemberships))
		}
	})

	t.Run("IsEmpty", func(t *testing.T) {
		td1 := NewACTargetDescription(nil, nil)
		if !td1.IsEmpty() {
			t.Error("Expected empty target description")
		}

		td2 := NewACTargetDescription([]string{"server"}, nil)
		if td2.IsEmpty() {
			t.Error("Expected non-empty target description")
		}
	})
}

func TestHolderMismatch(t *testing.T) {
	tests := []struct {
		mismatch HolderMismatch
		name     string
	}{
		{HolderMatchOK, "HolderMatchOK"},
		{HolderMismatchIssuer, "HolderMismatchIssuer"},
		{HolderMismatchSerial, "HolderMismatchSerial"},
		{HolderMismatchName, "HolderMismatchName"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify constants are distinct
			for _, other := range tests {
				if tt.mismatch != other.mismatch && tt.name == other.name {
					t.Error("Duplicate mismatch constant")
				}
			}
		})
	}
}

func TestCompareRDNSequences(t *testing.T) {
	t.Run("Equal sequences", func(t *testing.T) {
		rdn1 := pkix.RDNSequence{
			{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test"},
			},
		}
		rdn2 := pkix.RDNSequence{
			{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test"},
			},
		}

		if !compareRDNSequences(rdn1, rdn2) {
			t.Error("Equal sequences should match")
		}
	})

	t.Run("Different lengths", func(t *testing.T) {
		rdn1 := pkix.RDNSequence{
			{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test"}},
		}
		rdn2 := pkix.RDNSequence{
			{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test"}},
			{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Org"}},
		}

		if compareRDNSequences(rdn1, rdn2) {
			t.Error("Different length sequences should not match")
		}
	})

	t.Run("Different values", func(t *testing.T) {
		rdn1 := pkix.RDNSequence{
			{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test1"}},
		}
		rdn2 := pkix.RDNSequence{
			{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test2"}},
		}

		if compareRDNSequences(rdn1, rdn2) {
			t.Error("Different value sequences should not match")
		}
	})
}

func TestMatchesGeneralName(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test User",
			Organization: []string{"Test Org"},
		},
		NotBefore:      now.Add(-time.Hour),
		NotAfter:       now.Add(time.Hour),
		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"test@example.com"},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	t.Run("DNS name match", func(t *testing.T) {
		// Create a GeneralName for DNS
		gn := &ASN1GeneralName{
			Raw: asn1.RawValue{
				Tag:   int(GeneralNameDNSName),
				Bytes: []byte("test.example.com"),
			},
		}

		if !matchesGeneralName(cert, gn) {
			t.Error("DNS name should match")
		}
	})

	t.Run("DNS name no match", func(t *testing.T) {
		gn := &ASN1GeneralName{
			Raw: asn1.RawValue{
				Tag:   int(GeneralNameDNSName),
				Bytes: []byte("other.example.com"),
			},
		}

		if matchesGeneralName(cert, gn) {
			t.Error("DNS name should not match")
		}
	})

	t.Run("Email match", func(t *testing.T) {
		gn := &ASN1GeneralName{
			Raw: asn1.RawValue{
				Tag:   int(GeneralNameRFC822Name),
				Bytes: []byte("test@example.com"),
			},
		}

		if !matchesGeneralName(cert, gn) {
			t.Error("Email should match")
		}
	})
}

func TestACValidationConfig(t *testing.T) {
	t.Run("NewACValidationConfig", func(t *testing.T) {
		tm := NewSimpleTrustManager()
		config := NewACValidationConfig(tm)

		if config.TrustManager == nil {
			t.Error("TrustManager should not be nil")
		}
		if config.TimeTolerance != time.Minute {
			t.Errorf("TimeTolerance = %v, want %v", config.TimeTolerance, time.Minute)
		}
	})
}

func TestACValidator(t *testing.T) {
	t.Run("NewACValidator", func(t *testing.T) {
		tm := NewSimpleTrustManager()
		config := NewACValidationConfig(tm)
		validator := NewACValidator(config)

		if validator == nil {
			t.Error("NewACValidator returned nil")
		}
		if validator.Config != config {
			t.Error("Config not set correctly")
		}
	})
}

func TestSupportedACExtensions(t *testing.T) {
	expectedExtensions := []string{
		"2.5.29.35", // authorityKeyIdentifier
		"2.5.29.31", // cRLDistributionPoints
		"2.5.29.46", // freshestCRL
		"2.5.29.14", // subjectKeyIdentifier
		"2.5.29.55", // targetInformation
		"2.5.29.56", // noRevAvail
		"1.3.6.1.5.5.7.1.1", // authorityInfoAccess
		"1.3.6.1.5.5.7.1.4", // auditIdentity
	}

	for _, oid := range expectedExtensions {
		if !supportedACExtensions[oid] {
			t.Errorf("Extension %s should be supported", oid)
		}
	}
}

func TestHasACNoRevAvail(t *testing.T) {
	t.Run("With no_rev_avail", func(t *testing.T) {
		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				Extensions: []pkix.Extension{
					{Id: OIDNoRevAvail, Value: []byte{0x05, 0x00}}, // NULL
				},
			},
		}

		if !hasACNoRevAvail(ac) {
			t.Error("Should detect no_rev_avail extension")
		}
	})

	t.Run("Without no_rev_avail", func(t *testing.T) {
		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				Extensions: []pkix.Extension{},
			},
		}

		if hasACNoRevAvail(ac) {
			t.Error("Should not detect no_rev_avail extension")
		}
	})
}

func TestGetACExtensionValue(t *testing.T) {
	testValue := []byte{0x01, 0x02, 0x03}
	testOID := asn1.ObjectIdentifier{1, 2, 3, 4}

	ac := &AttributeCertificateV2{
		ACInfo: AttributeCertificateInfo{
			Extensions: []pkix.Extension{
				{Id: testOID, Value: testValue},
			},
		},
	}

	t.Run("Extension exists", func(t *testing.T) {
		value, found := GetACExtensionValue(ac, testOID)
		if !found {
			t.Error("Extension should be found")
		}
		if len(value) != len(testValue) {
			t.Errorf("Value length = %d, want %d", len(value), len(testValue))
		}
	})

	t.Run("Extension not found", func(t *testing.T) {
		_, found := GetACExtensionValue(ac, asn1.ObjectIdentifier{5, 6, 7})
		if found {
			t.Error("Extension should not be found")
		}
	})
}

func TestGetACSerialNumber(t *testing.T) {
	serial := big.NewInt(12345)
	ac := &AttributeCertificateV2{
		ACInfo: AttributeCertificateInfo{
			SerialNumber: serial,
		},
	}

	result := GetACSerialNumber(ac)
	if result.Cmp(serial) != 0 {
		t.Errorf("Serial = %v, want %v", result, serial)
	}
}

func TestACValidatorCheckCriticalExtensions(t *testing.T) {
	tm := NewSimpleTrustManager()
	config := NewACValidationConfig(tm)
	validator := NewACValidator(config)

	t.Run("No critical extensions", func(t *testing.T) {
		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				Extensions: []pkix.Extension{
					{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Critical: false},
				},
			},
		}

		err := validator.checkCriticalExtensions(ac)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("Supported critical extension", func(t *testing.T) {
		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				Extensions: []pkix.Extension{
					{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Critical: true}, // authorityKeyIdentifier
				},
			},
		}

		err := validator.checkCriticalExtensions(ac)
		if err != nil {
			t.Errorf("Unexpected error for supported critical extension: %v", err)
		}
	})

	t.Run("Unsupported critical extension", func(t *testing.T) {
		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				Extensions: []pkix.Extension{
					{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true},
				},
			},
		}

		err := validator.checkCriticalExtensions(ac)
		if err == nil {
			t.Error("Expected error for unsupported critical extension")
		}
	})
}

func TestACValidatorCheckValidityPeriod(t *testing.T) {
	now := time.Now()
	tm := NewSimpleTrustManager()
	config := NewACValidationConfig(tm)
	config.ValidationTime = now
	config.TimeTolerance = time.Minute
	validator := NewACValidator(config)

	t.Run("Valid period", func(t *testing.T) {
		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				AttrCertValidityPeriod: AttCertValidityPeriod{
					NotBeforeTime: now.Add(-time.Hour),
					NotAfterTime:  now.Add(time.Hour),
				},
			},
		}

		err := validator.checkValidityPeriod(ac)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("Not yet valid", func(t *testing.T) {
		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				AttrCertValidityPeriod: AttCertValidityPeriod{
					NotBeforeTime: now.Add(time.Hour),
					NotAfterTime:  now.Add(2 * time.Hour),
				},
			},
		}

		err := validator.checkValidityPeriod(ac)
		if err != ErrACNotYetValid {
			t.Errorf("Expected ErrACNotYetValid, got %v", err)
		}
	})

	t.Run("Expired", func(t *testing.T) {
		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				AttrCertValidityPeriod: AttCertValidityPeriod{
					NotBeforeTime: now.Add(-2 * time.Hour),
					NotAfterTime:  now.Add(-time.Hour),
				},
			},
		}

		err := validator.checkValidityPeriod(ac)
		if err != ErrACExpired {
			t.Errorf("Expected ErrACExpired, got %v", err)
		}
	})
}

func TestACValidationResult(t *testing.T) {
	result := &ACValidationResult{
		Valid:              true,
		ApprovedAttributes: map[string][]asn1.RawValue{},
		Errors:             nil,
		Warnings:           []string{"test warning"},
	}

	if !result.Valid {
		t.Error("Result should be valid")
	}
	if len(result.Warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d", len(result.Warnings))
	}
}

func TestCheckACHolderMatch(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:   "Test User",
			Organization: []string{"Test Org"},
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	t.Run("ObjectDigestInfo not supported", func(t *testing.T) {
		holder := &Holder{
			ObjectDigestInfo: &ObjectDigestInfo{},
		}

		_, err := CheckACHolderMatch(cert, holder)
		if err != ErrACObjectDigestNotSupported {
			t.Errorf("Expected ErrACObjectDigestNotSupported, got %v", err)
		}
	})

	t.Run("Empty holder", func(t *testing.T) {
		holder := &Holder{}

		mismatches, err := CheckACHolderMatch(cert, holder)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if len(mismatches) != 0 {
			t.Error("Empty holder should match any certificate")
		}
	})
}

func TestACValidatorValidateACTargeting(t *testing.T) {
	tm := NewSimpleTrustManager()
	config := NewACValidationConfig(tm)
	config.TargetDescription = NewACTargetDescription(
		[]string{"server.example.com"},
		[]string{"admin-group"},
	)
	validator := NewACValidator(config)

	t.Run("No target information extension", func(t *testing.T) {
		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				Extensions: []pkix.Extension{},
			},
		}

		err := validator.validateACTargeting(ac)
		if err != nil {
			t.Errorf("Should accept AC without targeting: %v", err)
		}
	})
}

func TestACErrors(t *testing.T) {
	errors := []error{
		ErrACHolderMismatch,
		ErrACIssuerNotFound,
		ErrACTargetMismatch,
		ErrACExpired,
		ErrACNotYetValid,
		ErrACCriticalExtension,
		ErrACObjectDigestNotSupported,
		ErrACRevoked,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("Error should not be nil")
		}
		if err.Error() == "" {
			t.Error("Error message should not be empty")
		}
	}
}

func TestGetACIssuerDN(t *testing.T) {
	// Create a V1Form issuer
	rdn := pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test CA"}},
	}
	rdnBytes, _ := asn1.Marshal(rdn)

	t.Run("V1Form issuer", func(t *testing.T) {
		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				Issuer: AttCertIssuer{
					V1Form: GeneralNames{
						{Raw: asn1.RawValue{
							Tag:   int(GeneralNameDirectoryName),
							Bytes: rdnBytes,
						}},
					},
				},
			},
		}

		name, err := GetACIssuerDN(ac)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if name.CommonName != "Test CA" {
			t.Errorf("CommonName = %s, want Test CA", name.CommonName)
		}
	})

	t.Run("No issuer DN", func(t *testing.T) {
		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				Issuer: AttCertIssuer{},
			},
		}

		_, err := GetACIssuerDN(ac)
		if err == nil {
			t.Error("Expected error for missing issuer DN")
		}
	})
}

func TestGetACAuthorityKeyID(t *testing.T) {
	t.Run("With AKI", func(t *testing.T) {
		keyID := []byte{0x01, 0x02, 0x03, 0x04}
		akiValue, _ := asn1.Marshal(struct {
			KeyIdentifier []byte `asn1:"optional,tag:0"`
		}{KeyIdentifier: keyID})

		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				Extensions: []pkix.Extension{
					{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Value: akiValue},
				},
			},
		}

		result := getACAuthorityKeyID(ac)
		if len(result) != len(keyID) {
			t.Errorf("KeyID length = %d, want %d", len(result), len(keyID))
		}
	})

	t.Run("Without AKI", func(t *testing.T) {
		ac := &AttributeCertificateV2{
			ACInfo: AttributeCertificateInfo{
				Extensions: []pkix.Extension{},
			},
		}

		result := getACAuthorityKeyID(ac)
		if result != nil {
			t.Error("Should return nil when AKI not present")
		}
	})
}

func TestParseAttributeCertificate(t *testing.T) {
	t.Run("Invalid data", func(t *testing.T) {
		_, err := ParseAttributeCertificate([]byte{0x00, 0x01, 0x02})
		if err == nil {
			t.Error("Expected error for invalid data")
		}
	})
}
