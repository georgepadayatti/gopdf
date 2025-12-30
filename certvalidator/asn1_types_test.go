package certvalidator

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestOIDs(t *testing.T) {
	t.Run("OIDTargetInformation", func(t *testing.T) {
		expected := asn1.ObjectIdentifier{2, 5, 29, 55}
		if !OIDTargetInformation.Equal(expected) {
			t.Errorf("expected %v, got %v", expected, OIDTargetInformation)
		}
	})

	t.Run("OIDNoRevAvail", func(t *testing.T) {
		expected := asn1.ObjectIdentifier{2, 5, 29, 56}
		if !OIDNoRevAvail.Equal(expected) {
			t.Errorf("expected %v, got %v", expected, OIDNoRevAvail)
		}
	})

	t.Run("OIDAAControls", func(t *testing.T) {
		expected := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 6}
		if !OIDAAControls.Equal(expected) {
			t.Errorf("expected %v, got %v", expected, OIDAAControls)
		}
	})

	t.Run("OIDAuditIdentity", func(t *testing.T) {
		expected := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 4}
		if !OIDAuditIdentity.Equal(expected) {
			t.Errorf("expected %v, got %v", expected, OIDAuditIdentity)
		}
	})
}

func TestASN1GeneralName(t *testing.T) {
	t.Run("GetType with DNS name", func(t *testing.T) {
		gn := &ASN1GeneralName{
			Raw: asn1.RawValue{
				Tag: int(GeneralNameDNSName),
			},
		}
		if gn.GetType() != GeneralNameDNSName {
			t.Errorf("expected DNS name type, got %v", gn.GetType())
		}
	})

	t.Run("GetType with RFC822 name", func(t *testing.T) {
		gn := &ASN1GeneralName{
			Raw: asn1.RawValue{
				Tag: int(GeneralNameRFC822Name),
			},
		}
		if gn.GetType() != GeneralNameRFC822Name {
			t.Errorf("expected RFC822 name type, got %v", gn.GetType())
		}
	})

	t.Run("GetType with URI", func(t *testing.T) {
		gn := &ASN1GeneralName{
			Raw: asn1.RawValue{
				Tag: int(GeneralNameURI),
			},
		}
		if gn.GetType() != GeneralNameURI {
			t.Errorf("expected URI type, got %v", gn.GetType())
		}
	})
}

func TestTargetType(t *testing.T) {
	tests := []struct {
		name     string
		target   Target
		expected TargetType
	}{
		{
			name: "target with name",
			target: Target{
				TargetName: ASN1GeneralName{
					Raw: asn1.RawValue{FullBytes: []byte{0x01}},
				},
			},
			expected: TargetTypeName,
		},
		{
			name: "target with group",
			target: Target{
				TargetGroup: ASN1GeneralName{
					Raw: asn1.RawValue{FullBytes: []byte{0x01}},
				},
			},
			expected: TargetTypeGroup,
		},
		{
			name: "target with cert",
			target: Target{
				TargetCert: TargetCert{
					TargetCertificate: IssuerSerial{
						Issuer: asn1.RawValue{FullBytes: []byte{0x01}},
					},
				},
			},
			expected: TargetTypeCert,
		},
		{
			name:     "empty target",
			target:   Target{},
			expected: TargetTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.target.GetType() != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, tt.target.GetType())
			}
		})
	}
}

func TestAttrSpec(t *testing.T) {
	t.Run("Contains existing OID", func(t *testing.T) {
		spec := AttrSpec{
			asn1.ObjectIdentifier{1, 2, 3},
			asn1.ObjectIdentifier{4, 5, 6},
		}
		if !spec.Contains(asn1.ObjectIdentifier{1, 2, 3}) {
			t.Error("expected spec to contain {1, 2, 3}")
		}
		if !spec.Contains(asn1.ObjectIdentifier{4, 5, 6}) {
			t.Error("expected spec to contain {4, 5, 6}")
		}
	})

	t.Run("Contains non-existing OID", func(t *testing.T) {
		spec := AttrSpec{
			asn1.ObjectIdentifier{1, 2, 3},
		}
		if spec.Contains(asn1.ObjectIdentifier{7, 8, 9}) {
			t.Error("expected spec to not contain {7, 8, 9}")
		}
	})

	t.Run("Contains empty spec", func(t *testing.T) {
		var spec AttrSpec
		if spec.Contains(asn1.ObjectIdentifier{1, 2, 3}) {
			t.Error("empty spec should not contain any OID")
		}
	})
}

func TestAAControls(t *testing.T) {
	t.Run("Accept with no restrictions", func(t *testing.T) {
		controls := &AAControls{
			PermitUnspecified: true,
		}
		if !controls.Accept(asn1.ObjectIdentifier{1, 2, 3}) {
			t.Error("expected accept with no restrictions")
		}
	})

	t.Run("Accept with excluded", func(t *testing.T) {
		controls := &AAControls{
			ExcludedAttrs: AttrSpec{
				asn1.ObjectIdentifier{1, 2, 3},
			},
			PermitUnspecified: true,
		}
		if controls.Accept(asn1.ObjectIdentifier{1, 2, 3}) {
			t.Error("expected reject for excluded OID")
		}
		if !controls.Accept(asn1.ObjectIdentifier{4, 5, 6}) {
			t.Error("expected accept for non-excluded OID")
		}
	})

	t.Run("Accept with permitted only", func(t *testing.T) {
		controls := &AAControls{
			PermittedAttrs: AttrSpec{
				asn1.ObjectIdentifier{1, 2, 3},
			},
			PermitUnspecified: false,
		}
		if !controls.Accept(asn1.ObjectIdentifier{1, 2, 3}) {
			t.Error("expected accept for permitted OID")
		}
		if controls.Accept(asn1.ObjectIdentifier{4, 5, 6}) {
			t.Error("expected reject for non-permitted OID")
		}
	})

	t.Run("Accept with permitted and permit unspecified", func(t *testing.T) {
		controls := &AAControls{
			PermittedAttrs: AttrSpec{
				asn1.ObjectIdentifier{1, 2, 3},
			},
			PermitUnspecified: true,
		}
		if !controls.Accept(asn1.ObjectIdentifier{1, 2, 3}) {
			t.Error("expected accept for permitted OID")
		}
		if !controls.Accept(asn1.ObjectIdentifier{4, 5, 6}) {
			t.Error("expected accept for unspecified OID")
		}
	})

	t.Run("Accept with both permitted and excluded", func(t *testing.T) {
		controls := &AAControls{
			PermittedAttrs: AttrSpec{
				asn1.ObjectIdentifier{1, 2, 3},
				asn1.ObjectIdentifier{4, 5, 6},
			},
			ExcludedAttrs: AttrSpec{
				asn1.ObjectIdentifier{4, 5, 6},
			},
			PermitUnspecified: true,
		}
		if !controls.Accept(asn1.ObjectIdentifier{1, 2, 3}) {
			t.Error("expected accept for permitted OID")
		}
		if controls.Accept(asn1.ObjectIdentifier{4, 5, 6}) {
			t.Error("expected reject for excluded OID (excluded takes precedence)")
		}
	})
}

func TestParseAAControls(t *testing.T) {
	t.Run("Valid AA controls", func(t *testing.T) {
		// Create a simple AAControls structure
		controls := AAControls{
			PathLenConstraint: 2,
			PermitUnspecified: true,
		}
		data, err := asn1.Marshal(controls)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		parsed, err := ParseAAControls(data)
		if err != nil {
			t.Fatalf("failed to parse: %v", err)
		}
		if parsed.PathLenConstraint != 2 {
			t.Errorf("expected path length 2, got %d", parsed.PathLenConstraint)
		}
	})

	t.Run("Invalid data", func(t *testing.T) {
		_, err := ParseAAControls([]byte{0xFF, 0xFF})
		if err == nil {
			t.Error("expected error for invalid data")
		}
	})
}

func createCertWithExtension(oid asn1.ObjectIdentifier, value []byte) *x509.Certificate {
	return &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Test"},
		SerialNumber: big.NewInt(1),
		Extensions: []pkix.Extension{
			{
				Id:    oid,
				Value: value,
			},
		},
	}
}

func TestHasNoRevAvail(t *testing.T) {
	t.Run("Certificate with no_rev_avail", func(t *testing.T) {
		nullValue, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagNull})
		cert := createCertWithExtension(OIDNoRevAvail, nullValue)
		if !HasNoRevAvail(cert) {
			t.Error("expected HasNoRevAvail to return true")
		}
	})

	t.Run("Certificate without no_rev_avail", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:      pkix.Name{CommonName: "Test"},
			SerialNumber: big.NewInt(1),
		}
		if HasNoRevAvail(cert) {
			t.Error("expected HasNoRevAvail to return false")
		}
	})
}

func TestExtensionRegistry(t *testing.T) {
	t.Run("NewExtensionRegistry", func(t *testing.T) {
		reg := NewExtensionRegistry()
		if reg == nil {
			t.Fatal("expected non-nil registry")
		}
		if len(reg.OIDMap) == 0 {
			t.Error("expected non-empty OID map")
		}
	})

	t.Run("GetExtensionName for known OID", func(t *testing.T) {
		reg := NewExtensionRegistry()
		name := reg.GetExtensionName(OIDTargetInformation)
		if name != "target_information" {
			t.Errorf("expected 'target_information', got %s", name)
		}
	})

	t.Run("GetExtensionName for unknown OID", func(t *testing.T) {
		reg := NewExtensionRegistry()
		oid := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
		name := reg.GetExtensionName(oid)
		if name != oid.String() {
			t.Errorf("expected OID string, got %s", name)
		}
	})

	t.Run("RegisterExtension", func(t *testing.T) {
		reg := NewExtensionRegistry()
		customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
		reg.RegisterExtension(customOID, "custom_extension")
		name := reg.GetExtensionName(customOID)
		if name != "custom_extension" {
			t.Errorf("expected 'custom_extension', got %s", name)
		}
	})

	t.Run("DefaultExtensionRegistry", func(t *testing.T) {
		if DefaultExtensionRegistry == nil {
			t.Fatal("expected non-nil default registry")
		}
		name := DefaultExtensionRegistry.GetExtensionName(OIDAAControls)
		if name != "aa_controls" {
			t.Errorf("expected 'aa_controls', got %s", name)
		}
	})
}

func TestTargets(t *testing.T) {
	t.Run("Empty Targets", func(t *testing.T) {
		var targets Targets
		if len(targets) != 0 {
			t.Errorf("expected empty targets, got %d", len(targets))
		}
	})

	t.Run("Targets with entries", func(t *testing.T) {
		targets := Targets{
			{TargetName: ASN1GeneralName{Raw: asn1.RawValue{FullBytes: []byte{1}}}},
			{TargetGroup: ASN1GeneralName{Raw: asn1.RawValue{FullBytes: []byte{2}}}},
		}
		if len(targets) != 2 {
			t.Errorf("expected 2 targets, got %d", len(targets))
		}
	})
}

func TestSequenceOfTargets(t *testing.T) {
	t.Run("Empty SequenceOfTargets", func(t *testing.T) {
		var seq SequenceOfTargets
		if len(seq) != 0 {
			t.Errorf("expected empty sequence, got %d", len(seq))
		}
	})

	t.Run("SequenceOfTargets with entries", func(t *testing.T) {
		seq := SequenceOfTargets{
			Targets{
				{TargetName: ASN1GeneralName{Raw: asn1.RawValue{FullBytes: []byte{1}}}},
			},
			Targets{
				{TargetGroup: ASN1GeneralName{Raw: asn1.RawValue{FullBytes: []byte{2}}}},
			},
		}
		if len(seq) != 2 {
			t.Errorf("expected 2 targets sequences, got %d", len(seq))
		}
	})
}

func TestIssuerSerial(t *testing.T) {
	t.Run("Empty IssuerSerial", func(t *testing.T) {
		var is IssuerSerial
		if is.Issuer.FullBytes != nil {
			t.Error("expected empty issuer")
		}
	})
}

func TestObjectDigestInfo(t *testing.T) {
	t.Run("ObjectDigestInfo fields", func(t *testing.T) {
		odi := ObjectDigestInfo{
			DigestedObjectType: asn1.Enumerated(0),
			DigestAlgorithm: AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			},
			ObjectDigest: asn1.BitString{Bytes: []byte{1, 2, 3}},
		}
		if int(odi.DigestedObjectType) != 0 {
			t.Errorf("expected type 0, got %d", odi.DigestedObjectType)
		}
	})
}

func TestAlgorithmIdentifier(t *testing.T) {
	t.Run("SHA256 algorithm", func(t *testing.T) {
		ai := AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
		}
		if !ai.Algorithm.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}) {
			t.Error("expected SHA256 OID")
		}
	})
}

func TestTargetCert(t *testing.T) {
	t.Run("TargetCert with issuer serial", func(t *testing.T) {
		tc := TargetCert{
			TargetCertificate: IssuerSerial{
				Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
				SerialNumber: asn1.RawValue{Bytes: []byte{1}},
			},
		}
		if tc.TargetCertificate.Issuer.FullBytes == nil {
			t.Error("expected issuer to be set")
		}
	})
}
