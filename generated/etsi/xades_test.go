package etsi

import (
	"encoding/xml"
	"testing"
	"time"
)

func TestXAdESNamespace(t *testing.T) {
	expected := "http://uri.etsi.org/01903/v1.3.2#"
	if XAdESNamespace != expected {
		t.Errorf("XAdESNamespace = %q, want %q", XAdESNamespace, expected)
	}
}

func TestQualifierType(t *testing.T) {
	tests := []struct {
		name     string
		q        QualifierType
		expected string
	}{
		{"OIDAsURI", QualifierOIDAsURI, "OIDAsURI"},
		{"OIDAsURN", QualifierOIDAsURN, "OIDAsURN"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.q) != tc.expected {
				t.Errorf("got %q, want %q", tc.q, tc.expected)
			}
		})
	}
}

func TestNewQualifyingProperties(t *testing.T) {
	qp := NewQualifyingProperties("#sig-id")
	if qp == nil {
		t.Fatal("NewQualifyingProperties() returned nil")
	}
	if qp.Target != "#sig-id" {
		t.Errorf("Target = %q, want %q", qp.Target, "#sig-id")
	}
}

func TestNewSignedProperties(t *testing.T) {
	sp := NewSignedProperties()
	if sp == nil {
		t.Fatal("NewSignedProperties() returned nil")
	}
}

func TestNewUnsignedProperties(t *testing.T) {
	up := NewUnsignedProperties()
	if up == nil {
		t.Fatal("NewUnsignedProperties() returned nil")
	}
}

func TestSignatureProductionPlaceMarshal(t *testing.T) {
	spp := SignatureProductionPlace{
		SignatureProductionPlaceType: SignatureProductionPlaceType{
			City:            "Berlin",
			StateOrProvince: "Berlin",
			PostalCode:      "10115",
			CountryName:     "Germany",
		},
	}

	data, err := xml.MarshalIndent(spp, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent failed: %v", err)
	}

	var parsed SignatureProductionPlace
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.City != "Berlin" {
		t.Errorf("City = %q, want %q", parsed.City, "Berlin")
	}
	if parsed.CountryName != "Germany" {
		t.Errorf("CountryName = %q, want %q", parsed.CountryName, "Germany")
	}
}

func TestSignerRoleMarshal(t *testing.T) {
	sr := SignerRole{
		SignerRoleType: SignerRoleType{
			ClaimedRoles: &ClaimedRolesListType{
				ClaimedRole: []AnyType{
					{Content: []byte("<Role>Signer</Role>")},
				},
			},
		},
	}

	data, err := xml.Marshal(sr)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed SignerRole
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.ClaimedRoles == nil {
		t.Fatal("ClaimedRoles should not be nil")
	}
	if len(parsed.ClaimedRoles.ClaimedRole) != 1 {
		t.Errorf("expected 1 ClaimedRole, got %d", len(parsed.ClaimedRoles.ClaimedRole))
	}
}

func TestCertificateValuesType(t *testing.T) {
	// Test basic struct creation and field access
	cv := CertificateValuesType{
		EncapsulatedX509Certificate: []EncapsulatedPKIDataType{
			{Value: []byte("cert1"), ID: "cert-1"},
			{Value: []byte("cert2"), ID: "cert-2"},
		},
		ID: "cert-values-1",
	}

	if len(cv.EncapsulatedX509Certificate) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(cv.EncapsulatedX509Certificate))
	}
	if cv.ID != "cert-values-1" {
		t.Errorf("ID = %q, want %q", cv.ID, "cert-values-1")
	}
	if cv.EncapsulatedX509Certificate[0].ID != "cert-1" {
		t.Errorf("first cert ID = %q, want %q", cv.EncapsulatedX509Certificate[0].ID, "cert-1")
	}
}

func TestRevocationValuesMarshal(t *testing.T) {
	rv := RevocationValues{
		RevocationValuesType: RevocationValuesType{
			CRLValues: &CRLValuesType{
				EncapsulatedCRLValue: []EncapsulatedPKIDataType{
					{Value: []byte("crl1")},
				},
			},
			OCSPValues: &OCSPValuesType{
				EncapsulatedOCSPValue: []EncapsulatedPKIDataType{
					{Value: []byte("ocsp1")},
				},
			},
			ID: "rev-values-1",
		},
	}

	data, err := xml.Marshal(rv)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed RevocationValues
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.CRLValues == nil {
		t.Fatal("CRLValues should not be nil")
	}
	if parsed.OCSPValues == nil {
		t.Fatal("OCSPValues should not be nil")
	}
}

func TestQualifyingPropertiesMarshal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	qp := QualifyingProperties{
		QualifyingPropertiesType: QualifyingPropertiesType{
			Target: "#signature-id",
			ID:     "qp-1",
			SignedProperties: &SignedPropertiesType{
				ID: "sp-1",
				SignedSignatureProperties: &SignedSignaturePropertiesType{
					SigningTime: &now,
					SignatureProductionPlace: &SignatureProductionPlaceType{
						City:        "Paris",
						CountryName: "France",
					},
				},
			},
		},
	}

	data, err := xml.MarshalIndent(qp, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent failed: %v", err)
	}

	var parsed QualifyingProperties
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Target != "#signature-id" {
		t.Errorf("Target = %q, want %q", parsed.Target, "#signature-id")
	}
	if parsed.ID != "qp-1" {
		t.Errorf("ID = %q, want %q", parsed.ID, "qp-1")
	}
	if parsed.SignedProperties == nil {
		t.Fatal("SignedProperties should not be nil")
	}
	if parsed.SignedProperties.SignedSignatureProperties == nil {
		t.Fatal("SignedSignatureProperties should not be nil")
	}
	if parsed.SignedProperties.SignedSignatureProperties.SignatureProductionPlace == nil {
		t.Fatal("SignatureProductionPlace should not be nil")
	}
	if parsed.SignedProperties.SignedSignatureProperties.SignatureProductionPlace.City != "Paris" {
		t.Error("City mismatch")
	}
}

func TestXAdESTimeStampType(t *testing.T) {
	// Test basic struct creation and field access
	ts := XAdESTimeStampType{
		ID: "ts-1",
		EncapsulatedTimeStamp: []EncapsulatedPKIDataType{
			{Value: []byte("timestamp-token"), ID: "ets-1"},
		},
	}

	if ts.ID != "ts-1" {
		t.Errorf("ID = %q, want %q", ts.ID, "ts-1")
	}
	if len(ts.EncapsulatedTimeStamp) != 1 {
		t.Errorf("expected 1 EncapsulatedTimeStamp, got %d", len(ts.EncapsulatedTimeStamp))
	}
	if ts.EncapsulatedTimeStamp[0].ID != "ets-1" {
		t.Errorf("EncapsulatedTimeStamp ID = %q, want %q", ts.EncapsulatedTimeStamp[0].ID, "ets-1")
	}
}

func TestObjectIdentifierMarshal(t *testing.T) {
	oi := ObjectIdentifier{
		ObjectIdentifierType: ObjectIdentifierType{
			Identifier: &IdentifierType{
				Value:     "1.2.3.4.5",
				Qualifier: QualifierOIDAsURN,
			},
			Description: "Test OID",
		},
	}

	data, err := xml.Marshal(oi)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed ObjectIdentifier
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Identifier == nil {
		t.Fatal("Identifier should not be nil")
	}
	if parsed.Identifier.Value != "1.2.3.4.5" {
		t.Error("Identifier value mismatch")
	}
	if parsed.Identifier.Qualifier != QualifierOIDAsURN {
		t.Error("Identifier qualifier mismatch")
	}
}

func TestIncludeTypeMarshal(t *testing.T) {
	referencedData := true
	inc := IncludeType{
		URI:            "#ref-1",
		ReferencedData: &referencedData,
	}

	data, err := xml.Marshal(inc)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed IncludeType
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.URI != "#ref-1" {
		t.Error("URI mismatch")
	}
}

func TestDataObjectFormatMarshal(t *testing.T) {
	dof := DataObjectFormat{
		DataObjectFormatType: DataObjectFormatType{
			ObjectReference: "#data-1",
			MimeType:        "application/pdf",
			Description:     "PDF document",
		},
	}

	data, err := xml.Marshal(dof)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed DataObjectFormat
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.ObjectReference != "#data-1" {
		t.Error("ObjectReference mismatch")
	}
	if parsed.MimeType != "application/pdf" {
		t.Error("MimeType mismatch")
	}
}

func TestCommitmentTypeIndicationMarshal(t *testing.T) {
	cti := CommitmentTypeIndication{
		CommitmentTypeIndicationType: CommitmentTypeIndicationType{
			CommitmentTypeId: &ObjectIdentifierType{
				Identifier: &IdentifierType{
					Value: "http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin",
				},
			},
			AllSignedDataObjects: &struct{}{},
		},
	}

	data, err := xml.Marshal(cti)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed CommitmentTypeIndication
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.CommitmentTypeId == nil {
		t.Fatal("CommitmentTypeId should not be nil")
	}
	if parsed.AllSignedDataObjects == nil {
		t.Fatal("AllSignedDataObjects should not be nil")
	}
}
