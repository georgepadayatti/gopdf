package etsi

import (
	"encoding/xml"
	"testing"
	"time"
)

func TestTS11910202Namespace(t *testing.T) {
	expected := "http://uri.etsi.org/19102/v1.2.1#"
	if TS11910202Namespace != expected {
		t.Errorf("TS11910202Namespace = %q, want %q", TS11910202Namespace, expected)
	}
}

func TestEndorsementType(t *testing.T) {
	tests := []struct {
		name     string
		et       EndorsementType
		expected string
	}{
		{"certified", EndorsementCertified, "certified"},
		{"claimed", EndorsementClaimed, "claimed"},
		{"signed", EndorsementSigned, "signed"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.et) != tc.expected {
				t.Errorf("got %q, want %q", tc.et, tc.expected)
			}
		})
	}
}

func TestMainIndicationConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"Passed", MainIndicationPassed, "urn:etsi:019102:mainindication:total-passed"},
		{"Failed", MainIndicationFailed, "urn:etsi:019102:mainindication:total-failed"},
		{"Indeterminate", MainIndicationIndeterminate, "urn:etsi:019102:mainindication:indeterminate"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.constant != tc.expected {
				t.Errorf("got %q, want %q", tc.constant, tc.expected)
			}
		})
	}
}

func TestNewValidationReport(t *testing.T) {
	vr := NewValidationReport()
	if vr == nil {
		t.Fatal("NewValidationReport() returned nil")
	}
}

func TestValidationReportAddSignatureReport(t *testing.T) {
	vr := NewValidationReport()

	report := &SignatureValidationReportType{
		SignatureValidationStatus: &ValidationStatusType{
			MainIndication: MainIndicationPassed,
		},
	}

	vr.AddSignatureReport(report)

	if len(vr.SignatureValidationReport) != 1 {
		t.Errorf("expected 1 report, got %d", len(vr.SignatureValidationReport))
	}
}

func TestValidationReportGetPassedReports(t *testing.T) {
	vr := createTestValidationReport()

	passed := vr.GetPassedReports()
	if len(passed) != 1 {
		t.Errorf("expected 1 passed report, got %d", len(passed))
	}
}

func TestValidationReportGetFailedReports(t *testing.T) {
	vr := createTestValidationReport()

	failed := vr.GetFailedReports()
	if len(failed) != 1 {
		t.Errorf("expected 1 failed report, got %d", len(failed))
	}
}

func createTestValidationReport() *ValidationReport {
	vr := NewValidationReport()

	// Add a passed report
	vr.AddSignatureReport(&SignatureValidationReportType{
		SignatureIdentifier: &SignatureIdentifierType{
			HashOnly:    true,
			DocHashOnly: false,
			ID:          "sig-1",
		},
		SignatureValidationStatus: &ValidationStatusType{
			MainIndication: MainIndicationPassed,
		},
	})

	// Add a failed report
	vr.AddSignatureReport(&SignatureValidationReportType{
		SignatureIdentifier: &SignatureIdentifierType{
			HashOnly:    false,
			DocHashOnly: false,
			ID:          "sig-2",
		},
		SignatureValidationStatus: &ValidationStatusType{
			MainIndication: MainIndicationFailed,
			SubIndication:  []string{"FORMAT_FAILURE"},
		},
	})

	// Add an indeterminate report
	vr.AddSignatureReport(&SignatureValidationReportType{
		SignatureIdentifier: &SignatureIdentifierType{
			HashOnly:    false,
			DocHashOnly: false,
			ID:          "sig-3",
		},
		SignatureValidationStatus: &ValidationStatusType{
			MainIndication: MainIndicationIndeterminate,
			SubIndication:  []string{"NO_POE"},
		},
	})

	return vr
}

func TestValidationReportMarshal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	vr := ValidationReport{
		ValidationReportType: ValidationReportType{
			SignatureValidationReport: []SignatureValidationReportType{
				{
					SignatureIdentifier: &SignatureIdentifierType{
						HashOnly:    true,
						DocHashOnly: false,
						ID:          "sig-1",
					},
					ValidationTimeInfo: &ValidationTimeInfoType{
						ValidationTime: &now,
					},
					SignatureValidationStatus: &ValidationStatusType{
						MainIndication: MainIndicationPassed,
					},
				},
			},
		},
	}

	data, err := xml.MarshalIndent(vr, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent failed: %v", err)
	}

	var parsed ValidationReport
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.SignatureValidationReport) != 1 {
		t.Fatalf("expected 1 report, got %d", len(parsed.SignatureValidationReport))
	}

	report := parsed.SignatureValidationReport[0]
	if report.SignatureIdentifier == nil {
		t.Fatal("SignatureIdentifier should not be nil")
	}
	if report.SignatureIdentifier.ID != "sig-1" {
		t.Error("SignatureIdentifier.ID mismatch")
	}
	if report.SignatureValidationStatus == nil {
		t.Fatal("SignatureValidationStatus should not be nil")
	}
	if report.SignatureValidationStatus.MainIndication != MainIndicationPassed {
		t.Error("MainIndication mismatch")
	}
}

func TestSignatureAttributesMarshal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	sa := SignatureAttributesType{
		SigningTime: []SASigningTimeType{
			{
				AttributeBaseType: AttributeBaseType{
					Signed: boolPtr(true),
				},
				Time: &now,
			},
		},
		MessageDigest: []SAMessageDigestType{
			{
				Digest: []byte("test-digest"),
			},
		},
		DataObjectFormat: []SADataObjectFormatType{
			{
				MimeType: "application/pdf",
			},
		},
	}

	data, err := xml.Marshal(sa)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed SignatureAttributesType
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.SigningTime) != 1 {
		t.Errorf("expected 1 SigningTime, got %d", len(parsed.SigningTime))
	}
	if len(parsed.MessageDigest) != 1 {
		t.Errorf("expected 1 MessageDigest, got %d", len(parsed.MessageDigest))
	}
}

func TestSignerInformationMarshal(t *testing.T) {
	pseudonym := false
	si := SignerInformationType{
		SignerCertificate: &VOReferenceType{
			VOReference: []string{"cert-1"},
		},
		Signer:    "CN=Test Signer,O=Test Org",
		Pseudonym: &pseudonym,
	}

	data, err := xml.Marshal(si)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed SignerInformationType
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Signer != "CN=Test Signer,O=Test Org" {
		t.Error("Signer mismatch")
	}
}

func TestValidationObjectMarshal(t *testing.T) {
	vo := ValidationObjectType{
		ObjectType: "urn:etsi:019102:validationObject:certificate",
		ValidationObjectRepresentation: &ValidationObjectRepresentationType{
			Base64: []byte("test-certificate-data"),
		},
		ID: "vo-1",
	}

	data, err := xml.Marshal(vo)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed ValidationObjectType
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.ID != "vo-1" {
		t.Error("ID mismatch")
	}
	if parsed.ObjectType != "urn:etsi:019102:validationObject:certificate" {
		t.Error("ObjectType mismatch")
	}
}

func TestCertificateChainMarshal(t *testing.T) {
	cc := CertificateChainType{
		SigningCertificate: &VOReferenceType{
			VOReference: []string{"cert-1"},
		},
		IntermediateCertificate: []VOReferenceType{
			{VOReference: []string{"cert-2"}},
			{VOReference: []string{"cert-3"}},
		},
		TrustAnchor: &VOReferenceType{
			VOReference: []string{"cert-4"},
		},
	}

	data, err := xml.Marshal(cc)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed CertificateChainType
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.IntermediateCertificate) != 2 {
		t.Errorf("expected 2 intermediate certificates, got %d", len(parsed.IntermediateCertificate))
	}
}

func TestPOETypeMarshal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	poe := POEType{
		POETime:     &now,
		TypeOfProof: "urn:etsi:019102:poetype:validation",
		POEObject: &VOReferenceType{
			VOReference: []string{"ts-1"},
		},
	}

	data, err := xml.Marshal(poe)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed POEType
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.TypeOfProof != "urn:etsi:019102:poetype:validation" {
		t.Error("TypeOfProof mismatch")
	}
}

func TestValidationStatusMarshal(t *testing.T) {
	vs := ValidationStatusType{
		MainIndication: MainIndicationFailed,
		SubIndication:  []string{"HASH_FAILURE", "SIG_CRYPTO_FAILURE"},
		AssociatedValidationReportData: []ValidationReportDataType{
			{
				CryptoInformation: []CryptoInformationType{
					{
						Algorithm:       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
						SecureAlgorithm: true,
					},
				},
			},
		},
	}

	data, err := xml.Marshal(vs)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed ValidationStatusType
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.MainIndication != MainIndicationFailed {
		t.Error("MainIndication mismatch")
	}
	if len(parsed.SubIndication) != 2 {
		t.Errorf("expected 2 sub-indications, got %d", len(parsed.SubIndication))
	}
}

func TestSignerRoleTypeMarshal(t *testing.T) {
	sr := SASignerRoleType{
		AttributeBaseType: AttributeBaseType{
			Signed: boolPtr(true),
		},
		RoleDetails: []SAOneSignerRoleType{
			{
				Role:            "Manager",
				EndorsementType: EndorsementClaimed,
			},
			{
				Role:            "Authorized Signatory",
				EndorsementType: EndorsementCertified,
			},
		},
	}

	data, err := xml.Marshal(sr)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed SASignerRoleType
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.RoleDetails) != 2 {
		t.Errorf("expected 2 roles, got %d", len(parsed.RoleDetails))
	}
	if parsed.RoleDetails[0].EndorsementType != EndorsementClaimed {
		t.Error("First role endorsement type mismatch")
	}
}

func TestConstraintStatusMarshal(t *testing.T) {
	cs := ConstraintStatusType{
		Status:       "VALID",
		OverriddenBy: "policy-override",
	}

	data, err := xml.Marshal(cs)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed ConstraintStatusType
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Status != "VALID" {
		t.Error("Status mismatch")
	}
	if parsed.OverriddenBy != "policy-override" {
		t.Error("OverriddenBy mismatch")
	}
}

func TestSignatureProductionPlaceTypeMarshal(t *testing.T) {
	signed := true
	spp := SASignatureProductionPlaceType{
		AttributeBaseType: AttributeBaseType{
			Signed: &signed,
		},
		AddressString: []string{"Berlin", "Germany"},
	}

	data, err := xml.Marshal(spp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed SASignatureProductionPlaceType
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.AddressString) != 2 {
		t.Errorf("expected 2 address strings, got %d", len(parsed.AddressString))
	}
}

// Helper function
func boolPtr(b bool) *bool {
	return &b
}
