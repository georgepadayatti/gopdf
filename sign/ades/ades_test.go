package ades

import (
	"encoding/asn1"
	"testing"
)

func TestCommitmentTypeString(t *testing.T) {
	tests := []struct {
		commitment CommitmentType
		expected   string
	}{
		{CommitmentProofOfOrigin, "proof_of_origin"},
		{CommitmentProofOfReceipt, "proof_of_receipt"},
		{CommitmentProofOfDelivery, "proof_of_delivery"},
		{CommitmentProofOfSender, "proof_of_sender"},
		{CommitmentProofOfApproval, "proof_of_approval"},
		{CommitmentProofOfCreation, "proof_of_creation"},
		{CommitmentType(99), "unknown"},
	}

	for _, tt := range tests {
		result := tt.commitment.String()
		if result != tt.expected {
			t.Errorf("CommitmentType(%d).String() = %s, want %s", tt.commitment, result, tt.expected)
		}
	}
}

func TestCommitmentTypeOID(t *testing.T) {
	tests := []struct {
		commitment CommitmentType
		expected   asn1.ObjectIdentifier
	}{
		{CommitmentProofOfOrigin, OIDProofOfOrigin},
		{CommitmentProofOfReceipt, OIDProofOfReceipt},
		{CommitmentProofOfDelivery, OIDProofOfDelivery},
		{CommitmentProofOfSender, OIDProofOfSender},
		{CommitmentProofOfApproval, OIDProofOfApproval},
		{CommitmentProofOfCreation, OIDProofOfCreation},
	}

	for _, tt := range tests {
		result := tt.commitment.OID()
		if !result.Equal(tt.expected) {
			t.Errorf("CommitmentType(%d).OID() = %v, want %v", tt.commitment, result, tt.expected)
		}
	}
}

func TestCommitmentTypeOIDUnknown(t *testing.T) {
	result := CommitmentType(99).OID()
	if result != nil {
		t.Error("Unknown commitment type should return nil OID")
	}
}

func TestNewCommitmentTypeIndication(t *testing.T) {
	indication := NewCommitmentTypeIndication(CommitmentProofOfApproval)

	if indication == nil {
		t.Fatal("NewCommitmentTypeIndication returned nil")
	}

	if !indication.CommitmentTypeID.Equal(OIDProofOfApproval) {
		t.Errorf("Expected OID %v, got %v", OIDProofOfApproval, indication.CommitmentTypeID)
	}
}

func TestCommitmentTypeIndicationMarshal(t *testing.T) {
	indication := NewCommitmentTypeIndication(CommitmentProofOfOrigin)

	data, err := indication.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshal returned empty data")
	}
}

func TestQcCertificateTypeString(t *testing.T) {
	tests := []struct {
		qcType   QcCertificateType
		expected string
	}{
		{QcTypeEsign, "qct_esign"},
		{QcTypeEseal, "qct_eseal"},
		{QcTypeWeb, "qct_web"},
		{QcCertificateType(99), "unknown"},
	}

	for _, tt := range tests {
		result := tt.qcType.String()
		if result != tt.expected {
			t.Errorf("QcCertificateType(%d).String() = %s, want %s", tt.qcType, result, tt.expected)
		}
	}
}

func TestQcCertificateTypeOID(t *testing.T) {
	tests := []struct {
		qcType   QcCertificateType
		expected asn1.ObjectIdentifier
	}{
		{QcTypeEsign, OIDQctEsign},
		{QcTypeEseal, OIDQctEseal},
		{QcTypeWeb, OIDQctWeb},
	}

	for _, tt := range tests {
		result := tt.qcType.OID()
		if !result.Equal(tt.expected) {
			t.Errorf("QcCertificateType(%d).OID() = %v, want %v", tt.qcType, result, tt.expected)
		}
	}
}

func TestQcCertificateTypeOIDUnknown(t *testing.T) {
	result := QcCertificateType(99).OID()
	if result != nil {
		t.Error("Unknown QC type should return nil OID")
	}
}

func TestComputePolicyHash(t *testing.T) {
	policyDoc := []byte("test policy document")
	hash := ComputePolicyHash(policyDoc)

	if len(hash) != 32 { // SHA-256 produces 32 bytes
		t.Errorf("Expected 32 byte hash, got %d bytes", len(hash))
	}

	// Same input should produce same hash
	hash2 := ComputePolicyHash(policyDoc)
	for i := range hash {
		if hash[i] != hash2[i] {
			t.Error("Same input should produce same hash")
			break
		}
	}
}

func TestNewSignaturePolicyId(t *testing.T) {
	policyOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	policyDoc := []byte("test policy")

	policyId := NewSignaturePolicyId(policyOID, policyDoc)

	if policyId == nil {
		t.Fatal("NewSignaturePolicyId returned nil")
	}

	if !policyId.SigPolicyID.Equal(policyOID) {
		t.Errorf("Expected policy OID %v, got %v", policyOID, policyId.SigPolicyID)
	}

	if len(policyId.SigPolicyHash.Digest) != 32 {
		t.Errorf("Expected 32 byte hash, got %d bytes", len(policyId.SigPolicyHash.Digest))
	}
}

func TestSignaturePolicyIdMarshal(t *testing.T) {
	policyOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	policyDoc := []byte("test policy")

	policyId := NewSignaturePolicyId(policyOID, policyDoc)

	data, err := policyId.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshal returned empty data")
	}
}

func TestSignerAttributesV2Marshal(t *testing.T) {
	attrs := &SignerAttributesV2{
		ClaimedAttributes: []Attribute{
			{
				Type:   asn1.ObjectIdentifier{1, 2, 3},
				Values: []asn1.RawValue{},
			},
		},
	}

	data, err := attrs.Marshal()
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
		{"OIDProofOfOrigin", OIDProofOfOrigin},
		{"OIDProofOfReceipt", OIDProofOfReceipt},
		{"OIDSignaturePolicyIdentifier", OIDSignaturePolicyIdentifier},
		{"OIDCommitmentType", OIDCommitmentType},
		{"OIDQcCompliance", OIDQcCompliance},
		{"OIDQcType", OIDQcType},
	}

	for _, tt := range tests {
		if len(tt.oid) == 0 {
			t.Errorf("%s OID is empty", tt.name)
		}
	}
}

func TestCAdESSignedAttrSpec(t *testing.T) {
	spec := &CAdESSignedAttrSpec{
		CommitmentType:   NewCommitmentTypeIndication(CommitmentProofOfOrigin),
		TimestampContent: true,
	}

	if spec.CommitmentType == nil {
		t.Error("CommitmentType should not be nil")
	}

	if !spec.TimestampContent {
		t.Error("TimestampContent should be true")
	}
}

func TestSignerAttrSpec(t *testing.T) {
	spec := &SignerAttrSpec{
		ClaimedAttrs: []Attribute{
			{
				Type: asn1.ObjectIdentifier{1, 2, 3},
			},
		},
		CertifiedAttrs: [][]byte{
			{0x30, 0x00},
		},
	}

	if len(spec.ClaimedAttrs) != 1 {
		t.Errorf("Expected 1 claimed attr, got %d", len(spec.ClaimedAttrs))
	}

	if len(spec.CertifiedAttrs) != 1 {
		t.Errorf("Expected 1 certified attr, got %d", len(spec.CertifiedAttrs))
	}
}

func TestMonetaryValue(t *testing.T) {
	mv := MonetaryValue{
		Currency: Iso4217CurrencyCode{Alphabetic: "EUR"},
		Amount:   1000,
		Exponent: 2,
	}

	if mv.Currency.Alphabetic != "EUR" {
		t.Errorf("Expected EUR, got %s", mv.Currency.Alphabetic)
	}

	if mv.Amount != 1000 {
		t.Errorf("Expected 1000, got %d", mv.Amount)
	}
}

func TestPKIDisclosureStatement(t *testing.T) {
	pds := PKIDisclosureStatement{
		URL:      "https://example.com/pds",
		Language: "en",
	}

	if pds.URL != "https://example.com/pds" {
		t.Errorf("Unexpected URL: %s", pds.URL)
	}

	if pds.Language != "en" {
		t.Errorf("Unexpected language: %s", pds.Language)
	}
}

func TestQcStatement(t *testing.T) {
	stmt := QcStatement{
		StatementID: OIDQcCompliance,
	}

	if !stmt.StatementID.Equal(OIDQcCompliance) {
		t.Error("Statement ID mismatch")
	}
}

func TestSignaturePolicyStore(t *testing.T) {
	store := SignaturePolicyStore{
		SPDocSpec: SPDocSpecification{
			OID: asn1.ObjectIdentifier{1, 2, 3},
			URI: "https://example.com/policy",
		},
		SPDocument: SignaturePolicyDocument{
			SigPolicyEncoded:  []byte("policy"),
			SigPolicyLocalURI: "file:///local/policy",
		},
	}

	if store.SPDocSpec.URI != "https://example.com/policy" {
		t.Error("Unexpected URI")
	}

	if string(store.SPDocument.SigPolicyEncoded) != "policy" {
		t.Error("Unexpected policy content")
	}
}

func TestDisplayText(t *testing.T) {
	dt := DisplayText{
		UTF8String: "Hello World",
	}

	if dt.UTF8String != "Hello World" {
		t.Errorf("Unexpected text: %s", dt.UTF8String)
	}
}

func TestNoticeReference(t *testing.T) {
	nr := NoticeReference{
		Organization: DisplayText{UTF8String: "Test Org"},
		NoticeNumbers: []int{1, 2, 3},
	}

	if nr.Organization.UTF8String != "Test Org" {
		t.Error("Unexpected organization")
	}

	if len(nr.NoticeNumbers) != 3 {
		t.Errorf("Expected 3 notice numbers, got %d", len(nr.NoticeNumbers))
	}
}

func TestSPUserNotice(t *testing.T) {
	explicitText := DisplayText{UTF8String: "This is a notice"}
	notice := SPUserNotice{
		ExplicitText: &explicitText,
	}

	if notice.ExplicitText.UTF8String != "This is a notice" {
		t.Error("Unexpected explicit text")
	}
}

func TestSignaturePolicyIdentifier(t *testing.T) {
	// Test implied policy
	implied := SignaturePolicyIdentifier{
		SignaturePolicyImplied: true,
	}

	if !implied.SignaturePolicyImplied {
		t.Error("Expected implied policy")
	}

	// Test explicit policy
	policyId := NewSignaturePolicyId(asn1.ObjectIdentifier{1, 2, 3}, []byte("policy"))
	explicit := SignaturePolicyIdentifier{
		SignaturePolicyId: policyId,
	}

	if explicit.SignaturePolicyId == nil {
		t.Error("Expected explicit policy ID")
	}
}
