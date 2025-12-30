// Package ades provides Advanced Electronic Signature (AdES) support.
// This includes CAdES (CMS Advanced Electronic Signatures) and PAdES
// (PDF Advanced Electronic Signatures) functionality.
package ades

import (
	"crypto/sha256"
	"encoding/asn1"
	"errors"
)

// Common errors
var (
	ErrInvalidOID        = errors.New("invalid OID")
	ErrInvalidCommitment = errors.New("invalid commitment type")
	ErrInvalidPolicyID   = errors.New("invalid signature policy identifier")
	ErrMissingAttribute  = errors.New("missing required attribute")
)

// OID definitions for CAdES
var (
	// Commitment Type OIDs from ETSI TS 119 172-1, RFC 5126
	OIDProofOfOrigin   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 6, 1}
	OIDProofOfReceipt  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 6, 2}
	OIDProofOfDelivery = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 6, 3}
	OIDProofOfSender   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 6, 4}
	OIDProofOfApproval = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 6, 5}
	OIDProofOfCreation = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 6, 6}

	// Signature Policy Qualifier OIDs from RFC 5126
	OIDSPUri        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 5, 1}
	OIDSPUserNotice = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 5, 2}
	OIDSPDocSpec    = asn1.ObjectIdentifier{0, 4, 0, 19122, 2, 1}

	// CMS Attribute OIDs
	OIDSignaturePolicyIdentifier = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 15}
	OIDCommitmentType            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 16}
	OIDContentTimeStamp          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 20}
	OIDMimeType                  = asn1.ObjectIdentifier{0, 4, 0, 1733, 2, 1}
	OIDSignerAttributesV2        = asn1.ObjectIdentifier{0, 4, 0, 19122, 1, 1}
	OIDClaimedSAML               = asn1.ObjectIdentifier{0, 4, 0, 19122, 1, 2}
	OIDSignaturePolicyStore      = asn1.ObjectIdentifier{0, 4, 0, 19122, 1, 3}

	// QC Statement OIDs from ETSI EN 319 412-5
	OIDQcCompliance              = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}
	OIDQcLimitValue              = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 2}
	OIDQcRetentionPeriod         = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 3}
	OIDQcSSCD                    = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}
	OIDQcPKIDisclosureStatements = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}
	OIDQcType                    = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}
	OIDQcCCLegislation           = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 7}

	// QC Certificate Type OIDs
	OIDQctEsign = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1}
	OIDQctEseal = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 2}
	OIDQctWeb   = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 3}
)

// CommitmentType represents a signature commitment type.
type CommitmentType int

const (
	CommitmentProofOfOrigin CommitmentType = iota
	CommitmentProofOfReceipt
	CommitmentProofOfDelivery
	CommitmentProofOfSender
	CommitmentProofOfApproval
	CommitmentProofOfCreation
)

// String returns the string representation of the commitment type.
func (c CommitmentType) String() string {
	switch c {
	case CommitmentProofOfOrigin:
		return "proof_of_origin"
	case CommitmentProofOfReceipt:
		return "proof_of_receipt"
	case CommitmentProofOfDelivery:
		return "proof_of_delivery"
	case CommitmentProofOfSender:
		return "proof_of_sender"
	case CommitmentProofOfApproval:
		return "proof_of_approval"
	case CommitmentProofOfCreation:
		return "proof_of_creation"
	default:
		return "unknown"
	}
}

// OID returns the ASN.1 OID for the commitment type.
func (c CommitmentType) OID() asn1.ObjectIdentifier {
	switch c {
	case CommitmentProofOfOrigin:
		return OIDProofOfOrigin
	case CommitmentProofOfReceipt:
		return OIDProofOfReceipt
	case CommitmentProofOfDelivery:
		return OIDProofOfDelivery
	case CommitmentProofOfSender:
		return OIDProofOfSender
	case CommitmentProofOfApproval:
		return OIDProofOfApproval
	case CommitmentProofOfCreation:
		return OIDProofOfCreation
	default:
		return nil
	}
}

// CommitmentTypeIndication represents a CAdES commitment type indication.
type CommitmentTypeIndication struct {
	CommitmentTypeID asn1.ObjectIdentifier
	Qualifiers       []CommitmentTypeQualifier `asn1:"optional"`
}

// CommitmentTypeQualifier represents a commitment type qualifier.
type CommitmentTypeQualifier struct {
	CommitmentTypeIdentifier asn1.ObjectIdentifier
	Qualifier                asn1.RawValue `asn1:"optional"`
}

// NewCommitmentTypeIndication creates a new commitment type indication.
func NewCommitmentTypeIndication(commitmentType CommitmentType) *CommitmentTypeIndication {
	return &CommitmentTypeIndication{
		CommitmentTypeID: commitmentType.OID(),
	}
}

// SignaturePolicyId represents a signature policy identifier.
type SignaturePolicyId struct {
	SigPolicyID         asn1.ObjectIdentifier
	SigPolicyHash       DigestInfo
	SigPolicyQualifiers []SigPolicyQualifierInfo `asn1:"optional"`
}

// DigestInfo represents an algorithm identifier and digest value.
type DigestInfo struct {
	DigestAlgorithm AlgorithmIdentifier
	Digest          []byte
}

// AlgorithmIdentifier represents an algorithm with optional parameters.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// SigPolicyQualifierInfo represents a signature policy qualifier.
type SigPolicyQualifierInfo struct {
	SigPolicyQualifierID asn1.ObjectIdentifier
	SigQualifier         asn1.RawValue
}

// SignaturePolicyIdentifier can be either an explicit policy ID or implied.
type SignaturePolicyIdentifier struct {
	SignaturePolicyId      *SignaturePolicyId
	SignaturePolicyImplied bool
}

// SPDocSpecification represents a signature policy document specification.
type SPDocSpecification struct {
	OID asn1.ObjectIdentifier
	URI string `asn1:"ia5"`
}

// SignaturePolicyDocument represents a signature policy document.
type SignaturePolicyDocument struct {
	SigPolicyEncoded  []byte
	SigPolicyLocalURI string `asn1:"ia5"`
}

// SignaturePolicyStore represents a stored signature policy.
type SignaturePolicyStore struct {
	SPDocSpec  SPDocSpecification
	SPDocument SignaturePolicyDocument
}

// DisplayText represents text that can be displayed (multiple encodings).
type DisplayText struct {
	VisibleString string `asn1:"optional,printable"`
	BMPString     string `asn1:"optional,bmp"`
	UTF8String    string `asn1:"optional,utf8"`
}

// NoticeReference references a notice by organization and numbers.
type NoticeReference struct {
	Organization  DisplayText
	NoticeNumbers []int
}

// SPUserNotice represents a signature policy user notice.
type SPUserNotice struct {
	NoticeRef    *NoticeReference `asn1:"optional"`
	ExplicitText *DisplayText     `asn1:"optional"`
}

// MonetaryValue represents a monetary value with currency.
type MonetaryValue struct {
	Currency Iso4217CurrencyCode
	Amount   int
	Exponent int
}

// Iso4217CurrencyCode represents a currency code.
type Iso4217CurrencyCode struct {
	Alphabetic string `asn1:"optional,printable"`
	Numeric    int    `asn1:"optional"`
}

// PKIDisclosureStatement represents a PKI disclosure statement.
type PKIDisclosureStatement struct {
	URL      string `asn1:"ia5"`
	Language string `asn1:"printable"`
}

// QcStatement represents a qualified certificate statement.
type QcStatement struct {
	StatementID   asn1.ObjectIdentifier
	StatementInfo asn1.RawValue `asn1:"optional"`
}

// QcStatements is a sequence of QC statements.
type QcStatements []QcStatement

// SignerAttributesV2 represents CAdES signer attributes.
type SignerAttributesV2 struct {
	ClaimedAttributes     []Attribute       `asn1:"optional,explicit,tag:0"`
	CertifiedAttributesV2 []asn1.RawValue   `asn1:"optional,explicit,tag:1"`
	SignedAssertions      []SignedAssertion `asn1:"optional,explicit,tag:2"`
}

// Attribute represents a generic attribute.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// SignedAssertion represents a signed assertion.
type SignedAssertion struct {
	SignedAssertionID asn1.ObjectIdentifier
	SignedAssertion   asn1.RawValue
}

// CAdESSignedAttrSpec specifies CAdES signed attributes for a signature.
type CAdESSignedAttrSpec struct {
	// CommitmentType is the signature commitment type.
	CommitmentType *CommitmentTypeIndication

	// TimestampContent indicates whether to include a signed timestamp.
	TimestampContent bool

	// SignaturePolicyIdentifier is the signature policy to embed.
	SignaturePolicyIdentifier *SignaturePolicyIdentifier

	// SignerAttributes contains signer attribute specifications.
	SignerAttributes *SignerAttrSpec
}

// SignerAttrSpec specifies signer attributes.
type SignerAttrSpec struct {
	// ClaimedAttrs are attributes claimed by the signer.
	ClaimedAttrs []Attribute

	// CertifiedAttrs are attribute certificates.
	CertifiedAttrs [][]byte // DER-encoded attribute certificates
}

// QcCertificateType represents qualified certificate type.
type QcCertificateType int

const (
	QcTypeEsign QcCertificateType = iota
	QcTypeEseal
	QcTypeWeb
)

// OID returns the ASN.1 OID for the QC certificate type.
func (q QcCertificateType) OID() asn1.ObjectIdentifier {
	switch q {
	case QcTypeEsign:
		return OIDQctEsign
	case QcTypeEseal:
		return OIDQctEseal
	case QcTypeWeb:
		return OIDQctWeb
	default:
		return nil
	}
}

// String returns the string representation.
func (q QcCertificateType) String() string {
	switch q {
	case QcTypeEsign:
		return "qct_esign"
	case QcTypeEseal:
		return "qct_eseal"
	case QcTypeWeb:
		return "qct_web"
	default:
		return "unknown"
	}
}

// ComputePolicyHash computes the hash of a signature policy document.
func ComputePolicyHash(policyDoc []byte) []byte {
	hash := sha256.Sum256(policyDoc)
	return hash[:]
}

// NewSignaturePolicyId creates a new signature policy ID with SHA-256 hash.
func NewSignaturePolicyId(policyOID asn1.ObjectIdentifier, policyDoc []byte) *SignaturePolicyId {
	return &SignaturePolicyId{
		SigPolicyID: policyOID,
		SigPolicyHash: DigestInfo{
			DigestAlgorithm: AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, // SHA-256
			},
			Digest: ComputePolicyHash(policyDoc),
		},
	}
}

// Marshal encodes the CommitmentTypeIndication to ASN.1 DER.
func (c *CommitmentTypeIndication) Marshal() ([]byte, error) {
	return asn1.Marshal(*c)
}

// Marshal encodes the SignaturePolicyId to ASN.1 DER.
func (s *SignaturePolicyId) Marshal() ([]byte, error) {
	return asn1.Marshal(*s)
}

// Marshal encodes the SignerAttributesV2 to ASN.1 DER.
func (s *SignerAttributesV2) Marshal() ([]byte, error) {
	return asn1.Marshal(*s)
}
