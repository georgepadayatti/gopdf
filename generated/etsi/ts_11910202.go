// Package etsi provides ETSI XML structures.
// This file contains ETSI TS 119.102-2 validation report structures.
//
// ETSI TS 119.102-2 specifies the XML format for validation reports
// of AdES digital signatures.
package etsi

import (
	"encoding/xml"
	"time"

	"github.com/georgepadayatti/gopdf/generated/w3c"
)

// TS11910202 namespace
const TS11910202Namespace = "http://uri.etsi.org/19102/v1.2.1#"

// EndorsementType specifies the type of signer role endorsement.
type EndorsementType string

const (
	EndorsementCertified EndorsementType = "certified"
	EndorsementClaimed   EndorsementType = "claimed"
	EndorsementSigned    EndorsementType = "signed"
)

// ConstraintStatusType contains constraint status information.
type ConstraintStatusType struct {
	Status       string `xml:"Status"`
	OverriddenBy string `xml:"OverriddenBy,omitempty"`
}

// NsPrefixMappingType maps namespace prefixes.
type NsPrefixMappingType struct {
	NamespaceURI    string `xml:"NamespaceURI"`
	NamespacePrefix string `xml:"NamespacePrefix"`
}

// SAFilterType contains a filter.
type SAFilterType struct {
	Filter string `xml:"Filter"`
}

// SAOCSPIDType identifies an OCSP response.
type SAOCSPIDType struct {
	ProducedAt        *time.Time `xml:"ProducedAt"`
	ResponderIDByName string     `xml:"ResponderIDByName,omitempty"`
	ResponderIDByKey  []byte     `xml:"ResponderIDByKey,omitempty"`
}

// SignatureQualityType contains signature quality information.
type SignatureQualityType struct {
	SignatureQualityInformation []string `xml:"SignatureQualityInformation"`
}

// SignatureValidationProcessType describes the validation process.
type SignatureValidationProcessType struct {
	SignatureValidationProcessID         string `xml:"SignatureValidationProcessID,omitempty"`
	SignatureValidationServicePolicy     string `xml:"SignatureValidationServicePolicy,omitempty"`
	SignatureValidationPracticeStatement string `xml:"SignatureValidationPracticeStatement,omitempty"`
}

// TypedDataType contains typed data.
type TypedDataType struct {
	Type  string `xml:"Type"`
	Value []byte `xml:",innerxml"`
}

// VOReferenceType references a validation object.
type VOReferenceType struct {
	Content     []byte   `xml:",innerxml"`
	VOReference []string `xml:"VOReference,attr,omitempty"`
}

// AdditionalValidationReportDataType contains additional report data.
type AdditionalValidationReportDataType struct {
	ReportData []TypedDataType `xml:"ReportData"`
}

// AttributeBaseType is the base for signature attributes.
type AttributeBaseType struct {
	AttributeObject []VOReferenceType `xml:"AttributeObject,omitempty"`
	Signed          *bool             `xml:"Signed,attr,omitempty"`
}

// CertificateChainType contains a certificate chain.
type CertificateChainType struct {
	SigningCertificate      *VOReferenceType  `xml:"SigningCertificate"`
	IntermediateCertificate []VOReferenceType `xml:"IntermediateCertificate,omitempty"`
	TrustAnchor             *VOReferenceType  `xml:"TrustAnchor,omitempty"`
}

// CryptoInformationType contains cryptographic information.
type CryptoInformationType struct {
	ValidationObjectId  *VOReferenceType `xml:"ValidationObjectId"`
	Algorithm           string           `xml:"Algorithm"`
	AlgorithmParameters *TypedDataType   `xml:"AlgorithmParameters,omitempty"`
	SecureAlgorithm     bool             `xml:"SecureAlgorithm"`
	NotAfter            *time.Time       `xml:"NotAfter,omitempty"`
}

// POEType represents Proof of Existence.
type POEType struct {
	POETime     *time.Time       `xml:"POETime"`
	TypeOfProof string           `xml:"TypeOfProof"`
	POEObject   *VOReferenceType `xml:"POEObject,omitempty"`
}

// RevocationStatusInformationType contains revocation status.
type RevocationStatusInformationType struct {
	ValidationObjectId *VOReferenceType `xml:"ValidationObjectId"`
	RevocationTime     *time.Time       `xml:"RevocationTime"`
	RevocationReason   string           `xml:"RevocationReason,omitempty"`
	RevocationObject   *VOReferenceType `xml:"RevocationObject,omitempty"`
}

// SACRLIDType identifies a CRL.
type SACRLIDType struct {
	DigestMethod *w3c.DigestMethod `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	DigestValue  *w3c.DigestValue  `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
}

// SACertIDType identifies a certificate.
type SACertIDType struct {
	X509IssuerSerial []byte            `xml:"X509IssuerSerial,omitempty"`
	DigestMethod     *w3c.DigestMethod `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	DigestValue      *w3c.DigestValue  `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
}

// SAOneSignerRoleType contains a single signer role.
type SAOneSignerRoleType struct {
	Role            string          `xml:"Role"`
	EndorsementType EndorsementType `xml:"EndorsementType"`
}

// SignatureIdentifierType identifies a signature.
type SignatureIdentifierType struct {
	DigestAlgAndValue *DigestAlgAndValueType `xml:"DigestAlgAndValue,omitempty"`
	SignatureValue    *w3c.SignatureValue    `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue,omitempty"`
	HashOnly          bool                   `xml:"HashOnly"`
	DocHashOnly       bool                   `xml:"DocHashOnly"`
	DAIdentifier      string                 `xml:"DAIdentifier,omitempty"`
	ID                string                 `xml:"id,attr,omitempty"`
}

// SignatureValidationPolicyType specifies the validation policy.
type SignatureValidationPolicyType struct {
	SignaturePolicyIdentifier *SignaturePolicyIdentifierType `xml:"SignaturePolicyIdentifier"`
	PolicyName                string                         `xml:"PolicyName,omitempty"`
	FormalPolicyURI           string                         `xml:"FormalPolicyURI,omitempty"`
	ReadablePolicyURI         string                         `xml:"ReadablePolicyURI,omitempty"`
	FormalPolicyObject        *VOReferenceType               `xml:"FormalPolicyObject,omitempty"`
}

// SignatureValidatorType identifies the validator.
type SignatureValidatorType struct {
	DigitalId      []DigitalIdentityType `xml:"DigitalId"`
	TSPInformation *TSPInformationType   `xml:"TSPInformation,omitempty"`
}

// SignerInformationType contains signer information.
type SignerInformationType struct {
	SignerCertificate *VOReferenceType `xml:"SignerCertificate"`
	Signer            string           `xml:"Signer,omitempty"`
	Pseudonym         *bool            `xml:"Pseudonym,attr,omitempty"`
}

// SignersDocumentType references the signed document.
type SignersDocumentType struct {
	DigestAlgAndValue              *DigestAlgAndValueType `xml:"DigestAlgAndValue"`
	SignersDocumentRepresentation  []VOReferenceType      `xml:"SignersDocumentRepresentation"`
	SignersDocumentRef             *VOReferenceType       `xml:"SignersDocumentRef,omitempty"`
}

// ValidationObjectRepresentationType represents a validation object.
type ValidationObjectRepresentationType struct {
	Direct            []byte                 `xml:"direct,omitempty"`
	Base64            []byte                 `xml:"base64,omitempty"`
	DigestAlgAndValue *DigestAlgAndValueType `xml:"DigestAlgAndValue,omitempty"`
	URI               string                 `xml:"URI,omitempty"`
}

// XAdESSignaturePtrType points to an XAdES signature.
type XAdESSignaturePtrType struct {
	NsPrefixMapping []NsPrefixMappingType `xml:"NsPrefixMapping,omitempty"`
	WhichDocument   string                `xml:"WhichDocument,attr,omitempty"`
	XPath           string                `xml:"XPath,attr,omitempty"`
	SchemaRefs      []string              `xml:"SchemaRefs,attr,omitempty"`
}

// SACertIDListType contains certificate IDs.
type SACertIDListType struct {
	AttributeBaseType
	CertID []SACertIDType `xml:"CertID,omitempty"`
}

// SACommitmentTypeIndicationType indicates commitment type.
type SACommitmentTypeIndicationType struct {
	AttributeBaseType
	CommitmentTypeIdentifier string `xml:"CommitmentTypeIdentifier"`
}

// SAContactInfoType contains contact information.
type SAContactInfoType struct {
	AttributeBaseType
	ContactInfoElement string `xml:"ContactInfoElement"`
}

// SADSSType contains DSS information.
type SADSSType struct {
	AttributeBaseType
	Certs *VOReferenceType `xml:"Certs,omitempty"`
	CRLs  *VOReferenceType `xml:"CRLs,omitempty"`
	OCSPs *VOReferenceType `xml:"OCSPs,omitempty"`
}

// SADataObjectFormatType describes data object format.
type SADataObjectFormatType struct {
	AttributeBaseType
	ContentType string `xml:"ContentType,omitempty"`
	MimeType    string `xml:"MimeType,omitempty"`
}

// SAMessageDigestType contains the message digest.
type SAMessageDigestType struct {
	AttributeBaseType
	Digest []byte `xml:"Digest"`
}

// SANameType contains a name.
type SANameType struct {
	AttributeBaseType
	NameElement string `xml:"NameElement"`
}

// SAReasonType contains a reason.
type SAReasonType struct {
	AttributeBaseType
	ReasonElement string `xml:"ReasonElement"`
}

// SARevIDListType contains revocation IDs.
type SARevIDListType struct {
	AttributeBaseType
	CRLID  []SACRLIDType  `xml:"CRLID,omitempty"`
	OCSPID []SAOCSPIDType `xml:"OCSPID,omitempty"`
}

// SASigPolicyIdentifierType identifies a signature policy.
type SASigPolicyIdentifierType struct {
	AttributeBaseType
	SigPolicyId string `xml:"SigPolicyId"`
}

// SASignatureProductionPlaceType contains production place.
type SASignatureProductionPlaceType struct {
	AttributeBaseType
	AddressString []string `xml:"AddressString"`
}

// SASignerRoleType contains signer roles.
type SASignerRoleType struct {
	AttributeBaseType
	RoleDetails []SAOneSignerRoleType `xml:"RoleDetails"`
}

// SASigningTimeType contains signing time.
type SASigningTimeType struct {
	AttributeBaseType
	Time *time.Time `xml:"Time"`
}

// SASubFilterType contains a sub-filter.
type SASubFilterType struct {
	AttributeBaseType
	SubFilterElement string `xml:"SubFilterElement"`
}

// SATimestampType contains a timestamp.
type SATimestampType struct {
	AttributeBaseType
	TimeStampValue *time.Time `xml:"TimeStampValue"`
}

// ValidationReportDataType contains validation report data.
type ValidationReportDataType struct {
	TrustAnchor                   *VOReferenceType                 `xml:"TrustAnchor,omitempty"`
	CertificateChain              *CertificateChainType            `xml:"CertificateChain,omitempty"`
	RelatedValidationObject       []VOReferenceType                `xml:"RelatedValidationObject,omitempty"`
	RevocationStatusInformation   *RevocationStatusInformationType `xml:"RevocationStatusInformation,omitempty"`
	CryptoInformation             []CryptoInformationType          `xml:"CryptoInformation,omitempty"`
	AdditionalValidationReportData *AdditionalValidationReportDataType `xml:"AdditionalValidationReportData,omitempty"`
}

// ValidationStatusType contains the validation status.
type ValidationStatusType struct {
	MainIndication         string                    `xml:"MainIndication"`
	SubIndication          []string                  `xml:"SubIndication,omitempty"`
	AssociatedValidationReportData []ValidationReportDataType `xml:"AssociatedValidationReportData,omitempty"`
}

// ValidationTimeInfoType contains validation time info.
type ValidationTimeInfoType struct {
	ValidationTime *time.Time `xml:"ValidationTime"`
	BestSignatureTime *POEType `xml:"BestSignatureTime,omitempty"`
}

// POEProvisioningType describes POE provisioning.
type POEProvisioningType struct {
	POETime         *time.Time       `xml:"POETime"`
	SignatureReference *VOReferenceType `xml:"SignatureReference,omitempty"`
	ValidationObject   []VOReferenceType `xml:"ValidationObject,omitempty"`
}

// IndividualValidationConstraintReportType reports on individual constraints.
type IndividualValidationConstraintReportType struct {
	Name              string                `xml:"Name"`
	Status            *ConstraintStatusType `xml:"Status"`
	Message           string                `xml:"Message,omitempty"`
	AdditionalInfo    []TypedDataType       `xml:"AdditionalInfo,omitempty"`
}

// SignatureAttributesType contains signature attributes.
type SignatureAttributesType struct {
	SigningTime                  []SASigningTimeType             `xml:"SigningTime,omitempty"`
	SigningCertificate           []SACertIDListType              `xml:"SigningCertificate,omitempty"`
	DataObjectFormat             []SADataObjectFormatType        `xml:"DataObjectFormat,omitempty"`
	CommitmentTypeIndication     []SACommitmentTypeIndicationType `xml:"CommitmentTypeIndication,omitempty"`
	AllDataObjectsTimeStamp      []SATimestampType               `xml:"AllDataObjectsTimeStamp,omitempty"`
	IndividualDataObjectsTimeStamp []SATimestampType             `xml:"IndividualDataObjectsTimeStamp,omitempty"`
	SigPolicyIdentifier          []SASigPolicyIdentifierType     `xml:"SigPolicyIdentifier,omitempty"`
	SignatureProductionPlace     []SASignatureProductionPlaceType `xml:"SignatureProductionPlace,omitempty"`
	SignerRole                   []SASignerRoleType              `xml:"SignerRole,omitempty"`
	CounterSignature             []VOReferenceType               `xml:"CounterSignature,omitempty"`
	SignatureTimeStamp           []SATimestampType               `xml:"SignatureTimeStamp,omitempty"`
	CompleteCertificateRefs      []SACertIDListType              `xml:"CompleteCertificateRefs,omitempty"`
	CompleteRevocationRefs       []SARevIDListType               `xml:"CompleteRevocationRefs,omitempty"`
	AttributeCertificateRefs     []SACertIDListType              `xml:"AttributeCertificateRefs,omitempty"`
	AttributeRevocationRefs      []SARevIDListType               `xml:"AttributeRevocationRefs,omitempty"`
	SigAndRefsTimeStamp          []SATimestampType               `xml:"SigAndRefsTimeStamp,omitempty"`
	RefsOnlyTimeStamp            []SATimestampType               `xml:"RefsOnlyTimeStamp,omitempty"`
	CertificateValues            []SADSSType                     `xml:"CertificateValues,omitempty"`
	RevocationValues             []SADSSType                     `xml:"RevocationValues,omitempty"`
	AttrAuthoritiesCertValues    []SADSSType                     `xml:"AttrAuthoritiesCertValues,omitempty"`
	AttributeRevocationValues    []SADSSType                     `xml:"AttributeRevocationValues,omitempty"`
	TimeStampValidationData      []SADSSType                     `xml:"TimeStampValidationData,omitempty"`
	ArchiveTimeStamp             []SATimestampType               `xml:"ArchiveTimeStamp,omitempty"`
	MessageDigest                []SAMessageDigestType           `xml:"MessageDigest,omitempty"`
	DSS                          []SADSSType                     `xml:"DSS,omitempty"`
	VRI                          []SADSSType                     `xml:"VRI,omitempty"`
	Reason                       []SAReasonType                  `xml:"Reason,omitempty"`
	Name                         []SANameType                    `xml:"Name,omitempty"`
	ContactInfo                  []SAContactInfoType             `xml:"ContactInfo,omitempty"`
	SubFilter                    []SASubFilterType               `xml:"SubFilter,omitempty"`
	ByteRange                    [][]int                         `xml:"ByteRange,omitempty"`
	Filter                       []SAFilterType                  `xml:"Filter,omitempty"`
}

// ValidationConstraintsEvaluationReportType reports on constraint evaluation.
type ValidationConstraintsEvaluationReportType struct {
	SignatureValidationPolicy *SignatureValidationPolicyType              `xml:"SignatureValidationPolicy,omitempty"`
	ValidationConstraint      []IndividualValidationConstraintReportType  `xml:"ValidationConstraint,omitempty"`
}

// SignatureValidationReportType contains a signature validation report.
type SignatureValidationReportType struct {
	SignatureIdentifier                  *SignatureIdentifierType                   `xml:"SignatureIdentifier,omitempty"`
	ValidationConstraintsEvaluationReport *ValidationConstraintsEvaluationReportType `xml:"ValidationConstraintsEvaluationReport,omitempty"`
	ValidationTimeInfo                   *ValidationTimeInfoType                    `xml:"ValidationTimeInfo,omitempty"`
	SignersDocument                      *SignersDocumentType                       `xml:"SignersDocument,omitempty"`
	SignatureAttributes                  *SignatureAttributesType                   `xml:"SignatureAttributes,omitempty"`
	SignerInformation                    *SignerInformationType                     `xml:"SignerInformation,omitempty"`
	SignatureQuality                     *SignatureQualityType                      `xml:"SignatureQuality,omitempty"`
	SignatureValidationProcess           *SignatureValidationProcessType            `xml:"SignatureValidationProcess,omitempty"`
	SignatureValidationStatus            *ValidationStatusType                      `xml:"SignatureValidationStatus"`
}

// ValidationObjectType represents a validation object.
type ValidationObjectType struct {
	ObjectType                     string                              `xml:"ObjectType"`
	ValidationObjectRepresentation *ValidationObjectRepresentationType `xml:"ValidationObjectRepresentation"`
	POE                            *POEType                            `xml:"POE,omitempty"`
	POEProvisioning                *POEProvisioningType                `xml:"POEProvisioning,omitempty"`
	ValidationReport               *SignatureValidationReportType      `xml:"ValidationReport,omitempty"`
	ID                             string                              `xml:"id,attr"`
}

// ValidationObjectListType contains validation objects.
type ValidationObjectListType struct {
	ValidationObject []ValidationObjectType `xml:"ValidationObject"`
}

// ValidationReportType is the main validation report structure.
type ValidationReportType struct {
	SignatureValidationReport  []SignatureValidationReportType `xml:"SignatureValidationReport"`
	SignatureValidationObjects *ValidationObjectListType       `xml:"SignatureValidationObjects,omitempty"`
	SignatureValidator         *SignatureValidatorType         `xml:"SignatureValidator,omitempty"`
	Signature                  *w3c.Signature                  `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
}

// ValidationReport is the root element for validation reports.
type ValidationReport struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/19102/v1.2.1# ValidationReport"`
	ValidationReportType
}

// NewValidationReport creates a new ValidationReport.
func NewValidationReport() *ValidationReport {
	return &ValidationReport{}
}

// AddSignatureReport adds a signature validation report.
func (vr *ValidationReport) AddSignatureReport(report *SignatureValidationReportType) {
	vr.SignatureValidationReport = append(vr.SignatureValidationReport, *report)
}

// GetPassedReports returns reports with TOTAL_PASSED status.
func (vr *ValidationReport) GetPassedReports() []*SignatureValidationReportType {
	var passed []*SignatureValidationReportType
	for i := range vr.SignatureValidationReport {
		r := &vr.SignatureValidationReport[i]
		if r.SignatureValidationStatus != nil &&
			r.SignatureValidationStatus.MainIndication == "urn:etsi:019102:mainindication:total-passed" {
			passed = append(passed, r)
		}
	}
	return passed
}

// GetFailedReports returns reports with TOTAL_FAILED status.
func (vr *ValidationReport) GetFailedReports() []*SignatureValidationReportType {
	var failed []*SignatureValidationReportType
	for i := range vr.SignatureValidationReport {
		r := &vr.SignatureValidationReport[i]
		if r.SignatureValidationStatus != nil &&
			r.SignatureValidationStatus.MainIndication == "urn:etsi:019102:mainindication:total-failed" {
			failed = append(failed, r)
		}
	}
	return failed
}

// Main indication URIs
const (
	MainIndicationPassed        = "urn:etsi:019102:mainindication:total-passed"
	MainIndicationFailed        = "urn:etsi:019102:mainindication:total-failed"
	MainIndicationIndeterminate = "urn:etsi:019102:mainindication:indeterminate"
)
