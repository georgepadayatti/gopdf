// Package etsi provides ETSI XML structures for electronic signatures.
//
// Implements XAdES (XML Advanced Electronic Signatures) structures defined in
// ETSI TS 101 903 V1.3.2
package etsi

import (
	"encoding/xml"
	"time"

	"github.com/georgepadayatti/gopdf/generated/w3c"
)

// XAdES namespace
const XAdESNamespace = "http://uri.etsi.org/01903/v1.3.2#"

// QualifierType represents the OID qualifier type.
type QualifierType string

const (
	QualifierOIDAsURI QualifierType = "OIDAsURI"
	QualifierOIDAsURN QualifierType = "OIDAsURN"
)

// AnyType contains wildcard content.
type AnyType struct {
	Content []byte `xml:",innerxml"`
}

// CRLIdentifierType identifies a CRL.
type CRLIdentifierType struct {
	Issuer    string     `xml:"Issuer"`
	IssueTime *time.Time `xml:"IssueTime"`
	Number    *int64     `xml:"Number,omitempty"`
	URI       string     `xml:"URI,attr,omitempty"`
}

// DocumentationReferencesType contains documentation references.
type DocumentationReferencesType struct {
	DocumentationReference []string `xml:"DocumentationReference"`
}

// EncapsulatedPKIDataType contains encapsulated PKI data.
type EncapsulatedPKIDataType struct {
	XMLName  xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# EncapsulatedPKIData"`
	Value    []byte   `xml:",chardata"`
	ID       string   `xml:"Id,attr,omitempty"`
	Encoding string   `xml:"Encoding,attr,omitempty"`
}

// IncludeType specifies an include reference.
type IncludeType struct {
	XMLName        xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# Include"`
	URI            string   `xml:"URI,attr"`
	ReferencedData *bool    `xml:"referencedData,attr,omitempty"`
}

// IntegerListType contains a list of integers.
type IntegerListType struct {
	Int []int64 `xml:"int"`
}

// QualifyingPropertiesReferenceType references qualifying properties.
type QualifyingPropertiesReferenceType struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# QualifyingPropertiesReference"`
	URI     string   `xml:"URI,attr"`
	ID      string   `xml:"Id,attr,omitempty"`
}

// ResponderIDType identifies an OCSP responder.
type ResponderIDType struct {
	ByName string `xml:"ByName,omitempty"`
	ByKey  []byte `xml:"ByKey,omitempty"`
}

// SPURI contains a signature policy URI.
type SPURI struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# SPURI"`
	Value   string   `xml:",chardata"`
}

// SignatureProductionPlaceType identifies where a signature was produced.
type SignatureProductionPlaceType struct {
	City            string `xml:"City,omitempty"`
	StateOrProvince string `xml:"StateOrProvince,omitempty"`
	PostalCode      string `xml:"PostalCode,omitempty"`
	CountryName     string `xml:"CountryName,omitempty"`
}

// SignatureProductionPlace is the element form of SignatureProductionPlaceType.
type SignatureProductionPlace struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# SignatureProductionPlace"`
	SignatureProductionPlaceType
}

// SigningTime contains the signing time.
type SigningTime struct {
	XMLName xml.Name   `xml:"http://uri.etsi.org/01903/v1.3.2# SigningTime"`
	Value   *time.Time `xml:",chardata"`
}

// CRLValuesType contains encapsulated CRL values.
type CRLValuesType struct {
	EncapsulatedCRLValue []EncapsulatedPKIDataType `xml:"EncapsulatedCRLValue"`
}

// CertificateValuesType contains certificate values.
type CertificateValuesType struct {
	EncapsulatedX509Certificate []EncapsulatedPKIDataType `xml:"EncapsulatedX509Certificate,omitempty"`
	OtherCertificate            []AnyType                 `xml:"OtherCertificate,omitempty"`
	ID                          string                    `xml:"Id,attr,omitempty"`
}

// CertificateValues is the element form of CertificateValuesType.
type CertificateValues struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# CertificateValues"`
	CertificateValuesType
}

// CertifiedRolesListType contains certified roles.
type CertifiedRolesListType struct {
	CertifiedRole []EncapsulatedPKIDataType `xml:"CertifiedRole"`
}

// ClaimedRolesListType contains claimed roles.
type ClaimedRolesListType struct {
	ClaimedRole []AnyType `xml:"ClaimedRole"`
}

// CommitmentTypeQualifiersListType contains commitment type qualifiers.
type CommitmentTypeQualifiersListType struct {
	CommitmentTypeQualifier []AnyType `xml:"CommitmentTypeQualifier,omitempty"`
}

// CounterSignatureType contains a counter-signature.
type CounterSignatureType struct {
	Signature *w3c.Signature `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
}

// CounterSignature is the element form of CounterSignatureType.
type CounterSignature struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# CounterSignature"`
	CounterSignatureType
}

// DigestAlgAndValueType contains a digest algorithm and value.
type DigestAlgAndValueType struct {
	DigestMethod *w3c.DigestMethod `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	DigestValue  *w3c.DigestValue  `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
}

// IdentifierType contains an identifier with optional qualifier.
type IdentifierType struct {
	Value     string        `xml:",chardata"`
	Qualifier QualifierType `xml:"Qualifier,attr,omitempty"`
}

// NoticeReferenceType references a notice.
type NoticeReferenceType struct {
	Organization  string           `xml:"Organization"`
	NoticeNumbers *IntegerListType `xml:"NoticeNumbers"`
}

// OCSPIdentifierType identifies an OCSP response.
type OCSPIdentifierType struct {
	ResponderID *ResponderIDType `xml:"ResponderID"`
	ProducedAt  *time.Time       `xml:"ProducedAt"`
	URI         string           `xml:"URI,attr,omitempty"`
}

// OCSPValuesType contains encapsulated OCSP values.
type OCSPValuesType struct {
	EncapsulatedOCSPValue []EncapsulatedPKIDataType `xml:"EncapsulatedOCSPValue"`
}

// OtherCertStatusRefsType contains other certificate status references.
type OtherCertStatusRefsType struct {
	OtherRef []AnyType `xml:"OtherRef"`
}

// OtherCertStatusValuesType contains other certificate status values.
type OtherCertStatusValuesType struct {
	OtherValue []AnyType `xml:"OtherValue"`
}

// ReferenceInfoType contains reference information.
type ReferenceInfoType struct {
	XMLName      xml.Name          `xml:"http://uri.etsi.org/01903/v1.3.2# ReferenceInfo"`
	DigestMethod *w3c.DigestMethod `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	DigestValue  *w3c.DigestValue  `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
	ID           string            `xml:"Id,attr,omitempty"`
	URI          string            `xml:"URI,attr,omitempty"`
}

// SigPolicyQualifiersListType contains signature policy qualifiers.
type SigPolicyQualifiersListType struct {
	SigPolicyQualifier []AnyType `xml:"SigPolicyQualifier"`
}

// UnsignedDataObjectPropertiesType contains unsigned data object properties.
type UnsignedDataObjectPropertiesType struct {
	UnsignedDataObjectProperty []AnyType `xml:"UnsignedDataObjectProperty"`
	ID                         string    `xml:"Id,attr,omitempty"`
}

// UnsignedDataObjectProperties is the element form.
type UnsignedDataObjectProperties struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# UnsignedDataObjectProperties"`
	UnsignedDataObjectPropertiesType
}

// AttrAuthoritiesCertValues is the element form of CertificateValuesType.
type AttrAuthoritiesCertValues struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# AttrAuthoritiesCertValues"`
	CertificateValuesType
}

// CRLRefType references a CRL.
type CRLRefType struct {
	DigestAlgAndValue *DigestAlgAndValueType `xml:"DigestAlgAndValue"`
	CRLIdentifier     *CRLIdentifierType     `xml:"CRLIdentifier,omitempty"`
}

// CertIDType identifies a certificate.
type CertIDType struct {
	CertDigest   *DigestAlgAndValueType `xml:"CertDigest"`
	IssuerSerial *w3c.X509IssuerSerial  `xml:"IssuerSerial"`
	URI          string                 `xml:"URI,attr,omitempty"`
}

// OCSPRefType references an OCSP response.
type OCSPRefType struct {
	OCSPIdentifier    *OCSPIdentifierType    `xml:"OCSPIdentifier"`
	DigestAlgAndValue *DigestAlgAndValueType `xml:"DigestAlgAndValue,omitempty"`
}

// ObjectIdentifierType contains an object identifier.
type ObjectIdentifierType struct {
	Identifier              *IdentifierType              `xml:"Identifier"`
	Description             string                       `xml:"Description,omitempty"`
	DocumentationReferences *DocumentationReferencesType `xml:"DocumentationReferences,omitempty"`
}

// ObjectIdentifier is the element form of ObjectIdentifierType.
type ObjectIdentifier struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# ObjectIdentifier"`
	ObjectIdentifierType
}

// RevocationValuesType contains revocation values.
type RevocationValuesType struct {
	CRLValues   *CRLValuesType             `xml:"CRLValues,omitempty"`
	OCSPValues  *OCSPValuesType            `xml:"OCSPValues,omitempty"`
	OtherValues *OtherCertStatusValuesType `xml:"OtherValues,omitempty"`
	ID          string                     `xml:"Id,attr,omitempty"`
}

// RevocationValues is the element form of RevocationValuesType.
type RevocationValues struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# RevocationValues"`
	RevocationValuesType
}

// AttributeRevocationValues is an alias for RevocationValues.
type AttributeRevocationValues struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# AttributeRevocationValues"`
	RevocationValuesType
}

// SPUserNoticeType contains a signature policy user notice.
type SPUserNoticeType struct {
	NoticeRef    *NoticeReferenceType `xml:"NoticeRef,omitempty"`
	ExplicitText string               `xml:"ExplicitText,omitempty"`
}

// SPUserNotice is the element form of SPUserNoticeType.
type SPUserNotice struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# SPUserNotice"`
	SPUserNoticeType
}

// SignerRoleType contains signer role information.
type SignerRoleType struct {
	ClaimedRoles   *ClaimedRolesListType   `xml:"ClaimedRoles,omitempty"`
	CertifiedRoles *CertifiedRolesListType `xml:"CertifiedRoles,omitempty"`
}

// SignerRole is the element form of SignerRoleType.
type SignerRole struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# SignerRole"`
	SignerRoleType
}

// CRLRefsType contains CRL references.
type CRLRefsType struct {
	CRLRef []CRLRefType `xml:"CRLRef"`
}

// CertIDListType contains a list of certificate IDs.
type CertIDListType struct {
	Cert []CertIDType `xml:"Cert"`
}

// SigningCertificate is the element form of CertIDListType.
type SigningCertificate struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# SigningCertificate"`
	CertIDListType
}

// OCSPRefsType contains OCSP references.
type OCSPRefsType struct {
	OCSPRef []OCSPRefType `xml:"OCSPRef"`
}

// SignaturePolicyIdType identifies a signature policy.
type SignaturePolicyIdType struct {
	SigPolicyId         *ObjectIdentifierType        `xml:"SigPolicyId"`
	Transforms          *w3c.Transforms              `xml:"http://www.w3.org/2000/09/xmldsig# Transforms,omitempty"`
	SigPolicyHash       *DigestAlgAndValueType       `xml:"SigPolicyHash"`
	SigPolicyQualifiers *SigPolicyQualifiersListType `xml:"SigPolicyQualifiers,omitempty"`
}

// CommitmentTypeIndicationType indicates commitment type.
type CommitmentTypeIndicationType struct {
	CommitmentTypeId         *ObjectIdentifierType             `xml:"CommitmentTypeId"`
	ObjectReference          []string                          `xml:"ObjectReference,omitempty"`
	AllSignedDataObjects     *struct{}                         `xml:"AllSignedDataObjects,omitempty"`
	CommitmentTypeQualifiers *CommitmentTypeQualifiersListType `xml:"CommitmentTypeQualifiers,omitempty"`
}

// CommitmentTypeIndication is the element form.
type CommitmentTypeIndication struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# CommitmentTypeIndication"`
	CommitmentTypeIndicationType
}

// DataObjectFormatType describes data object format.
type DataObjectFormatType struct {
	Description      string                `xml:"Description,omitempty"`
	ObjectIdentifier *ObjectIdentifierType `xml:"ObjectIdentifier,omitempty"`
	MimeType         string                `xml:"MimeType,omitempty"`
	Encoding         string                `xml:"Encoding,omitempty"`
	ObjectReference  string                `xml:"ObjectReference,attr"`
}

// DataObjectFormat is the element form of DataObjectFormatType.
type DataObjectFormat struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# DataObjectFormat"`
	DataObjectFormatType
}

// GenericTimeStampType is a generic timestamp structure.
type GenericTimeStampType struct {
	Include                []IncludeType               `xml:"Include,omitempty"`
	ReferenceInfo          []ReferenceInfoType         `xml:"ReferenceInfo,omitempty"`
	CanonicalizationMethod *w3c.CanonicalizationMethod `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod,omitempty"`
	EncapsulatedTimeStamp  []EncapsulatedPKIDataType   `xml:"EncapsulatedTimeStamp,omitempty"`
	XMLTimeStamp           []AnyType                   `xml:"XMLTimeStamp,omitempty"`
	ID                     string                      `xml:"Id,attr,omitempty"`
}

// XAdESTimeStampType is an XAdES timestamp (no ReferenceInfo).
type XAdESTimeStampType struct {
	Include                []IncludeType               `xml:"Include,omitempty"`
	CanonicalizationMethod *w3c.CanonicalizationMethod `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod,omitempty"`
	EncapsulatedTimeStamp  []EncapsulatedPKIDataType   `xml:"EncapsulatedTimeStamp,omitempty"`
	XMLTimeStamp           []AnyType                   `xml:"XMLTimeStamp,omitempty"`
	ID                     string                      `xml:"Id,attr,omitempty"`
}

// XAdESTimeStamp is the element form of XAdESTimeStampType.
type XAdESTimeStamp struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# XAdESTimeStamp"`
	XAdESTimeStampType
}

// AllDataObjectsTimeStamp is a timestamp covering all data objects.
type AllDataObjectsTimeStamp struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# AllDataObjectsTimeStamp"`
	XAdESTimeStampType
}

// IndividualDataObjectsTimeStamp timestamps individual data objects.
type IndividualDataObjectsTimeStamp struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# IndividualDataObjectsTimeStamp"`
	XAdESTimeStampType
}

// SignatureTimeStamp is a timestamp over the signature value.
type SignatureTimeStamp struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# SignatureTimeStamp"`
	XAdESTimeStampType
}

// SigAndRefsTimeStamp timestamps signature and references.
type SigAndRefsTimeStamp struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# SigAndRefsTimeStamp"`
	XAdESTimeStampType
}

// RefsOnlyTimeStamp timestamps only references.
type RefsOnlyTimeStamp struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# RefsOnlyTimeStamp"`
	XAdESTimeStampType
}

// ArchiveTimeStamp is an archival timestamp.
type ArchiveTimeStamp struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# ArchiveTimeStamp"`
	XAdESTimeStampType
}

// OtherTimeStampType requires ReferenceInfo.
type OtherTimeStampType struct {
	ReferenceInfo          []ReferenceInfoType         `xml:"ReferenceInfo"`
	CanonicalizationMethod *w3c.CanonicalizationMethod `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod,omitempty"`
	EncapsulatedTimeStamp  []EncapsulatedPKIDataType   `xml:"EncapsulatedTimeStamp,omitempty"`
	XMLTimeStamp           []AnyType                   `xml:"XMLTimeStamp,omitempty"`
	ID                     string                      `xml:"Id,attr,omitempty"`
}

// OtherTimeStamp is the element form of OtherTimeStampType.
type OtherTimeStamp struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# OtherTimeStamp"`
	OtherTimeStampType
}

// SignaturePolicyIdentifierType identifies or implies a signature policy.
type SignaturePolicyIdentifierType struct {
	SignaturePolicyId      *SignaturePolicyIdType `xml:"SignaturePolicyId,omitempty"`
	SignaturePolicyImplied *struct{}              `xml:"SignaturePolicyImplied,omitempty"`
}

// SignaturePolicyIdentifier is the element form.
type SignaturePolicyIdentifier struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# SignaturePolicyIdentifier"`
	SignaturePolicyIdentifierType
}

// CompleteCertificateRefsType contains complete certificate references.
type CompleteCertificateRefsType struct {
	CertRefs *CertIDListType `xml:"CertRefs"`
	ID       string          `xml:"Id,attr,omitempty"`
}

// CompleteCertificateRefs is the element form.
type CompleteCertificateRefs struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# CompleteCertificateRefs"`
	CompleteCertificateRefsType
}

// AttributeCertificateRefs is an alias for certificate refs.
type AttributeCertificateRefs struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# AttributeCertificateRefs"`
	CompleteCertificateRefsType
}

// CompleteRevocationRefsType contains complete revocation references.
type CompleteRevocationRefsType struct {
	CRLRefs   *CRLRefsType             `xml:"CRLRefs,omitempty"`
	OCSPRefs  *OCSPRefsType            `xml:"OCSPRefs,omitempty"`
	OtherRefs *OtherCertStatusRefsType `xml:"OtherRefs,omitempty"`
	ID        string                   `xml:"Id,attr,omitempty"`
}

// CompleteRevocationRefs is the element form.
type CompleteRevocationRefs struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# CompleteRevocationRefs"`
	CompleteRevocationRefsType
}

// AttributeRevocationRefs is an alias for revocation refs.
type AttributeRevocationRefs struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# AttributeRevocationRefs"`
	CompleteRevocationRefsType
}

// SignedDataObjectPropertiesType contains signed data object properties.
type SignedDataObjectPropertiesType struct {
	DataObjectFormat               []DataObjectFormatType         `xml:"DataObjectFormat,omitempty"`
	CommitmentTypeIndication       []CommitmentTypeIndicationType `xml:"CommitmentTypeIndication,omitempty"`
	AllDataObjectsTimeStamp        []XAdESTimeStampType           `xml:"AllDataObjectsTimeStamp,omitempty"`
	IndividualDataObjectsTimeStamp []XAdESTimeStampType           `xml:"IndividualDataObjectsTimeStamp,omitempty"`
	ID                             string                         `xml:"Id,attr,omitempty"`
}

// SignedDataObjectProperties is the element form.
type SignedDataObjectProperties struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# SignedDataObjectProperties"`
	SignedDataObjectPropertiesType
}

// SignedSignaturePropertiesType contains signed signature properties.
type SignedSignaturePropertiesType struct {
	SigningTime               *time.Time                     `xml:"SigningTime,omitempty"`
	SigningCertificate        *CertIDListType                `xml:"SigningCertificate,omitempty"`
	SignaturePolicyIdentifier *SignaturePolicyIdentifierType `xml:"SignaturePolicyIdentifier,omitempty"`
	SignatureProductionPlace  *SignatureProductionPlaceType  `xml:"SignatureProductionPlace,omitempty"`
	SignerRole                *SignerRoleType                `xml:"SignerRole,omitempty"`
	ID                        string                         `xml:"Id,attr,omitempty"`
}

// SignedSignatureProperties is the element form.
type SignedSignatureProperties struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# SignedSignatureProperties"`
	SignedSignaturePropertiesType
}

// UnsignedSignaturePropertiesType contains unsigned signature properties.
type UnsignedSignaturePropertiesType struct {
	CounterSignature          []CounterSignatureType        `xml:"CounterSignature,omitempty"`
	SignatureTimeStamp        []XAdESTimeStampType          `xml:"SignatureTimeStamp,omitempty"`
	CompleteCertificateRefs   []CompleteCertificateRefsType `xml:"CompleteCertificateRefs,omitempty"`
	CompleteRevocationRefs    []CompleteRevocationRefsType  `xml:"CompleteRevocationRefs,omitempty"`
	AttributeCertificateRefs  []CompleteCertificateRefsType `xml:"AttributeCertificateRefs,omitempty"`
	AttributeRevocationRefs   []CompleteRevocationRefsType  `xml:"AttributeRevocationRefs,omitempty"`
	SigAndRefsTimeStamp       []XAdESTimeStampType          `xml:"SigAndRefsTimeStamp,omitempty"`
	RefsOnlyTimeStamp         []XAdESTimeStampType          `xml:"RefsOnlyTimeStamp,omitempty"`
	CertificateValues         []CertificateValuesType       `xml:"CertificateValues,omitempty"`
	RevocationValues          []RevocationValuesType        `xml:"RevocationValues,omitempty"`
	AttrAuthoritiesCertValues []CertificateValuesType       `xml:"AttrAuthoritiesCertValues,omitempty"`
	AttributeRevocationValues []RevocationValuesType        `xml:"AttributeRevocationValues,omitempty"`
	ArchiveTimeStamp          []XAdESTimeStampType          `xml:"ArchiveTimeStamp,omitempty"`
	ID                        string                        `xml:"Id,attr,omitempty"`
}

// UnsignedSignatureProperties is the element form.
type UnsignedSignatureProperties struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# UnsignedSignatureProperties"`
	UnsignedSignaturePropertiesType
}

// SignedPropertiesType contains signed properties.
type SignedPropertiesType struct {
	SignedSignatureProperties  *SignedSignaturePropertiesType  `xml:"SignedSignatureProperties,omitempty"`
	SignedDataObjectProperties *SignedDataObjectPropertiesType `xml:"SignedDataObjectProperties,omitempty"`
	ID                         string                          `xml:"Id,attr,omitempty"`
}

// SignedProperties is the element form.
type SignedProperties struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# SignedProperties"`
	SignedPropertiesType
}

// UnsignedPropertiesType contains unsigned properties.
type UnsignedPropertiesType struct {
	UnsignedSignatureProperties  *UnsignedSignaturePropertiesType  `xml:"UnsignedSignatureProperties,omitempty"`
	UnsignedDataObjectProperties *UnsignedDataObjectPropertiesType `xml:"UnsignedDataObjectProperties,omitempty"`
	ID                           string                            `xml:"Id,attr,omitempty"`
}

// UnsignedProperties is the element form.
type UnsignedProperties struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# UnsignedProperties"`
	UnsignedPropertiesType
}

// QualifyingPropertiesType contains qualifying properties for XAdES.
type QualifyingPropertiesType struct {
	SignedProperties   *SignedPropertiesType   `xml:"SignedProperties,omitempty"`
	UnsignedProperties *UnsignedPropertiesType `xml:"UnsignedProperties,omitempty"`
	Target             string                  `xml:"Target,attr"`
	ID                 string                  `xml:"Id,attr,omitempty"`
}

// QualifyingProperties is the element form.
type QualifyingProperties struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/01903/v1.3.2# QualifyingProperties"`
	QualifyingPropertiesType
}

// NewQualifyingProperties creates a new QualifyingProperties.
func NewQualifyingProperties(target string) *QualifyingProperties {
	return &QualifyingProperties{
		QualifyingPropertiesType: QualifyingPropertiesType{
			Target: target,
		},
	}
}

// NewSignedProperties creates a new SignedProperties.
func NewSignedProperties() *SignedProperties {
	return &SignedProperties{}
}

// NewUnsignedProperties creates a new UnsignedProperties.
func NewUnsignedProperties() *UnsignedProperties {
	return &UnsignedProperties{}
}
