// Package crypt provides PDF encryption and decryption.
// This file implements ISO 32004 ASN.1 type definitions for PDF MAC.
//
// ISO 32004 defines the Message Authentication Code (MAC) mechanism
// for encrypted PDF documents to ensure document integrity.
package crypt

import (
	"encoding/asn1"
	"fmt"
)

// ISO 32004 defines the following OIDs:
//
// 1.0.32004.1.0 - PDF MAC Integrity Info content type
//   Used as the content type for the MAC'd data in a PDF MAC token
//
// 1.0.32004.1.1 - PDF MAC Wrap KDF
//   Key derivation function for deriving the MAC key encryption key
//   from the PDF's file encryption key
//
// 1.0.32004.1.2 - PDF MAC Data
//   CMS attribute used when attaching PDF MAC tokens to signatures

// ISO32004ContentType is the content type for PDF MAC integrity info.
const ISO32004ContentType = "pdf_mac_integrity_info"

// ISO32004KDFType is the KDF algorithm identifier.
const ISO32004KDFType = "pdf_mac_wrap_kdf"

// ISO32004AttributeType is the CMS attribute type for PDF MAC data.
const ISO32004AttributeType = "pdf_mac_data"

// ISO32004Version is the current version of the ISO 32004 specification.
const ISO32004Version = 0

// OID string representations for debugging and logging
const (
	OIDStringPdfMacIntegrityInfo = "1.0.32004.1.0"
	OIDStringPdfMacWrapKDF       = "1.0.32004.1.1"
	OIDStringPdfMacData          = "1.0.32004.1.2"
)

// iso32004OIDMap maps OID strings to their names.
var iso32004OIDMap = map[string]string{
	OIDStringPdfMacIntegrityInfo: ISO32004ContentType,
	OIDStringPdfMacWrapKDF:       ISO32004KDFType,
	OIDStringPdfMacData:          ISO32004AttributeType,
}

// GetISO32004OIDName returns the name for an ISO 32004 OID.
func GetISO32004OIDName(oid asn1.ObjectIdentifier) (string, bool) {
	name, ok := iso32004OIDMap[oid.String()]
	return name, ok
}

// IsISO32004OID checks if an OID is defined by ISO 32004.
func IsISO32004OID(oid asn1.ObjectIdentifier) bool {
	// ISO 32004 OIDs are under 1.0.32004.1.*
	if len(oid) >= 4 && oid[0] == 1 && oid[1] == 0 && oid[2] == 32004 && oid[3] == 1 {
		return true
	}
	return false
}

// ParsePdfMacIntegrityInfo parses an ASN.1 encoded PdfMacIntegrityInfo.
func ParsePdfMacIntegrityInfo(data []byte) (*PdfMacIntegrityInfo, error) {
	var info PdfMacIntegrityInfo
	rest, err := asn1.Unmarshal(data, &info)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PdfMacIntegrityInfo: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after PdfMacIntegrityInfo")
	}
	return &info, nil
}

// MarshalPdfMacIntegrityInfo marshals a PdfMacIntegrityInfo to ASN.1 DER.
func MarshalPdfMacIntegrityInfo(info *PdfMacIntegrityInfo) ([]byte, error) {
	return asn1.Marshal(*info)
}

// NewPdfMacIntegrityInfo creates a new PdfMacIntegrityInfo.
func NewPdfMacIntegrityInfo(dataDigest, signatureDigest []byte) *PdfMacIntegrityInfo {
	return &PdfMacIntegrityInfo{
		Version:         ISO32004Version,
		DataDigest:      dataDigest,
		SignatureDigest: signatureDigest,
	}
}

// HasSignatureDigest returns true if the integrity info includes a signature digest.
func (info *PdfMacIntegrityInfo) HasSignatureDigest() bool {
	return len(info.SignatureDigest) > 0
}

// Validate performs basic validation of the PdfMacIntegrityInfo.
func (info *PdfMacIntegrityInfo) Validate() error {
	if info.Version != ISO32004Version {
		return fmt.Errorf("unsupported PdfMacIntegrityInfo version: %d", info.Version)
	}
	if len(info.DataDigest) == 0 {
		return fmt.Errorf("PdfMacIntegrityInfo: dataDigest is required")
	}
	return nil
}

// KdfAlgorithmId represents a key derivation function algorithm identifier.
// This is used with the PDF MAC wrap KDF (OID 1.0.32004.1.1).
type KdfAlgorithmId struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// NewPdfMacKdfAlgorithmId creates a new KDF algorithm identifier for PDF MAC.
func NewPdfMacKdfAlgorithmId() KdfAlgorithmId {
	return KdfAlgorithmId{
		Algorithm: OIDPdfMacWrapKDF,
	}
}

// IsPdfMacKdf checks if this is the PDF MAC KDF algorithm.
func (kdf *KdfAlgorithmId) IsPdfMacKdf() bool {
	return kdf.Algorithm.Equal(OIDPdfMacWrapKDF)
}

// SetOfContentInfo represents a SET OF ContentInfo.
// Used for the pdf_mac_data attribute value.
type SetOfContentInfo []ContentInfo

// PdfMacDataAttribute represents the pdf_mac_data CMS attribute.
type PdfMacDataAttribute struct {
	Type   asn1.ObjectIdentifier
	Values SetOfContentInfo `asn1:"set"`
}

// NewPdfMacDataAttribute creates a new pdf_mac_data attribute.
func NewPdfMacDataAttribute(contentInfos ...ContentInfo) *PdfMacDataAttribute {
	return &PdfMacDataAttribute{
		Type:   OIDPdfMacData,
		Values: contentInfos,
	}
}

// IsPdfMacDataAttribute checks if a CMS attribute is a pdf_mac_data attribute.
func IsPdfMacDataAttribute(attr *CMSAttribute) bool {
	return attr.Type.Equal(OIDPdfMacData)
}

// ParsePdfMacDataAttribute parses the value of a pdf_mac_data attribute.
func ParsePdfMacDataAttribute(attr *CMSAttribute) ([]ContentInfo, error) {
	if !IsPdfMacDataAttribute(attr) {
		return nil, fmt.Errorf("not a pdf_mac_data attribute")
	}

	var contentInfos []ContentInfo
	_, err := asn1.Unmarshal(attr.Value.FullBytes, &contentInfos)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pdf_mac_data value: %w", err)
	}

	return contentInfos, nil
}

// ISO32004Registry provides OID lookup for ISO 32004 types.
type ISO32004Registry struct {
	contentTypes map[string]string
	kdfTypes     map[string]string
	attrTypes    map[string]string
}

// NewISO32004Registry creates a new ISO 32004 registry with default registrations.
func NewISO32004Registry() *ISO32004Registry {
	return &ISO32004Registry{
		contentTypes: map[string]string{
			OIDStringPdfMacIntegrityInfo: ISO32004ContentType,
		},
		kdfTypes: map[string]string{
			OIDStringPdfMacWrapKDF: ISO32004KDFType,
		},
		attrTypes: map[string]string{
			OIDStringPdfMacData: ISO32004AttributeType,
		},
	}
}

// LookupContentType looks up a content type name by OID.
func (r *ISO32004Registry) LookupContentType(oid asn1.ObjectIdentifier) (string, bool) {
	name, ok := r.contentTypes[oid.String()]
	return name, ok
}

// LookupKdfType looks up a KDF type name by OID.
func (r *ISO32004Registry) LookupKdfType(oid asn1.ObjectIdentifier) (string, bool) {
	name, ok := r.kdfTypes[oid.String()]
	return name, ok
}

// LookupAttrType looks up an attribute type name by OID.
func (r *ISO32004Registry) LookupAttrType(oid asn1.ObjectIdentifier) (string, bool) {
	name, ok := r.attrTypes[oid.String()]
	return name, ok
}

// DefaultISO32004Registry is the default registry instance.
var DefaultISO32004Registry = NewISO32004Registry()
