// Package etsi provides ETSI XML structures.
// This file contains additional types for ETSI TS 119.612.
package etsi

import (
	"encoding/xml"
)

// TS119612Extra namespace
const TS119612ExtraNamespace = "http://uri.etsi.org/02231/v2/additionaltypes#"

// MimeType contains a MIME type string.
type MimeType struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2/additionaltypes# MimeType"`
	Value   string   `xml:",chardata"`
}

// PublicKeyLocation contains a public key location URI.
type PublicKeyLocation struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2/additionaltypes# PublicKeyLocation"`
	Value   string   `xml:",chardata"`
}

// X509CertificateLocation contains a certificate location URI.
type X509CertificateLocation struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2/additionaltypes# X509CertificateLocation"`
	Value   string   `xml:",chardata"`
}

// CertSubjectDNAttributeType contains certificate subject DN attributes.
type CertSubjectDNAttributeType struct {
	AttributeOID []ObjectIdentifierType `xml:"AttributeOID"`
}

// CertSubjectDNAttribute is the element form.
type CertSubjectDNAttribute struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2/additionaltypes# CertSubjectDNAttribute"`
	CertSubjectDNAttributeType
}

// ExtendedKeyUsageType contains extended key usage OIDs.
type ExtendedKeyUsageType struct {
	KeyPurposeId []ObjectIdentifierType `xml:"KeyPurposeId"`
}

// ExtendedKeyUsage is the element form.
type ExtendedKeyUsage struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2/additionaltypes# ExtendedKeyUsage"`
	ExtendedKeyUsageType
}

// TakenOverByType indicates a service taken over by another.
type TakenOverByType struct {
	URI                string                  `xml:"URI"`
	TSPName            *InternationalNamesType `xml:"TSPName"`
	SchemeOperatorName *SchemeOperatorName     `xml:"http://uri.etsi.org/02231/v2# SchemeOperatorName"`
	SchemeTerritory    string                  `xml:"http://uri.etsi.org/02231/v2# SchemeTerritory"`
	OtherQualifier     []TSLAnyType            `xml:"OtherQualifier,omitempty"`
}

// TakenOverBy is the element form.
type TakenOverBy struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2/additionaltypes# TakenOverBy"`
	TakenOverByType
}
