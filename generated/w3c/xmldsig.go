// Package w3c provides W3C XML Digital Signature structures.
//
// Implements structures defined in XML Signature Syntax and Processing (Second Edition)
// https://www.w3.org/TR/xmldsig-core/
package w3c

import (
	"encoding/xml"
)

// Namespace is the XML Digital Signature namespace.
const Namespace = "http://www.w3.org/2000/09/xmldsig#"

// CanonicalizationMethod specifies the canonicalization algorithm.
type CanonicalizationMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
	Content   []byte   `xml:",innerxml"`
}

// DSAKeyValue contains DSA public key values.
type DSAKeyValue struct {
	XMLName     xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DSAKeyValue"`
	P           []byte   `xml:"P,omitempty"`
	Q           []byte   `xml:"Q,omitempty"`
	G           []byte   `xml:"G,omitempty"`
	Y           []byte   `xml:"Y"`
	J           []byte   `xml:"J,omitempty"`
	Seed        []byte   `xml:"Seed,omitempty"`
	PgenCounter []byte   `xml:"PgenCounter,omitempty"`
}

// RSAKeyValue contains RSA public key values.
type RSAKeyValue struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# RSAKeyValue"`
	Modulus  []byte   `xml:"Modulus"`
	Exponent []byte   `xml:"Exponent"`
}

// DigestMethod specifies the digest algorithm.
type DigestMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
	Content   []byte   `xml:",innerxml"`
}

// DigestValue contains the digest value.
type DigestValue struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
	Value   []byte   `xml:",chardata"`
}

// KeyName contains a key name.
type KeyName struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyName"`
	Value   string   `xml:",chardata"`
}

// MgmtData contains management data.
type MgmtData struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# MgmtData"`
	Value   string   `xml:",chardata"`
}

// Object contains an embedded object.
type Object struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Object"`
	ID       string   `xml:"Id,attr,omitempty"`
	MimeType string   `xml:"MimeType,attr,omitempty"`
	Encoding string   `xml:"Encoding,attr,omitempty"`
	Content  []byte   `xml:",innerxml"`
}

// PGPData contains PGP key data.
type PGPData struct {
	XMLName      xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# PGPData"`
	PGPKeyID     []byte   `xml:"PGPKeyID,omitempty"`
	PGPKeyPacket [][]byte `xml:"PGPKeyPacket,omitempty"`
}

// SPKIData contains SPKI data.
type SPKIData struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SPKIData"`
	SPKISexp [][]byte `xml:"SPKISexp"`
}

// SignatureMethod specifies the signature algorithm.
type SignatureMethod struct {
	XMLName          xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Algorithm        string   `xml:"Algorithm,attr"`
	HMACOutputLength *int     `xml:"HMACOutputLength,omitempty"`
	Content          []byte   `xml:",innerxml"`
}

// SignatureProperty contains a signature property.
type SignatureProperty struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureProperty"`
	Target  string   `xml:"Target,attr"`
	ID      string   `xml:"Id,attr,omitempty"`
	Content []byte   `xml:",innerxml"`
}

// SignatureValue contains the signature value.
type SignatureValue struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	Value   []byte   `xml:",chardata"`
	ID      string   `xml:"Id,attr,omitempty"`
}

// Transform specifies a transformation.
type Transform struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
	Algorithm string   `xml:"Algorithm,attr"`
	XPath     []string `xml:"XPath,omitempty"`
	Content   []byte   `xml:",innerxml"`
}

// Transforms contains a list of transforms.
type Transforms struct {
	XMLName    xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	Transforms []Transform `xml:"Transform"`
}

// X509IssuerSerial contains X509 issuer and serial number.
type X509IssuerSerial struct {
	X509IssuerName   string `xml:"X509IssuerName"`
	X509SerialNumber int64  `xml:"X509SerialNumber"`
}

// X509Data contains X509 certificate data.
type X509Data struct {
	XMLName          xml.Name           `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509IssuerSerial []X509IssuerSerial `xml:"X509IssuerSerial,omitempty"`
	X509SKI          [][]byte           `xml:"X509SKI,omitempty"`
	X509SubjectName  []string           `xml:"X509SubjectName,omitempty"`
	X509Certificate  [][]byte           `xml:"X509Certificate,omitempty"`
	X509CRL          [][]byte           `xml:"X509CRL,omitempty"`
}

// KeyValue contains a key value (DSA or RSA).
type KeyValue struct {
	XMLName     xml.Name     `xml:"http://www.w3.org/2000/09/xmldsig# KeyValue"`
	DSAKeyValue *DSAKeyValue `xml:"DSAKeyValue,omitempty"`
	RSAKeyValue *RSAKeyValue `xml:"RSAKeyValue,omitempty"`
	Content     []byte       `xml:",innerxml"`
}

// SignatureProperties contains signature properties.
type SignatureProperties struct {
	XMLName           xml.Name            `xml:"http://www.w3.org/2000/09/xmldsig# SignatureProperties"`
	SignatureProperty []SignatureProperty `xml:"SignatureProperty"`
	ID                string              `xml:"Id,attr,omitempty"`
}

// Reference contains a reference to a resource.
type Reference struct {
	XMLName      xml.Name      `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	Transforms   *Transforms   `xml:"Transforms,omitempty"`
	DigestMethod *DigestMethod `xml:"DigestMethod"`
	DigestValue  *DigestValue  `xml:"DigestValue"`
	ID           string        `xml:"Id,attr,omitempty"`
	URI          string        `xml:"URI,attr,omitempty"`
	Type         string        `xml:"Type,attr,omitempty"`
}

// RetrievalMethod describes how to retrieve a key.
type RetrievalMethod struct {
	XMLName    xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# RetrievalMethod"`
	Transforms *Transforms `xml:"Transforms,omitempty"`
	URI        string      `xml:"URI,attr,omitempty"`
	Type       string      `xml:"Type,attr,omitempty"`
}

// KeyInfo contains key information.
type KeyInfo struct {
	XMLName         xml.Name          `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	ID              string            `xml:"Id,attr,omitempty"`
	KeyName         []KeyName         `xml:"KeyName,omitempty"`
	KeyValue        []KeyValue        `xml:"KeyValue,omitempty"`
	RetrievalMethod []RetrievalMethod `xml:"RetrievalMethod,omitempty"`
	X509Data        []X509Data        `xml:"X509Data,omitempty"`
	PGPData         []PGPData         `xml:"PGPData,omitempty"`
	SPKIData        []SPKIData        `xml:"SPKIData,omitempty"`
	MgmtData        []MgmtData        `xml:"MgmtData,omitempty"`
	Content         []byte            `xml:",innerxml"`
}

// Manifest contains a list of references.
type Manifest struct {
	XMLName   xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Manifest"`
	Reference []Reference `xml:"Reference"`
	ID        string      `xml:"Id,attr,omitempty"`
}

// SignedInfo contains the signed information.
type SignedInfo struct {
	XMLName                xml.Name                `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	CanonicalizationMethod *CanonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        *SignatureMethod        `xml:"SignatureMethod"`
	Reference              []Reference             `xml:"Reference"`
	ID                     string                  `xml:"Id,attr,omitempty"`
}

// Signature is the root element for XML signatures.
type Signature struct {
	XMLName        xml.Name        `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     *SignedInfo     `xml:"SignedInfo"`
	SignatureValue *SignatureValue `xml:"SignatureValue"`
	KeyInfo        *KeyInfo        `xml:"KeyInfo,omitempty"`
	Object         []Object        `xml:"Object,omitempty"`
	ID             string          `xml:"Id,attr,omitempty"`
}

// Common algorithm URIs
const (
	// Canonicalization algorithms
	AlgC14N                = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	AlgC14NWithComments    = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	AlgExcC14N             = "http://www.w3.org/2001/10/xml-exc-c14n#"
	AlgExcC14NWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"

	// Digest algorithms
	AlgSHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
	AlgSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	AlgSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	AlgSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"

	// Signature algorithms
	AlgDSAWithSHA1     = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
	AlgRSAWithSHA1     = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	AlgRSAWithSHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgRSAWithSHA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	AlgRSAWithSHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	AlgECDSAWithSHA1   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
	AlgECDSAWithSHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	AlgECDSAWithSHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	AlgECDSAWithSHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	AlgHMACWithSHA1    = "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
	AlgHMACWithSHA256  = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"

	// Transform algorithms
	AlgEnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	AlgXPath              = "http://www.w3.org/TR/1999/REC-xpath-19991116"
	AlgXSLT               = "http://www.w3.org/TR/1999/REC-xslt-19991116"
	AlgBase64             = "http://www.w3.org/2000/09/xmldsig#base64"
)

// NewSignature creates a new empty Signature.
func NewSignature() *Signature {
	return &Signature{
		SignedInfo:     &SignedInfo{},
		SignatureValue: &SignatureValue{},
	}
}

// NewReference creates a new Reference with the given URI.
func NewReference(uri string) *Reference {
	return &Reference{
		URI:          uri,
		DigestMethod: &DigestMethod{},
		DigestValue:  &DigestValue{},
	}
}

// NewKeyInfo creates a new empty KeyInfo.
func NewKeyInfo() *KeyInfo {
	return &KeyInfo{}
}

// AddX509Certificate adds an X509 certificate to KeyInfo.
func (ki *KeyInfo) AddX509Certificate(certDER []byte) {
	if len(ki.X509Data) == 0 {
		ki.X509Data = append(ki.X509Data, X509Data{})
	}
	ki.X509Data[0].X509Certificate = append(ki.X509Data[0].X509Certificate, certDER)
}

// SetRSAKeyValue sets the RSA key value in KeyInfo.
func (ki *KeyInfo) SetRSAKeyValue(modulus, exponent []byte) {
	ki.KeyValue = append(ki.KeyValue, KeyValue{
		RSAKeyValue: &RSAKeyValue{
			Modulus:  modulus,
			Exponent: exponent,
		},
	})
}

// SetDSAKeyValue sets the DSA key value in KeyInfo.
func (ki *KeyInfo) SetDSAKeyValue(p, q, g, y []byte) {
	ki.KeyValue = append(ki.KeyValue, KeyValue{
		DSAKeyValue: &DSAKeyValue{
			P: p,
			Q: q,
			G: g,
			Y: y,
		},
	})
}
