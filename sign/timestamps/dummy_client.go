// Package timestamps provides a dummy timestamper for testing.
package timestamps

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// DummyTimeStamper acts as its own TSA for testing purposes.
// It accepts all requests and signs them using the provided certificate.
type DummyTimeStamper struct {
	// TSACert is the TSA signing certificate.
	TSACert *x509.Certificate

	// TSAKey is the TSA private key.
	TSAKey crypto.Signer

	// CertsToEmbed are additional certificates to include in the response.
	CertsToEmbed []*x509.Certificate

	// FixedTime is a fixed time to use instead of current time.
	// If nil, current time is used.
	FixedTime *time.Time

	// IncludeNonce controls whether to echo the nonce from requests.
	IncludeNonce bool

	// OverrideMD overrides the message digest algorithm.
	OverrideMD string

	// Policy is the TSA policy OID.
	Policy asn1.ObjectIdentifier
}

// NewDummyTimeStamper creates a new dummy timestamper.
func NewDummyTimeStamper(cert *x509.Certificate, key crypto.Signer) *DummyTimeStamper {
	return &DummyTimeStamper{
		TSACert:      cert,
		TSAKey:       key,
		IncludeNonce: true,
		// Default TSA policy OID
		Policy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 2, 2},
	}
}

// WithCertsToEmbed adds certificates to embed in responses.
func (d *DummyTimeStamper) WithCertsToEmbed(certs []*x509.Certificate) *DummyTimeStamper {
	d.CertsToEmbed = certs
	return d
}

// WithFixedTime sets a fixed timestamp time.
func (d *DummyTimeStamper) WithFixedTime(t time.Time) *DummyTimeStamper {
	d.FixedTime = &t
	return d
}

// WithoutNonce disables nonce echoing.
func (d *DummyTimeStamper) WithoutNonce() *DummyTimeStamper {
	d.IncludeNonce = false
	return d
}

// WithPolicy sets the TSA policy OID.
func (d *DummyTimeStamper) WithPolicy(policy asn1.ObjectIdentifier) *DummyTimeStamper {
	d.Policy = policy
	return d
}

// Timestamp implements Timestamper.
func (d *DummyTimeStamper) Timestamp(data []byte) ([]byte, error) {
	return d.TimestampWithOptions(data, DefaultTimestampRequestOptions())
}

// TimestampWithOptions implements Timestamper.
func (d *DummyTimeStamper) TimestampWithOptions(data []byte, opts *TimestampRequestOptions) ([]byte, error) {
	// Create timestamp request
	reqBytes, err := CreateTimestampRequest(data, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Parse the request
	var req TimeStampReq
	if _, err := asn1.Unmarshal(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("failed to parse request: %w", err)
	}

	// Generate timestamp response
	respBytes, err := d.handleRequest(&req)
	if err != nil {
		return nil, err
	}

	// Parse response to extract the token
	var resp TimeStampResp
	if _, err := asn1.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.TimeStampToken.FullBytes, nil
}

// handleRequest processes a timestamp request and generates a response.
func (d *DummyTimeStamper) handleRequest(req *TimeStampReq) ([]byte, error) {
	// Determine timestamp time
	genTime := time.Now()
	if d.FixedTime != nil {
		genTime = *d.FixedTime
	}

	// Create TSTInfo
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	tstInfo := TSTInfo{
		Version:        1,
		Policy:         d.Policy,
		MessageImprint: req.MessageImprint,
		SerialNumber:   serialNumber,
		GenTime:        genTime,
	}

	if d.IncludeNonce && req.Nonce != nil {
		tstInfo.Nonce = req.Nonce
	}

	// Encode TSTInfo
	tstInfoBytes, err := asn1.Marshal(tstInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encode TSTInfo: %w", err)
	}

	// Create signed CMS structure
	token, err := d.createSignedCMS(tstInfoBytes)
	if err != nil {
		return nil, err
	}

	// Create response
	resp := TimeStampResp{
		Status: PKIStatusInfo{
			Status: 0, // granted
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: token,
		},
	}

	return asn1.Marshal(resp)
}

// createSignedCMS creates a signed CMS structure for the TSTInfo.
func (d *DummyTimeStamper) createSignedCMS(tstInfoBytes []byte) ([]byte, error) {
	// Compute digest of TSTInfo
	h := sha256.New()
	h.Write(tstInfoBytes)
	messageDigest := h.Sum(nil)

	// Create signed attributes
	signedAttrs := []attribute{
		{
			Type: OIDContentType,
			Values: []asn1.RawValue{{
				FullBytes: mustMarshal(OIDTSTInfo),
			}},
		},
		{
			Type: OIDMessageDigest,
			Values: []asn1.RawValue{{
				Class: asn1.ClassUniversal,
				Tag:   asn1.TagOctetString,
				Bytes: messageDigest,
			}},
		},
	}

	// Encode signed attributes for signing
	signedAttrsBytes, err := asn1.Marshal(signedAttrs)
	if err != nil {
		return nil, err
	}

	// Sign the attributes
	signature, err := d.sign(signedAttrsBytes)
	if err != nil {
		return nil, err
	}

	// Create signer info
	si := signerInfo{
		Version: 1,
		SID: issuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: d.TSACert.RawIssuer},
			SerialNumber: d.TSACert.SerialNumber,
		},
		DigestAlgorithm: AlgorithmIdentifier{
			Algorithm:  OIDSHA256,
			Parameters: asn1.RawValue{Tag: 5},
		},
		SignedAttrs: signedAttrs,
		SignatureAlgorithm: AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // SHA256WithRSA
			Parameters: asn1.RawValue{Tag: 5},
		},
		Signature: signature,
	}

	// Collect certificates
	var certBytes []asn1.RawValue
	certBytes = append(certBytes, asn1.RawValue{FullBytes: d.TSACert.Raw})
	for _, cert := range d.CertsToEmbed {
		certBytes = append(certBytes, asn1.RawValue{FullBytes: cert.Raw})
	}

	// Create signed data
	signedData := signedData{
		Version: 3,
		DigestAlgorithms: []AlgorithmIdentifier{{
			Algorithm:  OIDSHA256,
			Parameters: asn1.RawValue{Tag: 5},
		}},
		EncapContentInfo: encapsulatedContentInfo{
			ContentType: OIDTSTInfo,
			Content: asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        0,
				IsCompound: true,
				Bytes:      tstInfoBytes,
			},
		},
		Certificates: certBytes,
		SignerInfos:  []signerInfo{si},
	}

	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, err
	}

	// Create ContentInfo
	contentInfo := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0"`
	}{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, // signedData
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataBytes,
		},
	}

	return asn1.Marshal(contentInfo)
}

// sign signs data with the TSA private key.
func (d *DummyTimeStamper) sign(data []byte) ([]byte, error) {
	// Compute hash
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)

	// Sign based on key type
	switch key := d.TSAKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	default:
		return nil, errors.New("unsupported key type - dummy timestamper supports RSA only")
	}
}

// Helper types for CMS structure

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type signerInfo struct {
	Version            int
	SID                issuerAndSerialNumber
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        []attribute `asn1:"implicit,tag:0,set"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
}

type encapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"implicit,optional,tag:0"`
	SignerInfos      []signerInfo    `asn1:"set"`
}

// generateSerialNumber generates a random serial number.
func generateSerialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// mustMarshal marshals data and panics on error.
func mustMarshal(v interface{}) []byte {
	data, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// DummyTimestamperConfig holds configuration for creating a dummy timestamper.
type DummyTimestamperConfig struct {
	// Certificate is the TSA certificate.
	Certificate *x509.Certificate

	// PrivateKey is the TSA private key.
	PrivateKey crypto.Signer

	// AdditionalCerts are certificates to include in responses.
	AdditionalCerts []*x509.Certificate

	// FixedTime is a fixed time to use (nil for current time).
	FixedTime *time.Time

	// IncludeNonce controls nonce handling.
	IncludeNonce bool

	// Policy is the TSA policy OID.
	Policy asn1.ObjectIdentifier
}

// NewDummyTimestamperFromConfig creates a dummy timestamper from config.
func NewDummyTimestamperFromConfig(cfg *DummyTimestamperConfig) (*DummyTimeStamper, error) {
	if cfg.Certificate == nil {
		return nil, errors.New("certificate is required")
	}
	if cfg.PrivateKey == nil {
		return nil, errors.New("private key is required")
	}

	ts := NewDummyTimeStamper(cfg.Certificate, cfg.PrivateKey)
	ts.CertsToEmbed = cfg.AdditionalCerts
	ts.FixedTime = cfg.FixedTime
	ts.IncludeNonce = cfg.IncludeNonce
	if len(cfg.Policy) > 0 {
		ts.Policy = cfg.Policy
	}

	return ts, nil
}

// CreateTestTimestamper creates a dummy timestamper with a self-signed certificate.
// This is useful for testing purposes.
func CreateTestTimestamper() (*DummyTimeStamper, error) {
	// Generate a new RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create a self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TSA",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return NewDummyTimeStamper(cert, privateKey), nil
}
