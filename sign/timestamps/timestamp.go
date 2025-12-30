// Package timestamps provides RFC 3161 timestamp support.
package timestamps

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"time"
)

// OIDs for timestamp structures
var (
	OIDContentType        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OIDTSTInfo            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	OIDSignatureTimeStamp = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

	// Hash algorithms
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// Common errors
var (
	ErrTimestampFailed   = errors.New("timestamp request failed")
	ErrTimestampRejected = errors.New("timestamp request rejected")
	ErrInvalidTimestamp  = errors.New("invalid timestamp")
	ErrTimestampMismatch = errors.New("timestamp message imprint mismatch")
)

// AlgorithmIdentifier represents an algorithm with parameters.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// MessageImprint represents the hash of the data to timestamp.
type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

// TimeStampReq represents a timestamp request (RFC 3161).
type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []Extension           `asn1:"optional,implicit,tag:0"`
}

// TimeStampResp represents a timestamp response (RFC 3161).
type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// PKIStatusInfo represents the status of a PKI operation.
type PKIStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// TSTInfo represents the timestamp token info.
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       Accuracy      `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,explicit,tag:0"`
	Extensions     []Extension   `asn1:"optional,implicit,tag:1"`
}

// Accuracy represents timestamp accuracy.
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,implicit,tag:0"`
	Micros  int `asn1:"optional,implicit,tag:1"`
}

// Extension represents an X.509 extension.
type Extension struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool `asn1:"optional,default:false"`
	ExtnValue []byte
}

// TimestampRequestOptions configures a timestamp request.
type TimestampRequestOptions struct {
	HashAlgorithm crypto.Hash
	Policy        asn1.ObjectIdentifier
	IncludeNonce  bool
	RequestCerts  bool
}

// DefaultTimestampRequestOptions returns default options.
func DefaultTimestampRequestOptions() *TimestampRequestOptions {
	return &TimestampRequestOptions{
		HashAlgorithm: crypto.SHA256,
		IncludeNonce:  true,
		RequestCerts:  true,
	}
}

// Timestamper creates timestamps.
type Timestamper interface {
	// Timestamp creates a timestamp for the given data.
	Timestamp(data []byte) ([]byte, error)
	// TimestampWithOptions creates a timestamp with custom options.
	TimestampWithOptions(data []byte, opts *TimestampRequestOptions) ([]byte, error)
}

// HTTPTimestamper implements Timestamper using HTTP.
type HTTPTimestamper struct {
	URL        string
	HTTPClient *http.Client
	Username   string
	Password   string
}

// NewHTTPTimestamper creates a new HTTP timestamper.
func NewHTTPTimestamper(url string) *HTTPTimestamper {
	return &HTTPTimestamper{
		URL: url,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetCredentials sets authentication credentials.
func (t *HTTPTimestamper) SetCredentials(username, password string) {
	t.Username = username
	t.Password = password
}

// Timestamp implements Timestamper.
func (t *HTTPTimestamper) Timestamp(data []byte) ([]byte, error) {
	return t.TimestampWithOptions(data, DefaultTimestampRequestOptions())
}

// TimestampWithOptions implements Timestamper.
func (t *HTTPTimestamper) TimestampWithOptions(data []byte, opts *TimestampRequestOptions) ([]byte, error) {
	// Create timestamp request
	req, err := CreateTimestampRequest(data, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Send request
	httpReq, err := http.NewRequest("POST", t.URL, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	if t.Username != "" {
		httpReq.SetBasicAuth(t.Username, t.Password)
	}

	resp, err := t.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTimestampFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrTimestampFailed, resp.StatusCode)
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse and validate response
	return ParseTimestampResponse(respData, data, opts.HashAlgorithm)
}

// CreateTimestampRequest creates a DER-encoded timestamp request.
func CreateTimestampRequest(data []byte, opts *TimestampRequestOptions) ([]byte, error) {
	// Hash the data
	h := getHasher(opts.HashAlgorithm)
	h.Write(data)
	digest := h.Sum(nil)

	// Create request
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm:  getHashOID(opts.HashAlgorithm),
				Parameters: asn1.RawValue{Tag: 5}, // NULL
			},
			HashedMessage: digest,
		},
		CertReq: opts.RequestCerts,
	}

	if len(opts.Policy) > 0 {
		req.ReqPolicy = opts.Policy
	}

	if opts.IncludeNonce {
		nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
		if err != nil {
			return nil, err
		}
		req.Nonce = nonce
	}

	return asn1.Marshal(req)
}

// ParseTimestampResponse parses and validates a timestamp response.
func ParseTimestampResponse(respData []byte, originalData []byte, hashAlg crypto.Hash) ([]byte, error) {
	var resp TimeStampResp
	if _, err := asn1.Unmarshal(respData, &resp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTimestamp, err)
	}

	// Check status
	if resp.Status.Status != 0 { // 0 = granted
		return nil, fmt.Errorf("%w: status %d", ErrTimestampRejected, resp.Status.Status)
	}

	// Verify message imprint
	tstInfo, err := ExtractTSTInfo(resp.TimeStampToken.FullBytes)
	if err != nil {
		return nil, err
	}

	// Compute expected hash
	h := getHasher(hashAlg)
	h.Write(originalData)
	expectedDigest := h.Sum(nil)

	if !bytes.Equal(tstInfo.MessageImprint.HashedMessage, expectedDigest) {
		return nil, ErrTimestampMismatch
	}

	return resp.TimeStampToken.FullBytes, nil
}

// ExtractTSTInfo extracts the TSTInfo from a timestamp token.
func ExtractTSTInfo(tokenData []byte) (*TSTInfo, error) {
	// Parse the ContentInfo
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(tokenData, &contentInfo); err != nil {
		return nil, err
	}

	// Parse SignedData
	var signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo struct {
			EContentType asn1.ObjectIdentifier
			EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
		}
		Certificates asn1.RawValue `asn1:"optional,implicit,tag:0"`
		SignerInfos  asn1.RawValue
	}
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, err
	}

	// Parse TSTInfo from encapsulated content
	var tstInfo TSTInfo
	if _, err := asn1.Unmarshal(signedData.EncapContentInfo.EContent.Bytes, &tstInfo); err != nil {
		return nil, fmt.Errorf("failed to parse TSTInfo: %w", err)
	}

	return &tstInfo, nil
}

// TimestampToken represents a parsed timestamp token.
type TimestampToken struct {
	Raw          []byte
	TSTInfo      *TSTInfo
	Certificates []*x509.Certificate
	SignerCert   *x509.Certificate
}

// ParseTimestampToken parses a timestamp token.
func ParseTimestampToken(data []byte) (*TimestampToken, error) {
	tstInfo, err := ExtractTSTInfo(data)
	if err != nil {
		return nil, err
	}

	token := &TimestampToken{
		Raw:     data,
		TSTInfo: tstInfo,
	}

	// Extract certificates
	token.Certificates, _ = extractCertificates(data)

	return token, nil
}

// extractCertificates extracts certificates from a CMS structure.
func extractCertificates(data []byte) ([]*x509.Certificate, error) {
	// Parse ContentInfo
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(data, &contentInfo); err != nil {
		return nil, err
	}

	// Parse SignedData to get certificates
	var signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo asn1.RawValue
		Certificates     []asn1.RawValue `asn1:"optional,implicit,tag:0,set"`
		CRLs             asn1.RawValue   `asn1:"optional,implicit,tag:1"`
		SignerInfos      asn1.RawValue
	}
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for _, certRaw := range signedData.Certificates {
		cert, err := x509.ParseCertificate(certRaw.FullBytes)
		if err == nil {
			certs = append(certs, cert)
		}
	}

	return certs, nil
}

// GetGenTime returns the generation time from a timestamp token.
func GetGenTime(tokenData []byte) (time.Time, error) {
	tstInfo, err := ExtractTSTInfo(tokenData)
	if err != nil {
		return time.Time{}, err
	}
	return tstInfo.GenTime, nil
}

// VerifyTimestamp verifies a timestamp against the original data.
func VerifyTimestamp(tokenData []byte, originalData []byte) error {
	tstInfo, err := ExtractTSTInfo(tokenData)
	if err != nil {
		return err
	}

	// Determine hash algorithm
	hashAlg := getHashFromOID(tstInfo.MessageImprint.HashAlgorithm.Algorithm)
	if hashAlg == 0 {
		return fmt.Errorf("unsupported hash algorithm")
	}

	// Compute expected hash
	h := hashAlg.New()
	h.Write(originalData)
	expectedDigest := h.Sum(nil)

	if !bytes.Equal(tstInfo.MessageImprint.HashedMessage, expectedDigest) {
		return ErrTimestampMismatch
	}

	return nil
}

// Helper functions

func getHasher(alg crypto.Hash) hash.Hash {
	switch alg {
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

func getHashOID(alg crypto.Hash) asn1.ObjectIdentifier {
	switch alg {
	case crypto.SHA384:
		return OIDSHA384
	case crypto.SHA512:
		return OIDSHA512
	default:
		return OIDSHA256
	}
}

func getHashFromOID(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(OIDSHA256):
		return crypto.SHA256
	case oid.Equal(OIDSHA384):
		return crypto.SHA384
	case oid.Equal(OIDSHA512):
		return crypto.SHA512
	default:
		return 0
	}
}

// DocumentTimestamp represents a document-level timestamp.
type DocumentTimestamp struct {
	TimestampToken []byte
	ByteRange      [4]int64
}

// CreateDocumentTimestamp creates a document-level timestamp.
func CreateDocumentTimestamp(pdfData []byte, byteRange [4]int64, timestamper Timestamper) (*DocumentTimestamp, error) {
	// Get the signed portion of the PDF
	signedData := make([]byte, byteRange[1]+byteRange[3])
	copy(signedData[:byteRange[1]], pdfData[byteRange[0]:byteRange[0]+byteRange[1]])
	copy(signedData[byteRange[1]:], pdfData[byteRange[2]:byteRange[2]+byteRange[3]])

	// Get timestamp
	token, err := timestamper.Timestamp(signedData)
	if err != nil {
		return nil, err
	}

	return &DocumentTimestamp{
		TimestampToken: token,
		ByteRange:      byteRange,
	}, nil
}
