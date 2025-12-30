// Package signers provides PDF signing functionality.
// This file implements the Cloud Signature Consortium (CSC) API signer.
//
// The CSC API specification (version 1.0.4.0, 2019-06) defines a standard
// interface for remote signing services, typically using keys stored in
// cloud-based HSMs.
//
// Usage:
//  1. Create a CSCServiceSessionInfo with the service URL and credentials
//  2. Fetch certificates using FetchCertsInCSCCredential
//  3. Create a CSCAuthorizationManager to handle SAD procurement
//  4. Create a CSCSigner and use it like any other Signer
package signers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/georgepadayatti/gopdf/sign/cms"
)

// CSC signer errors
var (
	ErrCSCSigningFailed      = errors.New("CSC signing request failed")
	ErrCSCAuthFailed         = errors.New("CSC authorization failed")
	ErrCSCCredentialFailed   = errors.New("CSC credential info request failed")
	ErrCSCInvalidResponse    = errors.New("invalid CSC response")
	ErrCSCUnsupportedAlgo    = errors.New("unsupported signature algorithm")
	ErrCSCBatchMismatch      = errors.New("batch digest algorithm mismatch")
	ErrCSCSADExpired         = errors.New("SAD token expired")
	ErrCSCSADUsed            = errors.New("prefetched SAD already used")
	ErrCSCBatchSizeMismatch  = errors.New("signature count mismatch")
	ErrCSCNoSignatureResults = errors.New("no signature results available")
)

// CSCServiceSessionInfo contains information about the CSC service
// and the required authentication data.
type CSCServiceSessionInfo struct {
	// ServiceURL is the base URL of the CSC service.
	// This is the part that precedes /csc/<version>/... in endpoint URLs.
	ServiceURL string

	// CredentialID is the identifier of the CSC credential to use.
	// The format is vendor-dependent.
	CredentialID string

	// OAuthToken is the OAuth token for authentication.
	OAuthToken string

	// APIVersion is the CSC API version (e.g., "v1", "v2").
	APIVersion string
}

// NewCSCServiceSessionInfo creates a new CSC service session info.
func NewCSCServiceSessionInfo(serviceURL, credentialID string) *CSCServiceSessionInfo {
	return &CSCServiceSessionInfo{
		ServiceURL:   serviceURL,
		CredentialID: credentialID,
		APIVersion:   "v1",
	}
}

// WithOAuthToken sets the OAuth token.
func (s *CSCServiceSessionInfo) WithOAuthToken(token string) *CSCServiceSessionInfo {
	s.OAuthToken = token
	return s
}

// WithAPIVersion sets the API version.
func (s *CSCServiceSessionInfo) WithAPIVersion(version string) *CSCServiceSessionInfo {
	s.APIVersion = version
	return s
}

// EndpointURL returns the full URL for a CSC endpoint.
func (s *CSCServiceSessionInfo) EndpointURL(endpoint string) string {
	return fmt.Sprintf("%s/csc/%s/%s", s.ServiceURL, s.APIVersion, endpoint)
}

// AuthHeaders returns the HTTP headers for authentication.
func (s *CSCServiceSessionInfo) AuthHeaders() map[string]string {
	if s.OAuthToken == "" {
		return nil
	}
	return map[string]string{
		"Authorization": "Bearer " + s.OAuthToken,
	}
}

// CSCCredentialInfo contains information about a CSC credential,
// typically fetched using a credentials/info call.
type CSCCredentialInfo struct {
	// SigningCert is the signer's certificate.
	SigningCert *x509.Certificate

	// Chain contains other relevant CA certificates.
	Chain []*x509.Certificate

	// SupportedMechanisms lists signature algorithms supported by the credential.
	SupportedMechanisms []string

	// MaxBatchSize is the maximum batch size for signing.
	MaxBatchSize int

	// HashPinningRequired indicates if SAD must be tied to specific hashes.
	// This is true when SCAL=2.
	HashPinningRequired bool

	// ResponseData contains the raw JSON response from the server.
	ResponseData map[string]interface{}
}

// GetCertificates returns all certificates (signing cert + chain).
func (c *CSCCredentialInfo) GetCertificates() []*x509.Certificate {
	result := make([]*x509.Certificate, 0, 1+len(c.Chain))
	result = append(result, c.SigningCert)
	result = append(result, c.Chain...)
	return result
}

// SupportsAlgorithm checks if the credential supports the given algorithm.
func (c *CSCCredentialInfo) SupportsAlgorithm(algorithm string) bool {
	for _, alg := range c.SupportedMechanisms {
		if alg == algorithm {
			return true
		}
	}
	return false
}

// CSCAuthorizationInfo contains authorization data from credentials/authorize.
type CSCAuthorizationInfo struct {
	// SAD is the Signature Activation Data (opaque to client).
	SAD string

	// ExpiresAt is the expiry time of the SAD.
	ExpiresAt time.Time
}

// IsExpired checks if the authorization has expired.
func (a *CSCAuthorizationInfo) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

// CSCAuthorizationManager is the interface for handling authorization requests.
type CSCAuthorizationManager interface {
	// AuthorizeSignature requests a SAD token from the signing service.
	AuthorizeSignature(ctx context.Context, hashB64s []string) (*CSCAuthorizationInfo, error)

	// GetSessionInfo returns the CSC session info.
	GetSessionInfo() *CSCServiceSessionInfo

	// GetCredentialInfo returns the credential info.
	GetCredentialInfo() *CSCCredentialInfo

	// GetAuthHeaders returns authentication headers for requests.
	GetAuthHeaders() map[string]string
}

// BaseCSCAuthorizationManager provides common functionality for authorization managers.
type BaseCSCAuthorizationManager struct {
	SessionInfo    *CSCServiceSessionInfo
	CredentialInfo *CSCCredentialInfo
	HTTPClient     *http.Client
}

// GetSessionInfo returns the CSC session info.
func (m *BaseCSCAuthorizationManager) GetSessionInfo() *CSCServiceSessionInfo {
	return m.SessionInfo
}

// GetCredentialInfo returns the credential info.
func (m *BaseCSCAuthorizationManager) GetCredentialInfo() *CSCCredentialInfo {
	return m.CredentialInfo
}

// GetAuthHeaders returns authentication headers.
func (m *BaseCSCAuthorizationManager) GetAuthHeaders() map[string]string {
	return m.SessionInfo.AuthHeaders()
}

// FormatCSCAuthRequest formats the request body for credentials/authorize.
func (m *BaseCSCAuthorizationManager) FormatCSCAuthRequest(
	numSignatures int,
	pin, otp string,
	hashB64s []string,
	description, clientData string,
) map[string]interface{} {
	result := map[string]interface{}{
		"credentialID": m.SessionInfo.CredentialID,
	}

	if hashB64s != nil {
		numSignatures = len(hashB64s)
		result["hash"] = hashB64s
	}

	result["numSignatures"] = numSignatures

	if pin != "" {
		result["PIN"] = pin
	}
	if otp != "" {
		result["OTP"] = otp
	}
	if description != "" {
		result["description"] = description
	}
	if clientData != "" {
		result["clientData"] = clientData
	}

	return result
}

// ParseCSCAuthResponse parses the response from credentials/authorize.
func ParseCSCAuthResponse(responseData map[string]interface{}) (*CSCAuthorizationInfo, error) {
	sadValue, ok := responseData["SAD"]
	if !ok {
		return nil, fmt.Errorf("%w: missing SAD value", ErrCSCInvalidResponse)
	}

	sad, ok := sadValue.(string)
	if !ok {
		return nil, fmt.Errorf("%w: SAD is not a string", ErrCSCInvalidResponse)
	}

	// Parse expiresIn (defaults to 3600 seconds)
	expiresIn := 3600
	if expiresInVal, ok := responseData["expiresIn"]; ok {
		switch v := expiresInVal.(type) {
		case float64:
			expiresIn = int(v)
		case int:
			expiresIn = v
		}
	}

	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	return &CSCAuthorizationInfo{
		SAD:       sad,
		ExpiresAt: expiresAt,
	}, nil
}

// PrefetchedSADAuthorizationManager uses a pre-fetched SAD token.
// This is useful when SAD is obtained before starting the signing process.
type PrefetchedSADAuthorizationManager struct {
	*BaseCSCAuthorizationManager
	AuthInfo *CSCAuthorizationInfo
	used     bool
	mu       sync.Mutex
}

// NewPrefetchedSADAuthorizationManager creates a new prefetched SAD manager.
func NewPrefetchedSADAuthorizationManager(
	sessionInfo *CSCServiceSessionInfo,
	credentialInfo *CSCCredentialInfo,
	authInfo *CSCAuthorizationInfo,
) *PrefetchedSADAuthorizationManager {
	return &PrefetchedSADAuthorizationManager{
		BaseCSCAuthorizationManager: &BaseCSCAuthorizationManager{
			SessionInfo:    sessionInfo,
			CredentialInfo: credentialInfo,
		},
		AuthInfo: authInfo,
	}
}

// AuthorizeSignature returns the prefetched SAD or an error if already used.
func (m *PrefetchedSADAuthorizationManager) AuthorizeSignature(
	ctx context.Context,
	hashB64s []string,
) (*CSCAuthorizationInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.used {
		return nil, ErrCSCSADUsed
	}
	m.used = true

	if m.AuthInfo.IsExpired() {
		return nil, ErrCSCSADExpired
	}

	return m.AuthInfo, nil
}

// OnDemandAuthorizationManager fetches SAD on demand.
type OnDemandAuthorizationManager struct {
	*BaseCSCAuthorizationManager
	PIN        string
	OTP        string
	ClientData string
}

// NewOnDemandAuthorizationManager creates an on-demand authorization manager.
func NewOnDemandAuthorizationManager(
	sessionInfo *CSCServiceSessionInfo,
	credentialInfo *CSCCredentialInfo,
	httpClient *http.Client,
) *OnDemandAuthorizationManager {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &OnDemandAuthorizationManager{
		BaseCSCAuthorizationManager: &BaseCSCAuthorizationManager{
			SessionInfo:    sessionInfo,
			CredentialInfo: credentialInfo,
			HTTPClient:     httpClient,
		},
	}
}

// WithPIN sets the PIN for authorization.
func (m *OnDemandAuthorizationManager) WithPIN(pin string) *OnDemandAuthorizationManager {
	m.PIN = pin
	return m
}

// WithOTP sets the OTP for authorization.
func (m *OnDemandAuthorizationManager) WithOTP(otp string) *OnDemandAuthorizationManager {
	m.OTP = otp
	return m
}

// AuthorizeSignature fetches a SAD token from the service.
func (m *OnDemandAuthorizationManager) AuthorizeSignature(
	ctx context.Context,
	hashB64s []string,
) (*CSCAuthorizationInfo, error) {
	url := m.SessionInfo.EndpointURL("credentials/authorize")

	reqData := m.FormatCSCAuthRequest(
		len(hashB64s),
		m.PIN,
		m.OTP,
		hashB64s,
		"",
		m.ClientData,
	)

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal request: %v", ErrCSCAuthFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %v", ErrCSCAuthFailed, err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range m.GetAuthHeaders() {
		req.Header.Set(k, v)
	}

	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %v", ErrCSCAuthFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", ErrCSCAuthFailed, resp.StatusCode, string(body))
	}

	var responseData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %v", ErrCSCAuthFailed, err)
	}

	return ParseCSCAuthResponse(responseData)
}

// CSCSigner implements the Signer interface for CSC remote signing.
type CSCSigner struct {
	authManager CSCAuthorizationManager
	httpClient  *http.Client

	// Configuration
	SignTimeout         time.Duration
	PreferPSS           bool
	EmbedRoots          bool
	ClientData          string
	BatchAutocommit     bool
	BatchSize           int
	EstRawSignatureSize int

	// Batch state
	mu           sync.Mutex
	currentBatch *cscBatchInfo
}

// cscBatchInfo tracks batch signing state.
type cscBatchInfo struct {
	mdAlgorithm string
	b64Hashes   []string
	initiated   bool
	results     [][]byte
	done        chan struct{}
	err         error
}

// NewCSCSigner creates a new CSC signer.
func NewCSCSigner(
	authManager CSCAuthorizationManager,
	httpClient *http.Client,
) *CSCSigner {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 300 * time.Second}
	}
	return &CSCSigner{
		authManager:         authManager,
		httpClient:          httpClient,
		SignTimeout:         300 * time.Second,
		PreferPSS:           false,
		EmbedRoots:          true,
		BatchAutocommit:     true,
		BatchSize:           1,
		EstRawSignatureSize: 512,
	}
}

// WithSignTimeout sets the signing timeout.
func (s *CSCSigner) WithSignTimeout(timeout time.Duration) *CSCSigner {
	s.SignTimeout = timeout
	return s
}

// WithBatchSize sets the batch size.
func (s *CSCSigner) WithBatchSize(size int) *CSCSigner {
	s.BatchSize = size
	return s
}

// WithClientData sets the client data for requests.
func (s *CSCSigner) WithClientData(data string) *CSCSigner {
	s.ClientData = data
	return s
}

// WithPreferPSS enables RSA-PSS padding preference.
func (s *CSCSigner) WithPreferPSS(prefer bool) *CSCSigner {
	s.PreferPSS = prefer
	return s
}

// GetCertificate implements Signer.
func (s *CSCSigner) GetCertificate() *x509.Certificate {
	return s.authManager.GetCredentialInfo().SigningCert
}

// GetCertificateChain implements Signer.
func (s *CSCSigner) GetCertificateChain() []*x509.Certificate {
	return s.authManager.GetCredentialInfo().Chain
}

// GetSignatureSize implements Signer.
func (s *CSCSigner) GetSignatureSize() int {
	cert := s.GetCertificate()
	chain := s.GetCertificateChain()

	size := 8192 // Base CMS structure
	if cert != nil {
		size += len(cert.Raw)
	}
	for _, c := range chain {
		size += len(c.Raw)
	}
	return size
}

// Sign implements Signer.
func (s *CSCSigner) Sign(data []byte) ([]byte, error) {
	return s.SignWithContext(context.Background(), data)
}

// SignWithContext signs data with a context for cancellation.
func (s *CSCSigner) SignWithContext(ctx context.Context, data []byte) ([]byte, error) {
	// Default to SHA-256
	return s.SignRaw(ctx, data, "sha256", false)
}

// SignRaw signs raw data with the specified digest algorithm.
func (s *CSCSigner) SignRaw(ctx context.Context, data []byte, digestAlgorithm string, dryRun bool) ([]byte, error) {
	if dryRun {
		return make([]byte, s.EstRawSignatureSize), nil
	}

	// Compute and base64-encode the hash
	tbsHash := Base64Digest(data, digestAlgorithm)

	s.mu.Lock()

	// Ensure we have a batch
	batch, err := s.ensureBatch(digestAlgorithm)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}

	// Add to batch
	ix := len(batch.b64Hashes)
	batch.b64Hashes = append(batch.b64Hashes, tbsHash)

	// Check if we should autocommit
	shouldCommit := s.BatchAutocommit && len(batch.b64Hashes) >= s.BatchSize

	s.mu.Unlock()

	if shouldCommit {
		if err := s.Commit(ctx); err != nil {
			// Log error but continue - we'll get an error when waiting
			_ = err
		}
	}

	// Wait for batch completion
	select {
	case <-batch.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if batch.err != nil {
		return nil, batch.err
	}

	if batch.results == nil || ix >= len(batch.results) {
		return nil, ErrCSCNoSignatureResults
	}

	return batch.results[ix], nil
}

// ensureBatch ensures there's an active batch for the given algorithm.
func (s *CSCSigner) ensureBatch(digestAlgorithm string) (*cscBatchInfo, error) {
	if s.currentBatch != nil {
		if s.currentBatch.initiated {
			// Wait for current batch to complete
			return nil, fmt.Errorf("batch commit in progress")
		}
		if s.currentBatch.mdAlgorithm != digestAlgorithm {
			return nil, fmt.Errorf("%w: expected %s, got %s",
				ErrCSCBatchMismatch, s.currentBatch.mdAlgorithm, digestAlgorithm)
		}
		return s.currentBatch, nil
	}

	s.currentBatch = &cscBatchInfo{
		mdAlgorithm: digestAlgorithm,
		b64Hashes:   make([]string, 0),
		done:        make(chan struct{}),
	}
	return s.currentBatch, nil
}

// Commit commits the current batch by calling signatures/signHash.
func (s *CSCSigner) Commit(ctx context.Context) error {
	s.mu.Lock()
	batch := s.currentBatch
	if batch == nil || batch.results != nil {
		s.mu.Unlock()
		return nil
	}
	if batch.initiated {
		s.mu.Unlock()
		// Wait for ongoing commit
		<-batch.done
		return batch.err
	}
	batch.initiated = true
	s.mu.Unlock()

	return s.doCommit(ctx, batch)
}

// doCommit performs the actual signing request.
func (s *CSCSigner) doCommit(ctx context.Context, batch *cscBatchInfo) error {
	defer func() {
		s.mu.Lock()
		s.currentBatch = nil
		s.mu.Unlock()
		close(batch.done)
	}()

	// Get authorization
	authInfo, err := s.authManager.AuthorizeSignature(ctx, batch.b64Hashes)
	if err != nil {
		batch.err = err
		return err
	}

	// Format signing request
	reqData, err := s.formatSigningRequest(batch.b64Hashes, batch.mdAlgorithm, authInfo)
	if err != nil {
		batch.err = err
		return err
	}

	// Make request
	sessionInfo := s.authManager.GetSessionInfo()
	url := sessionInfo.EndpointURL("signatures/signHash")

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		batch.err = fmt.Errorf("%w: failed to marshal request: %v", ErrCSCSigningFailed, err)
		return batch.err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		batch.err = fmt.Errorf("%w: failed to create request: %v", ErrCSCSigningFailed, err)
		return batch.err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.authManager.GetAuthHeaders() {
		req.Header.Set(k, v)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		batch.err = fmt.Errorf("%w: request failed: %v", ErrCSCSigningFailed, err)
		return batch.err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		batch.err = fmt.Errorf("%w: status %d: %s", ErrCSCSigningFailed, resp.StatusCode, string(body))
		return batch.err
	}

	var responseData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		batch.err = fmt.Errorf("%w: failed to decode response: %v", ErrCSCSigningFailed, err)
		return batch.err
	}

	// Parse signatures
	sigB64s, ok := responseData["signatures"].([]interface{})
	if !ok {
		batch.err = fmt.Errorf("%w: missing signatures in response", ErrCSCInvalidResponse)
		return batch.err
	}

	if len(sigB64s) != len(batch.b64Hashes) {
		batch.err = fmt.Errorf("%w: expected %d, got %d",
			ErrCSCBatchSizeMismatch, len(batch.b64Hashes), len(sigB64s))
		return batch.err
	}

	signatures := make([][]byte, len(sigB64s))
	for i, sigB64 := range sigB64s {
		sigStr, ok := sigB64.(string)
		if !ok {
			batch.err = fmt.Errorf("%w: signature %d is not a string", ErrCSCInvalidResponse, i)
			return batch.err
		}
		sig, err := base64.StdEncoding.DecodeString(sigStr)
		if err != nil {
			batch.err = fmt.Errorf("%w: failed to decode signature %d: %v", ErrCSCInvalidResponse, i, err)
			return batch.err
		}
		signatures[i] = sig
	}

	batch.results = signatures
	return nil
}

// formatSigningRequest formats the request for signatures/signHash.
func (s *CSCSigner) formatSigningRequest(
	tbsHashes []string,
	digestAlgorithm string,
	authInfo *CSCAuthorizationInfo,
) (map[string]interface{}, error) {
	sessionInfo := s.authManager.GetSessionInfo()

	// Get digest algorithm OID
	hashAlgoOID, err := getDigestAlgorithmOID(digestAlgorithm)
	if err != nil {
		return nil, err
	}

	// Get signature algorithm OID
	signAlgoOID, signAlgoParams, err := s.getSignatureAlgorithmOID(digestAlgorithm)
	if err != nil {
		return nil, err
	}

	reqData := map[string]interface{}{
		"credentialID": sessionInfo.CredentialID,
		"SAD":          authInfo.SAD,
		"hashAlgo":     hashAlgoOID,
		"signAlgo":     signAlgoOID,
		"hash":         tbsHashes,
	}

	if signAlgoParams != "" {
		reqData["signAlgoParams"] = signAlgoParams
	}

	if s.ClientData != "" {
		reqData["clientData"] = s.ClientData
	}

	return reqData, nil
}

// getSignatureAlgorithmOID returns the OID for the signature algorithm.
func (s *CSCSigner) getSignatureAlgorithmOID(digestAlgorithm string) (string, string, error) {
	credInfo := s.authManager.GetCredentialInfo()
	cert := credInfo.SigningCert

	// Determine key type from certificate
	var keyType string
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		keyType = "rsa"
	case x509.ECDSA:
		keyType = "ecdsa"
	case x509.Ed25519:
		keyType = "ed25519"
	default:
		return "", "", fmt.Errorf("%w: unknown key type", ErrCSCUnsupportedAlgo)
	}

	// Select algorithm based on key type and digest
	switch keyType {
	case "rsa":
		if s.PreferPSS {
			switch digestAlgorithm {
			case "sha256":
				return "1.2.840.113549.1.1.10", "", nil // rsassa-pss
			case "sha384":
				return "1.2.840.113549.1.1.10", "", nil
			case "sha512":
				return "1.2.840.113549.1.1.10", "", nil
			}
		}
		switch digestAlgorithm {
		case "sha256":
			return "1.2.840.113549.1.1.11", "", nil // sha256WithRSAEncryption
		case "sha384":
			return "1.2.840.113549.1.1.12", "", nil // sha384WithRSAEncryption
		case "sha512":
			return "1.2.840.113549.1.1.13", "", nil // sha512WithRSAEncryption
		}
	case "ecdsa":
		switch digestAlgorithm {
		case "sha256":
			return "1.2.840.10045.4.3.2", "", nil // ecdsa-with-SHA256
		case "sha384":
			return "1.2.840.10045.4.3.3", "", nil // ecdsa-with-SHA384
		case "sha512":
			return "1.2.840.10045.4.3.4", "", nil // ecdsa-with-SHA512
		}
	case "ed25519":
		return "1.3.101.112", "", nil // Ed25519
	}

	return "", "", fmt.Errorf("%w: %s with %s", ErrCSCUnsupportedAlgo, keyType, digestAlgorithm)
}

// getDigestAlgorithmOID returns the OID for a digest algorithm.
func getDigestAlgorithmOID(algorithm string) (string, error) {
	switch algorithm {
	case "sha256":
		return "2.16.840.1.101.3.4.2.1", nil
	case "sha384":
		return "2.16.840.1.101.3.4.2.2", nil
	case "sha512":
		return "2.16.840.1.101.3.4.2.3", nil
	case "sha1":
		return "1.3.14.3.2.26", nil
	default:
		return "", fmt.Errorf("%w: %s", ErrCSCUnsupportedAlgo, algorithm)
	}
}

// Base64Digest computes a digest and returns it as base64.
func Base64Digest(data []byte, digestAlgorithm string) string {
	var digest []byte

	switch digestAlgorithm {
	case "sha256":
		h := sha256.Sum256(data)
		digest = h[:]
	case "sha384":
		h := sha512.Sum384(data)
		digest = h[:]
	case "sha512":
		h := sha512.Sum512(data)
		digest = h[:]
	default:
		// Default to SHA-256
		h := sha256.Sum256(data)
		digest = h[:]
	}

	return base64.StdEncoding.EncodeToString(digest)
}

// FetchCertsInCSCCredential fetches certificate information from a CSC service.
func FetchCertsInCSCCredential(
	ctx context.Context,
	httpClient *http.Client,
	sessionInfo *CSCServiceSessionInfo,
) (*CSCCredentialInfo, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	url := sessionInfo.EndpointURL("credentials/info")

	reqData := map[string]interface{}{
		"credentialID": sessionInfo.CredentialID,
		"certificates": "chain",
		"certInfo":     false,
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal request: %v", ErrCSCCredentialFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %v", ErrCSCCredentialFailed, err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range sessionInfo.AuthHeaders() {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %v", ErrCSCCredentialFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", ErrCSCCredentialFailed, resp.StatusCode, string(body))
	}

	var responseData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %v", ErrCSCCredentialFailed, err)
	}

	return ParseCredentialInfoResponse(responseData)
}

// ParseCredentialInfoResponse parses the response from credentials/info.
func ParseCredentialInfoResponse(responseData map[string]interface{}) (*CSCCredentialInfo, error) {
	// Parse certificates
	certData, ok := responseData["cert"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: missing cert data", ErrCSCInvalidResponse)
	}

	certsB64, ok := certData["certificates"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: missing certificates array", ErrCSCInvalidResponse)
	}

	certs := make([]*x509.Certificate, 0, len(certsB64))
	for i, certB64 := range certsB64 {
		certStr, ok := certB64.(string)
		if !ok {
			return nil, fmt.Errorf("%w: certificate %d is not a string", ErrCSCInvalidResponse, i)
		}

		certDER, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decode certificate %d: %v", ErrCSCInvalidResponse, i, err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse certificate %d: %v", ErrCSCInvalidResponse, i, err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificates in response", ErrCSCInvalidResponse)
	}

	// Parse supported algorithms
	keyData, ok := responseData["key"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: missing key data", ErrCSCInvalidResponse)
	}

	algoOIDs, ok := keyData["algo"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: missing algo array", ErrCSCInvalidResponse)
	}

	mechanisms := make([]string, 0, len(algoOIDs))
	for _, oid := range algoOIDs {
		oidStr, ok := oid.(string)
		if ok {
			mechanisms = append(mechanisms, oidStr)
		}
	}

	// Parse max batch size
	maxBatchSize := 1
	if multisign, ok := responseData["multisign"]; ok {
		switch v := multisign.(type) {
		case float64:
			maxBatchSize = int(v)
		case int:
			maxBatchSize = v
		}
	}

	// Parse SCAL value
	hashPinningRequired := false
	if scal, ok := responseData["SCAL"]; ok {
		switch v := scal.(type) {
		case float64:
			hashPinningRequired = int(v) == 2
		case int:
			hashPinningRequired = v == 2
		}
	}

	return &CSCCredentialInfo{
		SigningCert:         certs[0],
		Chain:               certs[1:],
		SupportedMechanisms: mechanisms,
		MaxBatchSize:        maxBatchSize,
		HashPinningRequired: hashPinningRequired,
		ResponseData:        responseData,
	}, nil
}

// CSCSignerBuilder provides a fluent API for building a CSCSigner.
type CSCSignerBuilder struct {
	sessionInfo    *CSCServiceSessionInfo
	credentialInfo *CSCCredentialInfo
	authInfo       *CSCAuthorizationInfo
	httpClient     *http.Client
	signTimeout    time.Duration
	batchSize      int
	preferPSS      bool
	clientData     string
	pin            string
	otp            string
}

// NewCSCSignerBuilder creates a new builder for CSCSigner.
func NewCSCSignerBuilder(sessionInfo *CSCServiceSessionInfo) *CSCSignerBuilder {
	return &CSCSignerBuilder{
		sessionInfo: sessionInfo,
		signTimeout: 300 * time.Second,
		batchSize:   1,
	}
}

// WithCredentialInfo sets the credential info (skips fetching).
func (b *CSCSignerBuilder) WithCredentialInfo(info *CSCCredentialInfo) *CSCSignerBuilder {
	b.credentialInfo = info
	return b
}

// WithPrefetchedSAD sets pre-fetched authorization data.
func (b *CSCSignerBuilder) WithPrefetchedSAD(authInfo *CSCAuthorizationInfo) *CSCSignerBuilder {
	b.authInfo = authInfo
	return b
}

// WithHTTPClient sets the HTTP client.
func (b *CSCSignerBuilder) WithHTTPClient(client *http.Client) *CSCSignerBuilder {
	b.httpClient = client
	return b
}

// WithSignTimeout sets the signing timeout.
func (b *CSCSignerBuilder) WithSignTimeout(timeout time.Duration) *CSCSignerBuilder {
	b.signTimeout = timeout
	return b
}

// WithBatchSize sets the batch size.
func (b *CSCSignerBuilder) WithBatchSize(size int) *CSCSignerBuilder {
	b.batchSize = size
	return b
}

// WithPreferPSS enables RSA-PSS preference.
func (b *CSCSignerBuilder) WithPreferPSS(prefer bool) *CSCSignerBuilder {
	b.preferPSS = prefer
	return b
}

// WithClientData sets the client data.
func (b *CSCSignerBuilder) WithClientData(data string) *CSCSignerBuilder {
	b.clientData = data
	return b
}

// WithPIN sets the PIN for on-demand authorization.
func (b *CSCSignerBuilder) WithPIN(pin string) *CSCSignerBuilder {
	b.pin = pin
	return b
}

// WithOTP sets the OTP for on-demand authorization.
func (b *CSCSignerBuilder) WithOTP(otp string) *CSCSignerBuilder {
	b.otp = otp
	return b
}

// Build creates the CSCSigner.
func (b *CSCSignerBuilder) Build(ctx context.Context) (*CSCSigner, error) {
	if b.httpClient == nil {
		b.httpClient = &http.Client{Timeout: b.signTimeout}
	}

	// Fetch credential info if not provided
	if b.credentialInfo == nil {
		info, err := FetchCertsInCSCCredential(ctx, b.httpClient, b.sessionInfo)
		if err != nil {
			return nil, err
		}
		b.credentialInfo = info
	}

	// Create authorization manager
	var authManager CSCAuthorizationManager
	if b.authInfo != nil {
		authManager = NewPrefetchedSADAuthorizationManager(
			b.sessionInfo,
			b.credentialInfo,
			b.authInfo,
		)
	} else {
		manager := NewOnDemandAuthorizationManager(
			b.sessionInfo,
			b.credentialInfo,
			b.httpClient,
		)
		if b.pin != "" {
			manager.WithPIN(b.pin)
		}
		if b.otp != "" {
			manager.WithOTP(b.otp)
		}
		manager.ClientData = b.clientData
		authManager = manager
	}

	signer := NewCSCSigner(authManager, b.httpClient)
	signer.SignTimeout = b.signTimeout
	signer.BatchSize = b.batchSize
	signer.PreferPSS = b.preferPSS
	signer.ClientData = b.clientData

	return signer, nil
}

// Ensure CSCSigner implements Signer
var _ Signer = (*CSCSigner)(nil)

// GetHasher returns a hasher for the given algorithm.
func GetHasher(algorithm string) crypto.Hash {
	switch algorithm {
	case "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	case "sha1":
		return crypto.SHA1
	default:
		return crypto.SHA256
	}
}

// CMSSignerAdapter wraps CSCSigner to build full CMS signatures.
type CMSSignerAdapter struct {
	*CSCSigner
	digestAlgorithm string
}

func cmsAlgorithmForDigest(cert *x509.Certificate, digestAlgorithm string) (cms.SignatureAlgorithm, error) {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		switch digestAlgorithm {
		case "sha256":
			return cms.SHA256WithRSA, nil
		case "sha384":
			return cms.SHA384WithRSA, nil
		case "sha512":
			return cms.SHA512WithRSA, nil
		}
	case x509.ECDSA:
		switch digestAlgorithm {
		case "sha256":
			return cms.SHA256WithECDSA, nil
		case "sha384":
			return cms.SHA384WithECDSA, nil
		case "sha512":
			return cms.SHA512WithECDSA, nil
		}
	}

	return cms.SignatureAlgorithm{}, fmt.Errorf("%w: unsupported algorithm %s for %s",
		ErrCSCUnsupportedAlgo, digestAlgorithm, cert.PublicKeyAlgorithm.String())
}

// NewCMSSignerAdapter creates a CMS-compatible adapter for CSCSigner.
func NewCMSSignerAdapter(signer *CSCSigner, digestAlgorithm string) *CMSSignerAdapter {
	return &CMSSignerAdapter{
		CSCSigner:       signer,
		digestAlgorithm: strings.ToLower(digestAlgorithm),
	}
}

// Sign builds a complete CMS signature.
func (a *CMSSignerAdapter) Sign(data []byte) ([]byte, error) {
	ctx := context.Background()

	cert := a.GetCertificate()
	chain := a.GetCertificateChain()

	alg, err := cmsAlgorithmForDigest(cert, a.digestAlgorithm)
	if err != nil {
		return nil, err
	}

	builder := cms.NewCMSBuilder(cert, nil, alg)
	builder.SetCertificateChain(chain)

	_, signedAttrsBytes, err := builder.SignedAttributesForSigning(data)
	if err != nil {
		return nil, err
	}

	rawSig, err := a.CSCSigner.SignRaw(ctx, signedAttrsBytes, a.digestAlgorithm, false)
	if err != nil {
		return nil, err
	}

	if cert.PublicKeyAlgorithm == x509.ECDSA {
		rawSig, err = normalizeECDSASignature(cert, rawSig)
		if err != nil {
			return nil, err
		}
	}

	builder.SetPrecomputedSignature(rawSig)

	return builder.Sign(data)
}

func normalizeECDSASignature(cert *x509.Certificate, sig []byte) ([]byte, error) {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub == nil {
		return nil, fmt.Errorf("%w: missing ECDSA public key", ErrCSCUnsupportedAlgo)
	}

	var parsedSig struct {
		R *big.Int
		S *big.Int
	}
	if rest, err := asn1.Unmarshal(sig, &parsedSig); err == nil && len(rest) == 0 && parsedSig.R != nil && parsedSig.S != nil {
		return sig, nil
	}

	keyBytes := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*keyBytes {
		return nil, fmt.Errorf("%w: unexpected ECDSA signature length %d", ErrCSCUnsupportedAlgo, len(sig))
	}

	r := new(big.Int).SetBytes(sig[:keyBytes])
	s := new(big.Int).SetBytes(sig[keyBytes:])
	return asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: r, S: s})
}
