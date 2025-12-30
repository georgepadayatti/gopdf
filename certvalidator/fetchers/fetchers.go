// Package fetchers provides certificate, CRL, and OCSP fetching functionality.
package fetchers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Common errors
var (
	ErrFetchFailed          = errors.New("fetch failed")
	ErrInvalidResponse      = errors.New("invalid response")
	ErrTimeout              = errors.New("request timed out")
	ErrCRLParseFailed       = errors.New("CRL parse failed")
	ErrOCSPParseFailed      = errors.New("OCSP parse failed")
	ErrCertParseFailed      = errors.New("certificate parse failed")
	ErrNoDistributionPoints = errors.New("no CRL distribution points")
	ErrNoOCSPServers        = errors.New("no OCSP servers")
)

// FetcherConfig configures the fetcher behavior.
type FetcherConfig struct {
	// HTTP client timeout
	Timeout time.Duration
	// Maximum response size in bytes
	MaxResponseSize int64
	// User-Agent header
	UserAgent string
	// Whether to use caching
	UseCache bool
	// Cache TTL
	CacheTTL time.Duration
	// Maximum retry attempts (deprecated: use RetryConfig instead)
	MaxRetries int
	// Retry delay (deprecated: use RetryConfig instead)
	RetryDelay time.Duration

	// RetryConfig provides advanced retry configuration with exponential backoff.
	// If nil, basic retry with MaxRetries and RetryDelay is used.
	RetryConfig *RetryConfig

	// UseParallelURLs when true, attempts multiple URLs in parallel for OCSP/CRL.
	// This can reduce latency but increases load on external services.
	// Default: false (sequential)
	UseParallelURLs bool

	// CircuitBreaker provides circuit breaker protection for external services.
	// If nil, no circuit breaker is used.
	CircuitBreaker *CircuitBreaker

	// HTTPClient allows using a custom HTTP client.
	// If nil, a default client will be created with the specified Timeout.
	// Use this for custom TLS configuration, proxy support, or connection pooling.
	//
	// Example with proxy:
	//   proxyURL, _ := url.Parse("http://proxy.example.com:8080")
	//   transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	//   config.HTTPClient = &http.Client{Transport: transport, Timeout: 30*time.Second}
	//
	// Example with custom TLS:
	//   tlsConfig := &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12}
	//   transport := &http.Transport{TLSClientConfig: tlsConfig}
	//   config.HTTPClient = &http.Client{Transport: transport, Timeout: 30*time.Second}
	HTTPClient *http.Client

	// Transport allows specifying a custom HTTP transport.
	// This is a convenience option - if both HTTPClient and Transport are set,
	// HTTPClient takes precedence.
	// Use this for proxy configuration, TLS settings, or connection limits.
	Transport *http.Transport
}

// DefaultConfig returns the default fetcher configuration.
func DefaultConfig() *FetcherConfig {
	return &FetcherConfig{
		Timeout:         30 * time.Second,
		MaxResponseSize: 10 * 1024 * 1024, // 10 MB
		UserAgent:       "gopdf-certvalidator/1.0",
		UseCache:        true,
		CacheTTL:        1 * time.Hour,
		MaxRetries:      3,
		RetryDelay:      1 * time.Second,
	}
}

// Fetcher provides HTTP fetching functionality.
type Fetcher struct {
	config *FetcherConfig
	client *http.Client
	cache  *responseCache
}

// NewFetcher creates a new fetcher.
func NewFetcher(config *FetcherConfig) *Fetcher {
	if config == nil {
		config = DefaultConfig()
	}

	// Determine which HTTP client to use
	client := config.HTTPClient
	if client == nil {
		// Create a new client
		if config.Transport != nil {
			// Use the provided transport
			client = &http.Client{
				Transport: config.Transport,
				Timeout:   config.Timeout,
			}
		} else {
			// Use default transport with timeout
			client = &http.Client{
				Timeout: config.Timeout,
			}
		}
	}

	return &Fetcher{
		config: config,
		client: client,
		cache:  newResponseCache(config.CacheTTL),
	}
}

// NewFetcherWithClient creates a new fetcher with a custom HTTP client.
// This is a convenience function for enterprise deployments that need
// custom proxy, TLS, or authentication settings.
func NewFetcherWithClient(config *FetcherConfig, client *http.Client) *Fetcher {
	if config == nil {
		config = DefaultConfig()
	}
	if client == nil {
		client = &http.Client{Timeout: config.Timeout}
	}

	return &Fetcher{
		config: config,
		client: client,
		cache:  newResponseCache(config.CacheTTL),
	}
}

// GetHTTPClient returns the HTTP client used by this fetcher.
// This can be useful for inspecting or sharing the client configuration.
func (f *Fetcher) GetHTTPClient() *http.Client {
	return f.client
}

// responseCache implements a simple in-memory cache.
type responseCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	data      []byte
	expiresAt time.Time
}

func newResponseCache(ttl time.Duration) *responseCache {
	return &responseCache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
}

func (c *responseCache) get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.data, true
}

func (c *responseCache) set(key string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Fetch fetches data from a URL.
func (f *Fetcher) Fetch(ctx context.Context, urlStr string) ([]byte, error) {
	// Check cache
	if f.config.UseCache {
		if data, ok := f.cache.get(urlStr); ok {
			return data, nil
		}
	}

	// Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid URL: %v", ErrFetchFailed, err)
	}

	// Only allow HTTP and HTTPS
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("%w: unsupported scheme: %s", ErrFetchFailed, parsedURL.Scheme)
	}

	var lastErr error
	for attempt := 0; attempt <= f.config.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(f.config.RetryDelay):
			}
		}

		data, err := f.doFetch(ctx, urlStr)
		if err == nil {
			// Cache successful response
			if f.config.UseCache {
				f.cache.set(urlStr, data)
			}
			return data, nil
		}

		lastErr = err
	}

	return nil, lastErr
}

func (f *Fetcher) doFetch(ctx context.Context, urlStr string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}

	req.Header.Set("User-Agent", f.config.UserAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrFetchFailed, resp.StatusCode)
	}

	// Limit response size
	reader := io.LimitReader(resp.Body, f.config.MaxResponseSize)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}

	return data, nil
}

// CRLFetcher fetches Certificate Revocation Lists.
type CRLFetcher struct {
	fetcher *Fetcher
}

// NewCRLFetcher creates a new CRL fetcher.
func NewCRLFetcher(config *FetcherConfig) *CRLFetcher {
	return &CRLFetcher{
		fetcher: NewFetcher(config),
	}
}

// FetchCRL fetches a CRL from a URL.
func (f *CRLFetcher) FetchCRL(ctx context.Context, urlStr string) (*x509.RevocationList, error) {
	data, err := f.fetcher.Fetch(ctx, urlStr)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCRLParseFailed, err)
	}

	return crl, nil
}

// FetchCRLsForCert fetches all CRLs for a certificate.
func (f *CRLFetcher) FetchCRLsForCert(ctx context.Context, cert *x509.Certificate) ([]*x509.RevocationList, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		return nil, ErrNoDistributionPoints
	}

	var crls []*x509.RevocationList
	var lastErr error

	for _, dp := range cert.CRLDistributionPoints {
		crl, err := f.FetchCRL(ctx, dp)
		if err != nil {
			lastErr = err
			continue
		}
		crls = append(crls, crl)
	}

	if len(crls) == 0 && lastErr != nil {
		return nil, lastErr
	}

	return crls, nil
}

// FetchCRLWithRetry fetches a CRL with retry logic.
func (f *CRLFetcher) FetchCRLWithRetry(ctx context.Context, urlStr string) (*x509.RevocationList, *RetryResult, error) {
	retryConfig := f.fetcher.config.RetryConfig
	if retryConfig == nil {
		retryConfig = DefaultRetryConfig()
	}

	// Check circuit breaker if configured
	if cb := f.fetcher.config.CircuitBreaker; cb != nil {
		if !cb.Allow() {
			return nil, nil, ErrCircuitOpen
		}
	}

	crl, result := Retry(ctx, retryConfig, func(ctx context.Context) (*x509.RevocationList, error) {
		return f.FetchCRL(ctx, urlStr)
	})

	// Record result in circuit breaker
	if cb := f.fetcher.config.CircuitBreaker; cb != nil {
		if result.Success {
			cb.RecordSuccess()
		} else {
			cb.RecordFailure()
		}
	}

	if !result.Success {
		return nil, result, result.AllErrors()
	}

	return crl, result, nil
}

// FetchAnyCRLForCert fetches the first successful CRL from any distribution point.
// Unlike FetchCRLsForCert, this returns as soon as one CRL is successfully fetched.
func (f *CRLFetcher) FetchAnyCRLForCert(ctx context.Context, cert *x509.Certificate) (*x509.RevocationList, *MultiURLResult, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		return nil, nil, ErrNoDistributionPoints
	}

	// Get retry config
	retryConfig := f.fetcher.config.RetryConfig
	if retryConfig == nil {
		retryConfig = DefaultRetryConfig()
	}

	// Check circuit breaker if configured
	if cb := f.fetcher.config.CircuitBreaker; cb != nil {
		if !cb.Allow() {
			return nil, nil, ErrCircuitOpen
		}
	}

	// Use parallel or sequential URL fetching
	var crl *x509.RevocationList
	var multiResult *MultiURLResult

	if f.fetcher.config.UseParallelURLs {
		var parallelResult *ParallelMultiURLResult
		crl, parallelResult = RetryMultiURLParallel(ctx, retryConfig, cert.CRLDistributionPoints,
			func(ctx context.Context, url string) (*x509.RevocationList, error) {
				return f.FetchCRL(ctx, url)
			})
		multiResult = &parallelResult.MultiURLResult
	} else {
		crl, multiResult = RetryMultiURL(ctx, retryConfig, cert.CRLDistributionPoints,
			func(ctx context.Context, url string) (*x509.RevocationList, error) {
				return f.FetchCRL(ctx, url)
			})
	}

	// Record result in circuit breaker
	if cb := f.fetcher.config.CircuitBreaker; cb != nil {
		if multiResult.Success {
			cb.RecordSuccess()
		} else {
			cb.RecordFailure()
		}
	}

	if !multiResult.Success {
		return nil, multiResult, multiResult.AllErrors()
	}

	return crl, multiResult, nil
}

// OCSPFetcher fetches OCSP responses.
type OCSPFetcher struct {
	fetcher *Fetcher
}

// NewOCSPFetcher creates a new OCSP fetcher.
func NewOCSPFetcher(config *FetcherConfig) *OCSPFetcher {
	return &OCSPFetcher{
		fetcher: NewFetcher(config),
	}
}

// OCSPRequest represents an OCSP request.
type OCSPRequest struct {
	// Certificate to check
	Certificate *x509.Certificate
	// Issuer certificate
	Issuer *x509.Certificate
	// Hash algorithm to use
	HashAlgorithm x509.SignatureAlgorithm
}

// FetchOCSP fetches an OCSP response.
func (f *OCSPFetcher) FetchOCSP(ctx context.Context, req *OCSPRequest) (*ocsp.Response, error) {
	if len(req.Certificate.OCSPServer) == 0 {
		return nil, ErrNoOCSPServers
	}

	// Create OCSP request
	ocspReq, err := ocsp.CreateRequest(req.Certificate, req.Issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Get retry config
	retryConfig := f.fetcher.config.RetryConfig
	if retryConfig == nil {
		// Fall back to legacy config
		retryConfig = &RetryConfig{
			MaxAttempts:  f.fetcher.config.MaxRetries + 1,
			InitialDelay: f.fetcher.config.RetryDelay,
			MaxDelay:     f.fetcher.config.RetryDelay * 10,
			Multiplier:   2.0,
			Jitter:       0.1,
		}
	}

	// Check circuit breaker if configured
	if cb := f.fetcher.config.CircuitBreaker; cb != nil {
		if !cb.Allow() {
			return nil, ErrCircuitOpen
		}
	}

	// Use parallel or sequential URL fetching
	var resp *ocsp.Response
	var multiResult *MultiURLResult

	if f.fetcher.config.UseParallelURLs {
		var parallelResult *ParallelMultiURLResult
		resp, parallelResult = RetryMultiURLParallel(ctx, retryConfig, req.Certificate.OCSPServer,
			func(ctx context.Context, url string) (*ocsp.Response, error) {
				return f.fetchFromServer(ctx, url, ocspReq, req.Issuer)
			})
		multiResult = &parallelResult.MultiURLResult
	} else {
		resp, multiResult = RetryMultiURL(ctx, retryConfig, req.Certificate.OCSPServer,
			func(ctx context.Context, url string) (*ocsp.Response, error) {
				return f.fetchFromServer(ctx, url, ocspReq, req.Issuer)
			})
	}

	// Record result in circuit breaker
	if cb := f.fetcher.config.CircuitBreaker; cb != nil {
		if multiResult.Success {
			cb.RecordSuccess()
		} else {
			cb.RecordFailure()
		}
	}

	if !multiResult.Success {
		return nil, multiResult.AllErrors()
	}

	return resp, nil
}

// FetchOCSPWithResult fetches an OCSP response and returns detailed result info.
func (f *OCSPFetcher) FetchOCSPWithResult(ctx context.Context, req *OCSPRequest) (*ocsp.Response, *MultiURLResult, error) {
	if len(req.Certificate.OCSPServer) == 0 {
		return nil, nil, ErrNoOCSPServers
	}

	// Create OCSP request
	ocspReq, err := ocsp.CreateRequest(req.Certificate, req.Issuer, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Get retry config
	retryConfig := f.fetcher.config.RetryConfig
	if retryConfig == nil {
		retryConfig = DefaultRetryConfig()
	}

	// Use parallel or sequential URL fetching
	var resp *ocsp.Response
	var multiResult *MultiURLResult

	if f.fetcher.config.UseParallelURLs {
		var parallelResult *ParallelMultiURLResult
		resp, parallelResult = RetryMultiURLParallel(ctx, retryConfig, req.Certificate.OCSPServer,
			func(ctx context.Context, url string) (*ocsp.Response, error) {
				return f.fetchFromServer(ctx, url, ocspReq, req.Issuer)
			})
		multiResult = &parallelResult.MultiURLResult
	} else {
		resp, multiResult = RetryMultiURL(ctx, retryConfig, req.Certificate.OCSPServer,
			func(ctx context.Context, url string) (*ocsp.Response, error) {
				return f.fetchFromServer(ctx, url, ocspReq, req.Issuer)
			})
	}

	if !multiResult.Success {
		return nil, multiResult, multiResult.AllErrors()
	}

	return resp, multiResult, nil
}

func (f *OCSPFetcher) fetchFromServer(ctx context.Context, serverURL string, ocspReq []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	// Try POST first (preferred for larger requests)
	resp, err := f.fetchPOST(ctx, serverURL, ocspReq, issuer)
	if err == nil {
		return resp, nil
	}

	// Fallback to GET (base64 encoded request in URL)
	return f.fetchGET(ctx, serverURL, ocspReq, issuer)
}

func (f *OCSPFetcher) fetchPOST(ctx context.Context, serverURL string, ocspReq []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL, bytes.NewReader(ocspReq))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("User-Agent", f.fetcher.config.UserAgent)

	resp, err := f.fetcher.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrFetchFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.fetcher.config.MaxResponseSize))
	if err != nil {
		return nil, err
	}

	ocspResp, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOCSPParseFailed, err)
	}

	return ocspResp, nil
}

func (f *OCSPFetcher) fetchGET(ctx context.Context, serverURL string, ocspReq []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	// Base64 encode the request
	encoded := base64.StdEncoding.EncodeToString(ocspReq)
	fullURL := serverURL + "/" + url.PathEscape(encoded)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", f.fetcher.config.UserAgent)

	resp, err := f.fetcher.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrFetchFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.fetcher.config.MaxResponseSize))
	if err != nil {
		return nil, err
	}

	ocspResp, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOCSPParseFailed, err)
	}

	return ocspResp, nil
}

// CertFetcher fetches certificates.
type CertFetcher struct {
	fetcher *Fetcher
}

// NewCertFetcher creates a new certificate fetcher.
func NewCertFetcher(config *FetcherConfig) *CertFetcher {
	return &CertFetcher{
		fetcher: NewFetcher(config),
	}
}

// FetchCertificate fetches a certificate from a URL.
func (f *CertFetcher) FetchCertificate(ctx context.Context, urlStr string) (*x509.Certificate, error) {
	data, err := f.fetcher.Fetch(ctx, urlStr)
	if err != nil {
		return nil, err
	}

	// Try parsing as DER
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return cert, nil
	}

	// Try parsing as PEM
	certs, err := parseCertificatePEM(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertParseFailed, err)
	}

	if len(certs) == 0 {
		return nil, ErrCertParseFailed
	}

	return certs[0], nil
}

// FetchCertificates fetches multiple certificates from a URL.
func (f *CertFetcher) FetchCertificates(ctx context.Context, urlStr string) ([]*x509.Certificate, error) {
	data, err := f.fetcher.Fetch(ctx, urlStr)
	if err != nil {
		return nil, err
	}

	// Try parsing as DER (PKCS#7 or single cert)
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return []*x509.Certificate{cert}, nil
	}

	// Try parsing as PEM
	certs, err := parseCertificatePEM(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertParseFailed, err)
	}

	return certs, nil
}

// FetchIssuingCertificate fetches the issuing certificate for a given certificate.
func (f *CertFetcher) FetchIssuingCertificate(ctx context.Context, cert *x509.Certificate) (*x509.Certificate, error) {
	for _, url := range cert.IssuingCertificateURL {
		issuer, err := f.FetchCertificate(ctx, url)
		if err == nil {
			return issuer, nil
		}
	}
	return nil, fmt.Errorf("no issuing certificate found")
}

// parseCertificatePEM parses PEM-encoded certificates.
func parseCertificatePEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	// Simple PEM block detection
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		return nil, errors.New("not PEM encoded")
	}

	rest := data
	for len(rest) > 0 {
		// Find PEM block
		startIdx := bytes.Index(rest, []byte("-----BEGIN"))
		if startIdx == -1 {
			break
		}

		endMarker := []byte("-----END")
		endIdx := bytes.Index(rest[startIdx:], endMarker)
		if endIdx == -1 {
			break
		}

		// Find the end of the end marker line
		endIdx += startIdx
		lineEnd := bytes.IndexByte(rest[endIdx:], '\n')
		if lineEnd == -1 {
			lineEnd = len(rest) - endIdx
		} else {
			lineEnd++
		}

		block := rest[startIdx : endIdx+lineEnd]
		rest = rest[endIdx+lineEnd:]

		// Skip if not a certificate
		if !bytes.Contains(block, []byte("CERTIFICATE")) {
			continue
		}

		// Extract base64 content
		lines := bytes.Split(block, []byte("\n"))
		var b64Data []byte
		for _, line := range lines {
			line = bytes.TrimSpace(line)
			if len(line) == 0 || bytes.HasPrefix(line, []byte("-----")) {
				continue
			}
			b64Data = append(b64Data, line...)
		}

		derData, err := base64.StdEncoding.DecodeString(string(b64Data))
		if err != nil {
			continue
		}

		cert, err := x509.ParseCertificate(derData)
		if err != nil {
			continue
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// RevocationChecker checks certificate revocation status.
type RevocationChecker struct {
	crlFetcher  *CRLFetcher
	ocspFetcher *OCSPFetcher
	preferOCSP  bool
}

// NewRevocationChecker creates a new revocation checker.
func NewRevocationChecker(config *FetcherConfig, preferOCSP bool) *RevocationChecker {
	return &RevocationChecker{
		crlFetcher:  NewCRLFetcher(config),
		ocspFetcher: NewOCSPFetcher(config),
		preferOCSP:  preferOCSP,
	}
}

// RevocationStatus represents the revocation status of a certificate.
type RevocationStatus int

const (
	RevocationStatusUnknown RevocationStatus = iota
	RevocationStatusGood
	RevocationStatusRevoked
)

// String returns a string representation of the revocation status.
func (s RevocationStatus) String() string {
	switch s {
	case RevocationStatusGood:
		return "good"
	case RevocationStatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// RevocationResult contains the result of a revocation check.
type RevocationResult struct {
	Status         RevocationStatus
	Source         string // "OCSP" or "CRL"
	RevocationTime *time.Time
	Reason         string
	Error          error
}

// CheckRevocation checks if a certificate is revoked.
func (c *RevocationChecker) CheckRevocation(ctx context.Context, cert, issuer *x509.Certificate) *RevocationResult {
	if c.preferOCSP {
		// Try OCSP first
		result := c.checkOCSP(ctx, cert, issuer)
		if result.Status != RevocationStatusUnknown {
			return result
		}

		// Fall back to CRL
		return c.checkCRL(ctx, cert, issuer)
	}

	// Try CRL first
	result := c.checkCRL(ctx, cert, issuer)
	if result.Status != RevocationStatusUnknown {
		return result
	}

	// Fall back to OCSP
	return c.checkOCSP(ctx, cert, issuer)
}

func (c *RevocationChecker) checkOCSP(ctx context.Context, cert, issuer *x509.Certificate) *RevocationResult {
	req := &OCSPRequest{
		Certificate: cert,
		Issuer:      issuer,
	}

	resp, err := c.ocspFetcher.FetchOCSP(ctx, req)
	if err != nil {
		return &RevocationResult{
			Status: RevocationStatusUnknown,
			Source: "OCSP",
			Error:  err,
		}
	}

	switch resp.Status {
	case ocsp.Good:
		return &RevocationResult{
			Status: RevocationStatusGood,
			Source: "OCSP",
		}
	case ocsp.Revoked:
		return &RevocationResult{
			Status:         RevocationStatusRevoked,
			Source:         "OCSP",
			RevocationTime: &resp.RevokedAt,
			Reason:         fmt.Sprintf("revocation reason: %d", resp.RevocationReason),
		}
	default:
		return &RevocationResult{
			Status: RevocationStatusUnknown,
			Source: "OCSP",
		}
	}
}

func (c *RevocationChecker) checkCRL(ctx context.Context, cert, issuer *x509.Certificate) *RevocationResult {
	crls, err := c.crlFetcher.FetchCRLsForCert(ctx, cert)
	if err != nil {
		return &RevocationResult{
			Status: RevocationStatusUnknown,
			Source: "CRL",
			Error:  err,
		}
	}

	for _, crl := range crls {
		// Check if certificate is in CRL
		for _, revoked := range crl.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return &RevocationResult{
					Status:         RevocationStatusRevoked,
					Source:         "CRL",
					RevocationTime: &revoked.RevocationTime,
					Reason:         fmt.Sprintf("revocation reason: %d", revoked.ReasonCode),
				}
			}
		}
	}

	return &RevocationResult{
		Status: RevocationStatusGood,
		Source: "CRL",
	}
}

// AIA (Authority Information Access) fetcher
type AIAFetcher struct {
	certFetcher *CertFetcher
	ocspFetcher *OCSPFetcher
}

// NewAIAFetcher creates a new AIA fetcher.
func NewAIAFetcher(config *FetcherConfig) *AIAFetcher {
	return &AIAFetcher{
		certFetcher: NewCertFetcher(config),
		ocspFetcher: NewOCSPFetcher(config),
	}
}

// FetchIssuers fetches issuer certificates via AIA.
func (f *AIAFetcher) FetchIssuers(ctx context.Context, cert *x509.Certificate) ([]*x509.Certificate, error) {
	var issuers []*x509.Certificate

	for _, url := range cert.IssuingCertificateURL {
		certs, err := f.certFetcher.FetchCertificates(ctx, url)
		if err != nil {
			continue
		}
		issuers = append(issuers, certs...)
	}

	if len(issuers) == 0 {
		return nil, errors.New("no issuers found via AIA")
	}

	return issuers, nil
}

// ClearCache clears the response cache.
func (f *Fetcher) ClearCache() {
	f.cache.mu.Lock()
	defer f.cache.mu.Unlock()
	f.cache.entries = make(map[string]*cacheEntry)
}
