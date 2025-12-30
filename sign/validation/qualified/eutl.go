// Package qualified provides EUTL (EU Trusted List) fetching and parsing
// functionality for qualified electronic signature validation.
package qualified

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EU_LOTL_LOCATION is the location of the EU's global list-of-the-lists (LOTL).
const EU_LOTL_LOCATION = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

// TLCache is a cache for trusted lists to speed up downloading.
type TLCache interface {
	// Get retrieves a cached value by key.
	Get(key string) (string, bool)
	// Set stores a value in the cache.
	Set(key string, value string)
}

// InMemoryTLCache is an in-memory cache for trusted lists.
type InMemoryTLCache struct {
	mu    sync.RWMutex
	cache map[string]string
}

// NewInMemoryTLCache creates a new in-memory TL cache.
func NewInMemoryTLCache() *InMemoryTLCache {
	return &InMemoryTLCache{
		cache: make(map[string]string),
	}
}

// Get retrieves a cached value.
func (c *InMemoryTLCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, ok := c.cache[key]
	return value, ok
}

// Set stores a value in the cache.
func (c *InMemoryTLCache) Set(key string, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = value
}

// FileSystemTLCache is a file-system backed cache for trusted lists.
type FileSystemTLCache struct {
	mu          sync.RWMutex
	root        string
	expireAfter time.Duration
	index       map[string]cacheEntry
}

type cacheEntry struct {
	ExpEpochSeconds int64  `json:"exp_epoch_seconds"`
	Fname           string `json:"fname"`
}

// NewFileSystemTLCache creates a new file system TL cache.
func NewFileSystemTLCache(cachePath string, expireAfter time.Duration) (*FileSystemTLCache, error) {
	if err := os.MkdirAll(cachePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	cache := &FileSystemTLCache{
		root:        cachePath,
		expireAfter: expireAfter,
		index:       make(map[string]cacheEntry),
	}

	// Load existing index
	indexPath := filepath.Join(cachePath, "index.json")
	if data, err := os.ReadFile(indexPath); err == nil {
		if err := json.Unmarshal(data, &cache.index); err != nil {
			// Reset index if corrupted
			cache.index = make(map[string]cacheEntry)
		}
	}

	return cache, nil
}

// Get retrieves a cached value.
func (c *FileSystemTLCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.index[key]
	if !ok {
		return "", false
	}

	// Check expiration
	if time.Now().Unix() > entry.ExpEpochSeconds {
		return "", false
	}

	// Read cached file
	cachedFilePath := filepath.Join(c.root, entry.Fname)
	content, err := os.ReadFile(cachedFilePath)
	if err != nil {
		return "", false
	}

	return string(content), true
}

// Set stores a value in the cache.
func (c *FileSystemTLCache) Set(key string, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expTime := time.Now().Add(c.expireAfter)
	hash := sha256.Sum256([]byte(key))
	fname := hex.EncodeToString(hash[:])

	// Update index
	c.index[key] = cacheEntry{
		ExpEpochSeconds: expTime.Unix(),
		Fname:           fname,
	}

	// Save index
	indexPath := filepath.Join(c.root, "index.json")
	if indexData, err := json.Marshal(c.index); err == nil {
		os.WriteFile(indexPath, indexData, 0644)
	}

	// Save content
	os.WriteFile(filepath.Join(c.root, fname), []byte(value), 0644)
}

// Reset clears the cache.
func (c *FileSystemTLCache) Reset() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, err := os.ReadDir(c.root)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		os.Remove(filepath.Join(c.root, entry.Name()))
	}

	c.index = make(map[string]cacheEntry)
	return nil
}

// TLReference is a reference to a trusted list.
type TLReference struct {
	// LocationURI is the URI where the trusted list can be found.
	LocationURI string

	// Territory is the territory with which the referenced trusted list is associated.
	Territory string

	// TLSOCerts are certificates that can be used to validate the signature
	// on the referenced trusted list.
	TLSOCerts []*x509.Certificate

	// SchemeRules are URIs for scheme rules that apply to the referenced trusted list.
	SchemeRules map[string]bool
}

// LOTLParseResult is the result of parsing a list-of-the-lists.
type LOTLParseResult struct {
	References []*TLReference
	Errors     []*TSPServiceParsingError
	PivotURLs  []string
}

// TLFetcher handles fetching trusted lists from remote locations.
type TLFetcher struct {
	client     *http.Client
	cache      TLCache
	maxRetries int
	baseDelay  time.Duration
	timeout    time.Duration
}

// TLFetcherOption is an option for configuring the TL fetcher.
type TLFetcherOption func(*TLFetcher)

// WithCache sets the cache for the fetcher.
func WithCache(cache TLCache) TLFetcherOption {
	return func(f *TLFetcher) {
		f.cache = cache
	}
}

// WithMaxRetries sets the maximum number of retries.
func WithMaxRetries(retries int) TLFetcherOption {
	return func(f *TLFetcher) {
		f.maxRetries = retries
	}
}

// WithTimeout sets the HTTP timeout.
func WithTimeout(timeout time.Duration) TLFetcherOption {
	return func(f *TLFetcher) {
		f.timeout = timeout
	}
}

// NewTLFetcher creates a new TL fetcher.
func NewTLFetcher(opts ...TLFetcherOption) *TLFetcher {
	f := &TLFetcher{
		maxRetries: 3,
		baseDelay:  2 * time.Second,
		timeout:    30 * time.Second,
	}

	for _, opt := range opts {
		opt(f)
	}

	f.client = &http.Client{
		Timeout: f.timeout,
	}

	return f
}

// Fetch fetches content from a URI.
func (f *TLFetcher) Fetch(ctx context.Context, uri string) (string, error) {
	// Check cache first
	if f.cache != nil {
		if content, ok := f.cache.Get(uri); ok {
			return content, nil
		}
	}

	// Fetch with retries
	var lastErr error
	delay := f.baseDelay

	for attempt := 0; attempt < f.maxRetries; attempt++ {
		content, err := f.doFetch(ctx, uri)
		if err == nil {
			// Store in cache
			if f.cache != nil {
				f.cache.Set(uri, content)
			}
			return content, nil
		}

		lastErr = err

		// Check for non-retriable errors
		if httpErr, ok := err.(*HTTPError); ok && httpErr.StatusCode < 500 {
			return "", err
		}

		// Wait before retry
		if attempt < f.maxRetries-1 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(delay):
				delay *= 2
			}
		}
	}

	return "", lastErr
}

func (f *TLFetcher) doFetch(ctx context.Context, uri string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "text/xml")
	req.Header.Add("Accept", ETSITSLMimeType)

	resp, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", &HTTPError{StatusCode: resp.StatusCode}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// HTTPError represents an HTTP error.
type HTTPError struct {
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP error: %d", e.StatusCode)
}

// FetchLOTL fetches the EU list-of-the-lists.
func FetchLOTL(ctx context.Context, fetcher *TLFetcher, url string) (string, error) {
	if url == "" {
		url = EU_LOTL_LOCATION
	}
	return fetcher.Fetch(ctx, url)
}

// LOTLToRegistry populates a TSPRegistry from a list-of-the-lists.
// This is a placeholder that requires XML parsing implementation.
func LOTLToRegistry(
	ctx context.Context,
	lotlXML string,
	fetcher *TLFetcher,
	tlsoCerts []*x509.Certificate,
	registry *TSPRegistry,
	onlyTerritories map[string]bool,
) (*TSPRegistry, []*TSPServiceParsingError) {
	if registry == nil {
		registry = NewTSPRegistry()
	}

	var errors []*TSPServiceParsingError

	// Note: Full XML parsing of ETSI TS 119 612 trusted lists requires
	// a comprehensive XML parser. This is a placeholder implementation.
	// In a production system, you would use an XML library to parse the
	// TrustServiceStatusList structure.

	errors = append(errors, NewTSPServiceParsingError(
		"XML parsing of trusted lists not yet implemented - use pre-parsed registry"))

	return registry, errors
}

// TLParseOptions contains options for parsing trusted lists.
type TLParseOptions struct {
	// ValidateSig indicates whether to validate the XML signature.
	ValidateSig bool
	// TLSOCerts are certificates to use for signature validation.
	TLSOCerts []*x509.Certificate
}

// ParseTrustedListUnsafe parses a trusted list without signature validation.
// Note: This is a placeholder - full implementation requires ETSI TS 119 612 XML parsing.
func ParseTrustedListUnsafe(tlXML string) (*TSPRegistry, []*TSPServiceParsingError) {
	registry := NewTSPRegistry()
	var errors []*TSPServiceParsingError

	// Placeholder: XML parsing not implemented
	errors = append(errors, NewTSPServiceParsingError(
		"XML parsing of trusted lists requires implementation"))

	return registry, errors
}

// ParseLOTLUnsafe parses a list-of-the-lists without signature validation.
// Note: This is a placeholder - full implementation requires ETSI TS 119 612 XML parsing.
func ParseLOTLUnsafe(lotlXML string) (*LOTLParseResult, error) {
	// Placeholder: XML parsing not implemented
	return &LOTLParseResult{
		References: []*TLReference{},
		Errors:     []*TSPServiceParsingError{},
		PivotURLs:  []string{},
	}, nil
}

// LatestKnownLOTLTLSOCerts retrieves the latest known LOTL signer certificates.
func LatestKnownLOTLTLSOCerts() []*x509.Certificate {
	return loadLOTLCerts("lotl-certs/latest.pem")
}

// OJEUBootstrapLOTLTLSOCerts retrieves the bootstrap LOTL certificates
// from OJ C 276, 16.8.2019.
func OJEUBootstrapLOTLTLSOCerts() []*x509.Certificate {
	return loadLOTLCerts("lotl-certs/bootstrap.pem")
}

// ValidateAndParseLOTL validates and parses a list-of-the-lists.
func ValidateAndParseLOTL(lotlXML string, tlsoCerts []*x509.Certificate) (*LOTLParseResult, error) {
	if tlsoCerts == nil {
		tlsoCerts = LatestKnownLOTLTLSOCerts()
	}

	// Note: XML signature validation requires signxml or similar library
	// For now, we parse without validation as a placeholder

	return ParseLOTLUnsafe(lotlXML)
}

// TrustedListManager manages trusted lists and their refresh.
type TrustedListManager struct {
	mu        sync.RWMutex
	registry  *TSPRegistry
	fetcher   *TLFetcher
	lastFetch time.Time
	lotlURL   string
}

// NewTrustedListManager creates a new trusted list manager.
func NewTrustedListManager(fetcher *TLFetcher) *TrustedListManager {
	return &TrustedListManager{
		registry: NewTSPRegistry(),
		fetcher:  fetcher,
		lotlURL:  EU_LOTL_LOCATION,
	}
}

// SetLOTLURL sets the LOTL URL.
func (m *TrustedListManager) SetLOTLURL(url string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lotlURL = url
}

// Registry returns the current TSP registry.
func (m *TrustedListManager) Registry() *TSPRegistry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.registry
}

// LastFetch returns the last fetch time.
func (m *TrustedListManager) LastFetch() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastFetch
}

// Refresh refreshes the trusted lists from the LOTL.
func (m *TrustedListManager) Refresh(ctx context.Context) error {
	lotlXML, err := FetchLOTL(ctx, m.fetcher, m.lotlURL)
	if err != nil {
		return fmt.Errorf("failed to fetch LOTL: %w", err)
	}

	registry, parseErrors := LOTLToRegistry(ctx, lotlXML, m.fetcher, nil, nil, nil)
	if len(parseErrors) > 0 {
		// Log errors but continue with partial results
		for _, e := range parseErrors {
			fmt.Printf("LOTL parse warning: %s\n", e.Message)
		}
	}

	m.mu.Lock()
	m.registry = registry
	m.lastFetch = time.Now()
	m.mu.Unlock()

	return nil
}

// CreateAssessor creates a QualificationAssessor from the current registry.
func (m *TrustedListManager) CreateAssessor() *QualificationAssessor {
	return NewQualificationAssessor(m.Registry())
}
