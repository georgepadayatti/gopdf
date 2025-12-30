package qualified

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEU_LOTL_LOCATION(t *testing.T) {
	expected := "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
	if EU_LOTL_LOCATION != expected {
		t.Errorf("EU_LOTL_LOCATION = %q, want %q", EU_LOTL_LOCATION, expected)
	}
}

func TestNewInMemoryTLCache(t *testing.T) {
	cache := NewInMemoryTLCache()
	if cache == nil {
		t.Error("NewInMemoryTLCache returned nil")
	}
	if cache.cache == nil {
		t.Error("cache map not initialized")
	}
}

func TestInMemoryTLCache_GetSet(t *testing.T) {
	cache := NewInMemoryTLCache()

	// Test get non-existent key
	_, ok := cache.Get("key1")
	if ok {
		t.Error("Expected ok = false for non-existent key")
	}

	// Test set and get
	cache.Set("key1", "value1")
	value, ok := cache.Get("key1")
	if !ok {
		t.Error("Expected ok = true after Set")
	}
	if value != "value1" {
		t.Errorf("Expected value = 'value1', got %q", value)
	}

	// Test overwrite
	cache.Set("key1", "value2")
	value, ok = cache.Get("key1")
	if !ok || value != "value2" {
		t.Error("Overwrite failed")
	}
}

func TestNewFileSystemTLCache(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tlcache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cache, err := NewFileSystemTLCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("NewFileSystemTLCache failed: %v", err)
	}
	if cache == nil {
		t.Error("cache is nil")
	}
	if cache.expireAfter != 1*time.Hour {
		t.Error("expireAfter not set correctly")
	}
}

func TestFileSystemTLCache_GetSet(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tlcache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cache, err := NewFileSystemTLCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("NewFileSystemTLCache failed: %v", err)
	}

	// Test get non-existent key
	_, ok := cache.Get("key1")
	if ok {
		t.Error("Expected ok = false for non-existent key")
	}

	// Test set and get
	cache.Set("key1", "value1")
	value, ok := cache.Get("key1")
	if !ok {
		t.Error("Expected ok = true after Set")
	}
	if value != "value1" {
		t.Errorf("Expected value = 'value1', got %q", value)
	}

	// Verify file was created
	files, _ := os.ReadDir(tmpDir)
	if len(files) < 2 { // index.json + cached file
		t.Errorf("Expected at least 2 files in cache dir, got %d", len(files))
	}
}

func TestFileSystemTLCache_Expiration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tlcache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test with expiration in the past (-1 second) to avoid timing issues
	cache := &FileSystemTLCache{
		root:        tmpDir,
		expireAfter: -1 * time.Second, // Already expired when set
		index:       make(map[string]cacheEntry),
	}

	// Manually set an entry with immediate past expiration
	cache.mu.Lock()
	cache.index["key1"] = cacheEntry{
		ExpEpochSeconds: time.Now().Add(-1 * time.Second).Unix(),
		Fname:           "testfile",
	}
	// Create the cached file
	os.WriteFile(filepath.Join(tmpDir, "testfile"), []byte("value1"), 0644)
	cache.mu.Unlock()

	_, ok := cache.Get("key1")
	if ok {
		t.Error("Expected cache entry to be expired")
	}
}

func TestFileSystemTLCache_Reset(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tlcache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cache, err := NewFileSystemTLCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("NewFileSystemTLCache failed: %v", err)
	}

	cache.Set("key1", "value1")
	cache.Set("key2", "value2")

	err = cache.Reset()
	if err != nil {
		t.Errorf("Reset failed: %v", err)
	}

	_, ok := cache.Get("key1")
	if ok {
		t.Error("Expected cache to be empty after Reset")
	}

	files, _ := os.ReadDir(tmpDir)
	if len(files) != 0 {
		t.Errorf("Expected empty cache dir after Reset, got %d files", len(files))
	}
}

func TestFileSystemTLCache_PersistenceAcrossInstances(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tlcache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// First instance
	cache1, err := NewFileSystemTLCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("NewFileSystemTLCache failed: %v", err)
	}
	cache1.Set("key1", "value1")

	// Second instance - should load from disk
	cache2, err := NewFileSystemTLCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("NewFileSystemTLCache failed: %v", err)
	}

	value, ok := cache2.Get("key1")
	if !ok {
		t.Error("Expected cache entry to persist across instances")
	}
	if value != "value1" {
		t.Errorf("Expected value = 'value1', got %q", value)
	}
}

func TestNewTLFetcher_Defaults(t *testing.T) {
	fetcher := NewTLFetcher()
	if fetcher == nil {
		t.Error("NewTLFetcher returned nil")
	}
	if fetcher.maxRetries != 3 {
		t.Errorf("Expected maxRetries = 3, got %d", fetcher.maxRetries)
	}
	if fetcher.baseDelay != 2*time.Second {
		t.Errorf("Expected baseDelay = 2s, got %v", fetcher.baseDelay)
	}
	if fetcher.timeout != 30*time.Second {
		t.Errorf("Expected timeout = 30s, got %v", fetcher.timeout)
	}
}

func TestNewTLFetcher_WithOptions(t *testing.T) {
	cache := NewInMemoryTLCache()
	fetcher := NewTLFetcher(
		WithCache(cache),
		WithMaxRetries(5),
		WithTimeout(60*time.Second),
	)

	if fetcher.cache != cache {
		t.Error("Cache not set correctly")
	}
	if fetcher.maxRetries != 5 {
		t.Errorf("Expected maxRetries = 5, got %d", fetcher.maxRetries)
	}
	if fetcher.timeout != 60*time.Second {
		t.Errorf("Expected timeout = 60s, got %v", fetcher.timeout)
	}
}

func TestTLFetcher_Fetch_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<xml>test</xml>"))
	}))
	defer server.Close()

	fetcher := NewTLFetcher()
	content, err := fetcher.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Errorf("Fetch failed: %v", err)
	}
	if content != "<xml>test</xml>" {
		t.Errorf("Expected content = '<xml>test</xml>', got %q", content)
	}
}

func TestTLFetcher_Fetch_WithCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<xml>test</xml>"))
	}))
	defer server.Close()

	cache := NewInMemoryTLCache()
	fetcher := NewTLFetcher(WithCache(cache))

	// First fetch
	content1, err := fetcher.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Errorf("First fetch failed: %v", err)
	}

	// Second fetch - should use cache
	content2, err := fetcher.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Errorf("Second fetch failed: %v", err)
	}

	if content1 != content2 {
		t.Error("Content should be same from cache")
	}
	if callCount != 1 {
		t.Errorf("Expected server to be called once, called %d times", callCount)
	}
}

func TestTLFetcher_Fetch_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	fetcher := NewTLFetcher(WithMaxRetries(1))
	_, err := fetcher.Fetch(context.Background(), server.URL)
	if err == nil {
		t.Error("Expected error for 404 response")
	}
	if httpErr, ok := err.(*HTTPError); ok {
		if httpErr.StatusCode != http.StatusNotFound {
			t.Errorf("Expected StatusCode = 404, got %d", httpErr.StatusCode)
		}
	} else {
		t.Error("Expected HTTPError")
	}
}

func TestTLFetcher_Fetch_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	fetcher := NewTLFetcher()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := fetcher.Fetch(ctx, server.URL)
	if err == nil {
		t.Error("Expected error for cancelled context")
	}
}

func TestHTTPError(t *testing.T) {
	err := &HTTPError{StatusCode: 404}
	expected := "HTTP error: 404"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestFetchLOTL_DefaultURL(t *testing.T) {
	// Skip actual network call
	fetcher := NewTLFetcher(WithMaxRetries(1), WithTimeout(1*time.Second))
	_, err := FetchLOTL(context.Background(), fetcher, "")
	// We expect an error since we're not mocking the actual EU server
	// This test verifies the function doesn't panic with empty URL
	if err == nil {
		t.Log("FetchLOTL succeeded (unexpected in test environment)")
	}
}

func TestFetchLOTL_CustomURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<xml>lotl</xml>"))
	}))
	defer server.Close()

	fetcher := NewTLFetcher()
	content, err := FetchLOTL(context.Background(), fetcher, server.URL)
	if err != nil {
		t.Errorf("FetchLOTL failed: %v", err)
	}
	if content != "<xml>lotl</xml>" {
		t.Errorf("Unexpected content: %q", content)
	}
}

func TestLOTLToRegistry(t *testing.T) {
	registry := NewTSPRegistry()
	fetcher := NewTLFetcher()

	result, errors := LOTLToRegistry(
		context.Background(),
		"<xml>dummy</xml>",
		fetcher,
		nil,
		registry,
		nil,
	)

	if result == nil {
		t.Error("Expected non-nil registry")
	}
	if len(errors) == 0 {
		t.Error("Expected parsing errors (placeholder implementation)")
	}
}

func TestLOTLToRegistry_NilRegistry(t *testing.T) {
	fetcher := NewTLFetcher()

	result, _ := LOTLToRegistry(
		context.Background(),
		"<xml>dummy</xml>",
		fetcher,
		nil,
		nil,
		nil,
	)

	if result == nil {
		t.Error("Expected new registry to be created")
	}
}

func TestParseTrustedListUnsafe(t *testing.T) {
	registry, errors := ParseTrustedListUnsafe("<xml>test</xml>")
	if registry == nil {
		t.Error("Expected non-nil registry")
	}
	if len(errors) == 0 {
		t.Error("Expected parsing errors (placeholder implementation)")
	}
}

func TestParseLOTLUnsafe(t *testing.T) {
	result, err := ParseLOTLUnsafe("<xml>test</xml>")
	if err != nil {
		t.Errorf("ParseLOTLUnsafe failed: %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result")
	}
	if result.References == nil {
		t.Error("Expected References to be initialized")
	}
}

func TestLatestKnownLOTLTLSOCerts(t *testing.T) {
	certs := LatestKnownLOTLTLSOCerts()
	// Placeholder returns nil
	if certs != nil {
		t.Log("LatestKnownLOTLTLSOCerts returned certs (unexpected for placeholder)")
	}
}

func TestOJEUBootstrapLOTLTLSOCerts(t *testing.T) {
	certs := OJEUBootstrapLOTLTLSOCerts()
	// Placeholder returns nil
	if certs != nil {
		t.Log("OJEUBootstrapLOTLTLSOCerts returned certs (unexpected for placeholder)")
	}
}

func TestValidateAndParseLOTL(t *testing.T) {
	result, err := ValidateAndParseLOTL("<xml>test</xml>", nil)
	if err != nil {
		t.Errorf("ValidateAndParseLOTL failed: %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestNewTrustedListManager(t *testing.T) {
	fetcher := NewTLFetcher()
	manager := NewTrustedListManager(fetcher)

	if manager == nil {
		t.Error("NewTrustedListManager returned nil")
	}
	if manager.registry == nil {
		t.Error("Registry not initialized")
	}
	if manager.fetcher != fetcher {
		t.Error("Fetcher not set correctly")
	}
	if manager.lotlURL != EU_LOTL_LOCATION {
		t.Errorf("lotlURL = %q, want %q", manager.lotlURL, EU_LOTL_LOCATION)
	}
}

func TestTrustedListManager_SetLOTLURL(t *testing.T) {
	fetcher := NewTLFetcher()
	manager := NewTrustedListManager(fetcher)

	customURL := "https://example.com/lotl.xml"
	manager.SetLOTLURL(customURL)

	if manager.lotlURL != customURL {
		t.Errorf("lotlURL = %q, want %q", manager.lotlURL, customURL)
	}
}

func TestTrustedListManager_Registry(t *testing.T) {
	fetcher := NewTLFetcher()
	manager := NewTrustedListManager(fetcher)

	registry := manager.Registry()
	if registry == nil {
		t.Error("Registry returned nil")
	}
}

func TestTrustedListManager_LastFetch(t *testing.T) {
	fetcher := NewTLFetcher()
	manager := NewTrustedListManager(fetcher)

	lastFetch := manager.LastFetch()
	if !lastFetch.IsZero() {
		t.Error("Expected zero time before any fetch")
	}
}

func TestTrustedListManager_CreateAssessor(t *testing.T) {
	fetcher := NewTLFetcher()
	manager := NewTrustedListManager(fetcher)

	assessor := manager.CreateAssessor()
	if assessor == nil {
		t.Error("CreateAssessor returned nil")
	}
}

func TestTrustedListManager_Refresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<xml>lotl</xml>"))
	}))
	defer server.Close()

	fetcher := NewTLFetcher()
	manager := NewTrustedListManager(fetcher)
	manager.SetLOTLURL(server.URL)

	err := manager.Refresh(context.Background())
	if err != nil {
		t.Errorf("Refresh failed: %v", err)
	}

	if manager.LastFetch().IsZero() {
		t.Error("LastFetch should be set after Refresh")
	}
}

func TestTrustedListManager_Refresh_Error(t *testing.T) {
	fetcher := NewTLFetcher(WithMaxRetries(1), WithTimeout(1*time.Second))
	manager := NewTrustedListManager(fetcher)
	manager.SetLOTLURL("http://invalid-url-that-does-not-exist.example.com")

	err := manager.Refresh(context.Background())
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestTLReference(t *testing.T) {
	ref := TLReference{
		LocationURI: "https://example.com/tl.xml",
		Territory:   "DE",
		TLSOCerts:   nil,
		SchemeRules: map[string]bool{"rule1": true},
	}

	if ref.LocationURI != "https://example.com/tl.xml" {
		t.Error("LocationURI not set correctly")
	}
	if ref.Territory != "DE" {
		t.Error("Territory not set correctly")
	}
	if !ref.SchemeRules["rule1"] {
		t.Error("SchemeRules not set correctly")
	}
}

func TestLOTLParseResult(t *testing.T) {
	result := LOTLParseResult{
		References: []*TLReference{
			{Territory: "DE"},
			{Territory: "FR"},
		},
		Errors:    []*TSPServiceParsingError{},
		PivotURLs: []string{"url1", "url2"},
	}

	if len(result.References) != 2 {
		t.Errorf("Expected 2 references, got %d", len(result.References))
	}
	if len(result.PivotURLs) != 2 {
		t.Errorf("Expected 2 pivot URLs, got %d", len(result.PivotURLs))
	}
}

func TestTLParseOptions(t *testing.T) {
	opts := TLParseOptions{
		ValidateSig: true,
		TLSOCerts:   nil,
	}

	if !opts.ValidateSig {
		t.Error("ValidateSig not set correctly")
	}
}

func TestFileSystemTLCache_InvalidPath(t *testing.T) {
	// Test with an invalid/non-writable path
	// On most systems, trying to create a directory in root should fail
	_, err := NewFileSystemTLCache("/nonexistent/invalid/path", 1*time.Hour)
	if err == nil {
		// May succeed on some systems, that's ok
		t.Log("NewFileSystemTLCache succeeded with unusual path")
	}
}

func TestFileSystemTLCache_CorruptedIndex(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tlcache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write corrupted index
	indexPath := filepath.Join(tmpDir, "index.json")
	os.WriteFile(indexPath, []byte("not valid json"), 0644)

	// Should handle gracefully
	cache, err := NewFileSystemTLCache(tmpDir, 1*time.Hour)
	if err != nil {
		t.Fatalf("Should handle corrupted index gracefully: %v", err)
	}
	if len(cache.index) != 0 {
		t.Error("Expected empty index after corrupted file")
	}
}
