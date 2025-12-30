package fetchers

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultHTTPClientConfig(t *testing.T) {
	config := DefaultHTTPClientConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", config.Timeout)
	}

	if config.MinTLSVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinTLSVersion TLS1.2, got %v", config.MinTLSVersion)
	}

	if config.MaxIdleConns != 100 {
		t.Errorf("Expected MaxIdleConns 100, got %d", config.MaxIdleConns)
	}

	if config.MaxIdleConnsPerHost != 10 {
		t.Errorf("Expected MaxIdleConnsPerHost 10, got %d", config.MaxIdleConnsPerHost)
	}

	if config.IdleConnTimeout != 90*time.Second {
		t.Errorf("Expected IdleConnTimeout 90s, got %v", config.IdleConnTimeout)
	}

	if config.DialTimeout != 30*time.Second {
		t.Errorf("Expected DialTimeout 30s, got %v", config.DialTimeout)
	}

	if config.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}
}

func TestNewHTTPClient(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		client, err := NewHTTPClient(nil)
		if err != nil {
			t.Fatalf("NewHTTPClient(nil) error: %v", err)
		}
		if client == nil {
			t.Fatal("NewHTTPClient(nil) returned nil client")
		}
		if client.Timeout != 30*time.Second {
			t.Errorf("Expected timeout 30s, got %v", client.Timeout)
		}
	})

	t.Run("CustomTimeout", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		config.Timeout = 60 * time.Second

		client, err := NewHTTPClient(config)
		if err != nil {
			t.Fatalf("NewHTTPClient error: %v", err)
		}
		if client.Timeout != 60*time.Second {
			t.Errorf("Expected timeout 60s, got %v", client.Timeout)
		}
	})

	t.Run("CustomTLS", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		config.MinTLSVersion = tls.VersionTLS13

		client, err := NewHTTPClient(config)
		if err != nil {
			t.Fatalf("NewHTTPClient error: %v", err)
		}
		if client == nil {
			t.Fatal("Client is nil")
		}

		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatal("Transport is not *http.Transport")
		}
		if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
			t.Errorf("Expected MinVersion TLS1.3, got %v", transport.TLSClientConfig.MinVersion)
		}
	})

	t.Run("InvalidProxyURL", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		config.ProxyURL = "://invalid-url"

		_, err := NewHTTPClient(config)
		if err == nil {
			t.Error("Expected error for invalid proxy URL")
		}
	})

	t.Run("ValidProxyURL", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		config.ProxyURL = "http://proxy.example.com:8080"

		client, err := NewHTTPClient(config)
		if err != nil {
			t.Fatalf("NewHTTPClient error: %v", err)
		}
		if client == nil {
			t.Fatal("Client is nil")
		}
	})

	t.Run("InsecureSkipVerify", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		config.InsecureSkipVerify = true

		client, err := NewHTTPClient(config)
		if err != nil {
			t.Fatalf("NewHTTPClient error: %v", err)
		}

		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatal("Transport is not *http.Transport")
		}
		if !transport.TLSClientConfig.InsecureSkipVerify {
			t.Error("Expected InsecureSkipVerify to be true")
		}
	})
}

func TestNewHTTPClientWithProxy(t *testing.T) {
	client, err := NewHTTPClientWithProxy("http://proxy.example.com:8080", 15*time.Second)
	if err != nil {
		t.Fatalf("NewHTTPClientWithProxy error: %v", err)
	}
	if client == nil {
		t.Fatal("Client is nil")
	}
	if client.Timeout != 15*time.Second {
		t.Errorf("Expected timeout 15s, got %v", client.Timeout)
	}
}

func TestNewHTTPClientWithTLS(t *testing.T) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	client := NewHTTPClientWithTLS(tlsConfig, 20*time.Second)
	if client == nil {
		t.Fatal("Client is nil")
	}
	if client.Timeout != 20*time.Second {
		t.Errorf("Expected timeout 20s, got %v", client.Timeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if transport.TLSClientConfig != tlsConfig {
		t.Error("TLSClientConfig not set correctly")
	}
}

func TestNewSecureHTTPClient(t *testing.T) {
	client := NewSecureHTTPClient(25 * time.Second)
	if client == nil {
		t.Fatal("Client is nil")
	}
	if client.Timeout != 25*time.Second {
		t.Errorf("Expected timeout 25s, got %v", client.Timeout)
	}
}

func TestNewInsecureHTTPClient(t *testing.T) {
	client := NewInsecureHTTPClient(10 * time.Second)
	if client == nil {
		t.Fatal("Client is nil")
	}
	if client.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", client.Timeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be true")
	}
}

func TestCloneHTTPClient(t *testing.T) {
	t.Run("CloneNilClient", func(t *testing.T) {
		cloned := CloneHTTPClient(nil, 15*time.Second)
		if cloned == nil {
			t.Fatal("Cloned client is nil")
		}
		if cloned.Timeout != 15*time.Second {
			t.Errorf("Expected timeout 15s, got %v", cloned.Timeout)
		}
	})

	t.Run("CloneExistingClient", func(t *testing.T) {
		original := &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns: 50,
			},
		}

		cloned := CloneHTTPClient(original, 20*time.Second)
		if cloned == nil {
			t.Fatal("Cloned client is nil")
		}
		if cloned.Timeout != 20*time.Second {
			t.Errorf("Expected timeout 20s, got %v", cloned.Timeout)
		}
		// Transport should be shared
		if cloned.Transport != original.Transport {
			t.Error("Transport should be shared")
		}
	})
}

func TestHTTPClientFunctional(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	t.Run("SecureClient", func(t *testing.T) {
		client := NewSecureHTTPClient(5 * time.Second)
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("CustomConfig", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		config.Timeout = 5 * time.Second
		config.MaxIdleConns = 5

		client, err := NewHTTPClient(config)
		if err != nil {
			t.Fatalf("NewHTTPClient error: %v", err)
		}

		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})
}

func TestFetcherWithCustomHTTPClient(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test data"))
	}))
	defer server.Close()

	t.Run("ConfigWithHTTPClient", func(t *testing.T) {
		customClient := &http.Client{Timeout: 5 * time.Second}
		config := DefaultConfig()
		config.HTTPClient = customClient

		fetcher := NewFetcher(config)
		if fetcher.GetHTTPClient() != customClient {
			t.Error("Fetcher should use the custom HTTP client")
		}
	})

	t.Run("ConfigWithTransport", func(t *testing.T) {
		transport := &http.Transport{MaxIdleConns: 50}
		config := DefaultConfig()
		config.Transport = transport

		fetcher := NewFetcher(config)
		client := fetcher.GetHTTPClient()
		if client.Transport != transport {
			t.Error("Fetcher should use the custom transport")
		}
	})

	t.Run("NewFetcherWithClient", func(t *testing.T) {
		customClient := &http.Client{Timeout: 10 * time.Second}
		fetcher := NewFetcherWithClient(nil, customClient)

		if fetcher.GetHTTPClient() != customClient {
			t.Error("Fetcher should use the provided client")
		}
	})
}
