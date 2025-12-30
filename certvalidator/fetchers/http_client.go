package fetchers

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

// HTTPClientConfig provides configuration options for creating HTTP clients.
// This struct allows for easy configuration of proxy, TLS, and timeout settings
// commonly needed in enterprise environments.
type HTTPClientConfig struct {
	// Timeout is the overall request timeout.
	// Default: 30 seconds.
	Timeout time.Duration

	// ProxyURL is the URL of the HTTP proxy to use.
	// If empty, the system's default proxy settings are used.
	// Example: "http://proxy.example.com:8080"
	ProxyURL string

	// TLSConfig provides custom TLS configuration.
	// If nil, the default TLS configuration is used.
	TLSConfig *tls.Config

	// InsecureSkipVerify disables TLS certificate verification.
	// WARNING: This should only be used for testing or development.
	// Setting this to true makes the connection vulnerable to MITM attacks.
	InsecureSkipVerify bool

	// MinTLSVersion specifies the minimum TLS version to accept.
	// Default: TLS 1.2 (recommended minimum for security).
	// Valid values: tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13
	MinTLSVersion uint16

	// MaxIdleConns controls the maximum number of idle (keep-alive) connections.
	// Default: 100.
	MaxIdleConns int

	// MaxIdleConnsPerHost controls the maximum idle connections per host.
	// Default: 10.
	MaxIdleConnsPerHost int

	// IdleConnTimeout is the maximum time an idle connection will remain idle.
	// Default: 90 seconds.
	IdleConnTimeout time.Duration

	// DisableKeepAlives disables HTTP keep-alives.
	// Default: false (keep-alives are enabled).
	DisableKeepAlives bool

	// DialTimeout is the maximum time to wait for a connection to be established.
	// Default: 30 seconds.
	DialTimeout time.Duration

	// ResponseHeaderTimeout is the maximum time to wait for response headers.
	// Default: 0 (no timeout, uses overall Timeout).
	ResponseHeaderTimeout time.Duration
}

// DefaultHTTPClientConfig returns a secure default configuration.
func DefaultHTTPClientConfig() *HTTPClientConfig {
	return &HTTPClientConfig{
		Timeout:             30 * time.Second,
		MinTLSVersion:       tls.VersionTLS12,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DialTimeout:         30 * time.Second,
	}
}

// NewHTTPClient creates an HTTP client with the specified configuration.
// This function handles all the common configuration options for enterprise deployments.
func NewHTTPClient(config *HTTPClientConfig) (*http.Client, error) {
	if config == nil {
		config = DefaultHTTPClientConfig()
	}

	// Create TLS config
	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: config.MinTLSVersion,
		}
		if config.InsecureSkipVerify {
			tlsConfig.InsecureSkipVerify = true
		}
	}

	// Set minimum TLS version if not already set
	if tlsConfig.MinVersion == 0 && config.MinTLSVersion != 0 {
		tlsConfig.MinVersion = config.MinTLSVersion
	}

	// Create dialer
	dialer := &net.Dialer{
		Timeout:   config.DialTimeout,
		KeepAlive: 30 * time.Second,
	}

	// Create transport
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsConfig,
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		IdleConnTimeout:       config.IdleConnTimeout,
		DisableKeepAlives:     config.DisableKeepAlives,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Configure proxy if specified
	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}, nil
}

// NewHTTPClientWithProxy creates an HTTP client configured to use a proxy.
// This is a convenience function for common proxy configurations.
//
// Example:
//
//	client, err := NewHTTPClientWithProxy("http://proxy.example.com:8080", 30*time.Second)
func NewHTTPClientWithProxy(proxyURL string, timeout time.Duration) (*http.Client, error) {
	config := DefaultHTTPClientConfig()
	config.ProxyURL = proxyURL
	config.Timeout = timeout
	return NewHTTPClient(config)
}

// NewHTTPClientWithTLS creates an HTTP client with custom TLS configuration.
// This is useful for connecting to servers with custom certificates or
// when specific TLS versions are required.
//
// Example:
//
//	tlsConfig := &tls.Config{
//	    MinVersion: tls.VersionTLS13,
//	    RootCAs: customCertPool,
//	}
//	client := NewHTTPClientWithTLS(tlsConfig, 30*time.Second)
func NewHTTPClientWithTLS(tlsConfig *tls.Config, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       tlsConfig,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// NewSecureHTTPClient creates an HTTP client with enhanced security settings.
// This client uses TLS 1.2 minimum, standard timeouts, and connection pooling.
// Suitable for production use when connecting to external services like
// OCSP responders and CRL distribution points.
func NewSecureHTTPClient(timeout time.Duration) *http.Client {
	config := DefaultHTTPClientConfig()
	config.Timeout = timeout
	config.MinTLSVersion = tls.VersionTLS12

	client, _ := NewHTTPClient(config)
	return client
}

// NewInsecureHTTPClient creates an HTTP client that skips TLS certificate verification.
// WARNING: This should only be used for testing or development environments.
// Using this client in production makes the connection vulnerable to MITM attacks.
func NewInsecureHTTPClient(timeout time.Duration) *http.Client {
	config := DefaultHTTPClientConfig()
	config.Timeout = timeout
	config.InsecureSkipVerify = true

	client, _ := NewHTTPClient(config)
	return client
}

// CloneHTTPClient creates a copy of an HTTP client with optional modifications.
// This is useful when you need to use the same base configuration but with
// different timeouts or other settings.
func CloneHTTPClient(client *http.Client, timeout time.Duration) *http.Client {
	if client == nil {
		return &http.Client{Timeout: timeout}
	}

	newClient := &http.Client{
		Transport:     client.Transport,
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       timeout,
	}

	return newClient
}
