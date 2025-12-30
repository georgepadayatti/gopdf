package signers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func generateTestCert() (*x509.Certificate, *rsa.PrivateKey) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Signer",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	return cert, key
}

func TestCSCServiceSessionInfo(t *testing.T) {
	t.Run("NewCSCServiceSessionInfo", func(t *testing.T) {
		info := NewCSCServiceSessionInfo("https://csc.example.com", "cred123")

		if info.ServiceURL != "https://csc.example.com" {
			t.Errorf("ServiceURL = %q", info.ServiceURL)
		}
		if info.CredentialID != "cred123" {
			t.Errorf("CredentialID = %q", info.CredentialID)
		}
		if info.APIVersion != "v1" {
			t.Errorf("APIVersion = %q", info.APIVersion)
		}
	})

	t.Run("WithOAuthToken", func(t *testing.T) {
		info := NewCSCServiceSessionInfo("https://csc.example.com", "cred123").
			WithOAuthToken("token123")

		if info.OAuthToken != "token123" {
			t.Errorf("OAuthToken = %q", info.OAuthToken)
		}
	})

	t.Run("WithAPIVersion", func(t *testing.T) {
		info := NewCSCServiceSessionInfo("https://csc.example.com", "cred123").
			WithAPIVersion("v2")

		if info.APIVersion != "v2" {
			t.Errorf("APIVersion = %q", info.APIVersion)
		}
	})

	t.Run("EndpointURL", func(t *testing.T) {
		info := NewCSCServiceSessionInfo("https://csc.example.com", "cred123")

		url := info.EndpointURL("credentials/info")
		expected := "https://csc.example.com/csc/v1/credentials/info"
		if url != expected {
			t.Errorf("EndpointURL = %q, want %q", url, expected)
		}
	})

	t.Run("AuthHeaders_WithToken", func(t *testing.T) {
		info := NewCSCServiceSessionInfo("https://csc.example.com", "cred123").
			WithOAuthToken("token123")

		headers := info.AuthHeaders()
		if headers["Authorization"] != "Bearer token123" {
			t.Errorf("Authorization = %q", headers["Authorization"])
		}
	})

	t.Run("AuthHeaders_NoToken", func(t *testing.T) {
		info := NewCSCServiceSessionInfo("https://csc.example.com", "cred123")

		headers := info.AuthHeaders()
		if headers != nil {
			t.Errorf("Expected nil headers, got %v", headers)
		}
	})
}

func TestCSCCredentialInfo(t *testing.T) {
	cert, _ := generateTestCert()
	chainCert, _ := generateTestCert()

	t.Run("GetCertificates", func(t *testing.T) {
		info := &CSCCredentialInfo{
			SigningCert: cert,
			Chain:       []*x509.Certificate{chainCert},
		}

		certs := info.GetCertificates()
		if len(certs) != 2 {
			t.Errorf("len(certs) = %d, want 2", len(certs))
		}
		if certs[0] != cert {
			t.Error("First cert should be signing cert")
		}
		if certs[1] != chainCert {
			t.Error("Second cert should be chain cert")
		}
	})

	t.Run("SupportsAlgorithm", func(t *testing.T) {
		info := &CSCCredentialInfo{
			SupportedMechanisms: []string{"1.2.840.113549.1.1.11", "1.2.840.10045.4.3.2"},
		}

		if !info.SupportsAlgorithm("1.2.840.113549.1.1.11") {
			t.Error("Should support sha256WithRSAEncryption")
		}
		if info.SupportsAlgorithm("unknown") {
			t.Error("Should not support unknown")
		}
	})
}

func TestCSCAuthorizationInfo(t *testing.T) {
	t.Run("IsExpired_NotExpired", func(t *testing.T) {
		info := &CSCAuthorizationInfo{
			SAD:       "test-sad",
			ExpiresAt: time.Now().Add(time.Hour),
		}

		if info.IsExpired() {
			t.Error("Should not be expired")
		}
	})

	t.Run("IsExpired_Expired", func(t *testing.T) {
		info := &CSCAuthorizationInfo{
			SAD:       "test-sad",
			ExpiresAt: time.Now().Add(-time.Hour),
		}

		if !info.IsExpired() {
			t.Error("Should be expired")
		}
	})
}

func TestParseCSCAuthResponse(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		response := map[string]interface{}{
			"SAD":       "test-sad-value",
			"expiresIn": float64(7200),
		}

		info, err := ParseCSCAuthResponse(response)
		if err != nil {
			t.Fatalf("ParseCSCAuthResponse failed: %v", err)
		}

		if info.SAD != "test-sad-value" {
			t.Errorf("SAD = %q", info.SAD)
		}

		// Check expiry is roughly 2 hours from now
		expectedExpiry := time.Now().Add(2 * time.Hour)
		diff := info.ExpiresAt.Sub(expectedExpiry)
		if diff < -time.Minute || diff > time.Minute {
			t.Errorf("ExpiresAt off by too much: %v", diff)
		}
	})

	t.Run("MissingSAD", func(t *testing.T) {
		response := map[string]interface{}{
			"expiresIn": float64(3600),
		}

		_, err := ParseCSCAuthResponse(response)
		if err == nil {
			t.Error("Expected error for missing SAD")
		}
	})

	t.Run("DefaultExpiry", func(t *testing.T) {
		response := map[string]interface{}{
			"SAD": "test-sad",
		}

		info, err := ParseCSCAuthResponse(response)
		if err != nil {
			t.Fatalf("ParseCSCAuthResponse failed: %v", err)
		}

		// Default is 3600 seconds (1 hour)
		expectedExpiry := time.Now().Add(time.Hour)
		diff := info.ExpiresAt.Sub(expectedExpiry)
		if diff < -time.Minute || diff > time.Minute {
			t.Errorf("ExpiresAt off by too much: %v", diff)
		}
	})
}

func TestPrefetchedSADAuthorizationManager(t *testing.T) {
	cert, _ := generateTestCert()
	sessionInfo := NewCSCServiceSessionInfo("https://csc.example.com", "cred123")
	credInfo := &CSCCredentialInfo{SigningCert: cert}
	authInfo := &CSCAuthorizationInfo{
		SAD:       "prefetched-sad",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	t.Run("FirstCall", func(t *testing.T) {
		manager := NewPrefetchedSADAuthorizationManager(sessionInfo, credInfo, authInfo)

		result, err := manager.AuthorizeSignature(context.Background(), []string{"hash1"})
		if err != nil {
			t.Fatalf("AuthorizeSignature failed: %v", err)
		}

		if result.SAD != "prefetched-sad" {
			t.Errorf("SAD = %q", result.SAD)
		}
	})

	t.Run("SecondCallFails", func(t *testing.T) {
		manager := NewPrefetchedSADAuthorizationManager(sessionInfo, credInfo, authInfo)

		// First call
		_, _ = manager.AuthorizeSignature(context.Background(), []string{"hash1"})

		// Second call should fail
		_, err := manager.AuthorizeSignature(context.Background(), []string{"hash2"})
		if err != ErrCSCSADUsed {
			t.Errorf("Expected ErrCSCSADUsed, got %v", err)
		}
	})

	t.Run("ExpiredSAD", func(t *testing.T) {
		expiredAuth := &CSCAuthorizationInfo{
			SAD:       "expired-sad",
			ExpiresAt: time.Now().Add(-time.Hour),
		}
		manager := NewPrefetchedSADAuthorizationManager(sessionInfo, credInfo, expiredAuth)

		_, err := manager.AuthorizeSignature(context.Background(), []string{"hash1"})
		if err != ErrCSCSADExpired {
			t.Errorf("Expected ErrCSCSADExpired, got %v", err)
		}
	})
}

func TestBaseCSCAuthorizationManager(t *testing.T) {
	sessionInfo := NewCSCServiceSessionInfo("https://csc.example.com", "cred123").
		WithOAuthToken("token123")
	cert, _ := generateTestCert()
	credInfo := &CSCCredentialInfo{SigningCert: cert}

	manager := &BaseCSCAuthorizationManager{
		SessionInfo:    sessionInfo,
		CredentialInfo: credInfo,
	}

	t.Run("GetSessionInfo", func(t *testing.T) {
		if manager.GetSessionInfo() != sessionInfo {
			t.Error("GetSessionInfo mismatch")
		}
	})

	t.Run("GetCredentialInfo", func(t *testing.T) {
		if manager.GetCredentialInfo() != credInfo {
			t.Error("GetCredentialInfo mismatch")
		}
	})

	t.Run("GetAuthHeaders", func(t *testing.T) {
		headers := manager.GetAuthHeaders()
		if headers["Authorization"] != "Bearer token123" {
			t.Errorf("Authorization = %q", headers["Authorization"])
		}
	})

	t.Run("FormatCSCAuthRequest", func(t *testing.T) {
		req := manager.FormatCSCAuthRequest(1, "1234", "567890", nil, "test", "data")

		if req["credentialID"] != "cred123" {
			t.Errorf("credentialID = %v", req["credentialID"])
		}
		if req["numSignatures"] != 1 {
			t.Errorf("numSignatures = %v", req["numSignatures"])
		}
		if req["PIN"] != "1234" {
			t.Errorf("PIN = %v", req["PIN"])
		}
		if req["OTP"] != "567890" {
			t.Errorf("OTP = %v", req["OTP"])
		}
		if req["description"] != "test" {
			t.Errorf("description = %v", req["description"])
		}
		if req["clientData"] != "data" {
			t.Errorf("clientData = %v", req["clientData"])
		}
	})

	t.Run("FormatCSCAuthRequest_WithHashes", func(t *testing.T) {
		hashes := []string{"hash1", "hash2", "hash3"}
		req := manager.FormatCSCAuthRequest(1, "", "", hashes, "", "")

		if req["numSignatures"] != 3 {
			t.Errorf("numSignatures = %v, want 3", req["numSignatures"])
		}
		if h, ok := req["hash"].([]string); !ok || len(h) != 3 {
			t.Errorf("hash = %v", req["hash"])
		}
	})
}

func TestBase64Digest(t *testing.T) {
	data := []byte("test data")

	t.Run("SHA256", func(t *testing.T) {
		result := Base64Digest(data, "sha256")
		if result == "" {
			t.Error("Empty result")
		}
		// Should be valid base64
		_, err := base64.StdEncoding.DecodeString(result)
		if err != nil {
			t.Errorf("Invalid base64: %v", err)
		}
	})

	t.Run("SHA384", func(t *testing.T) {
		result := Base64Digest(data, "sha384")
		if result == "" {
			t.Error("Empty result")
		}
	})

	t.Run("SHA512", func(t *testing.T) {
		result := Base64Digest(data, "sha512")
		if result == "" {
			t.Error("Empty result")
		}
	})

	t.Run("Unknown_DefaultsSHA256", func(t *testing.T) {
		result := Base64Digest(data, "unknown")
		sha256Result := Base64Digest(data, "sha256")
		if result != sha256Result {
			t.Error("Unknown algorithm should default to SHA256")
		}
	})
}

func TestGetDigestAlgorithmOID(t *testing.T) {
	tests := []struct {
		algorithm string
		want      string
		wantErr   bool
	}{
		{"sha256", "2.16.840.1.101.3.4.2.1", false},
		{"sha384", "2.16.840.1.101.3.4.2.2", false},
		{"sha512", "2.16.840.1.101.3.4.2.3", false},
		{"sha1", "1.3.14.3.2.26", false},
		{"unknown", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			got, err := getDigestAlgorithmOID(tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getDigestAlgorithmOID(%q) = %q, want %q", tt.algorithm, got, tt.want)
			}
		})
	}
}

func TestGetHasher(t *testing.T) {
	tests := []struct {
		algorithm string
		want      int // hash size
	}{
		{"sha256", 32},
		{"sha384", 48},
		{"sha512", 64},
		{"sha1", 20},
		{"unknown", 32}, // defaults to SHA256
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			h := GetHasher(tt.algorithm)
			if h.Size() != tt.want {
				t.Errorf("hash size = %d, want %d", h.Size(), tt.want)
			}
		})
	}
}

func TestCSCSigner(t *testing.T) {
	cert, _ := generateTestCert()
	sessionInfo := NewCSCServiceSessionInfo("https://csc.example.com", "cred123")
	credInfo := &CSCCredentialInfo{
		SigningCert:         cert,
		Chain:               []*x509.Certificate{},
		SupportedMechanisms: []string{"1.2.840.113549.1.1.11"},
		MaxBatchSize:        10,
	}
	authInfo := &CSCAuthorizationInfo{
		SAD:       "test-sad",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	authManager := NewPrefetchedSADAuthorizationManager(sessionInfo, credInfo, authInfo)

	t.Run("NewCSCSigner", func(t *testing.T) {
		signer := NewCSCSigner(authManager, nil)

		if signer == nil {
			t.Fatal("Signer is nil")
		}
		if signer.BatchSize != 1 {
			t.Errorf("BatchSize = %d, want 1", signer.BatchSize)
		}
		if signer.SignTimeout != 300*time.Second {
			t.Errorf("SignTimeout = %v", signer.SignTimeout)
		}
	})

	t.Run("WithSignTimeout", func(t *testing.T) {
		signer := NewCSCSigner(authManager, nil).WithSignTimeout(60 * time.Second)
		if signer.SignTimeout != 60*time.Second {
			t.Errorf("SignTimeout = %v", signer.SignTimeout)
		}
	})

	t.Run("WithBatchSize", func(t *testing.T) {
		signer := NewCSCSigner(authManager, nil).WithBatchSize(5)
		if signer.BatchSize != 5 {
			t.Errorf("BatchSize = %d", signer.BatchSize)
		}
	})

	t.Run("WithClientData", func(t *testing.T) {
		signer := NewCSCSigner(authManager, nil).WithClientData("test-data")
		if signer.ClientData != "test-data" {
			t.Errorf("ClientData = %q", signer.ClientData)
		}
	})

	t.Run("WithPreferPSS", func(t *testing.T) {
		signer := NewCSCSigner(authManager, nil).WithPreferPSS(true)
		if !signer.PreferPSS {
			t.Error("PreferPSS should be true")
		}
	})

	t.Run("GetCertificate", func(t *testing.T) {
		signer := NewCSCSigner(authManager, nil)
		if signer.GetCertificate() != cert {
			t.Error("GetCertificate mismatch")
		}
	})

	t.Run("GetCertificateChain", func(t *testing.T) {
		signer := NewCSCSigner(authManager, nil)
		chain := signer.GetCertificateChain()
		if chain == nil {
			t.Error("GetCertificateChain returned nil")
		}
	})

	t.Run("GetSignatureSize", func(t *testing.T) {
		signer := NewCSCSigner(authManager, nil)
		size := signer.GetSignatureSize()
		if size < 8192 {
			t.Errorf("GetSignatureSize = %d, expected >= 8192", size)
		}
	})

	t.Run("SignRaw_DryRun", func(t *testing.T) {
		signer := NewCSCSigner(authManager, nil)
		signer.EstRawSignatureSize = 256

		result, err := signer.SignRaw(context.Background(), []byte("test"), "sha256", true)
		if err != nil {
			t.Fatalf("SignRaw dry run failed: %v", err)
		}
		if len(result) != 256 {
			t.Errorf("len(result) = %d, want 256", len(result))
		}
	})
}

func TestCSCSignerWithMockServer(t *testing.T) {
	cert, key := generateTestCert()

	// Create mock CSC server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/csc/v1/credentials/info":
			certB64 := base64.StdEncoding.EncodeToString(cert.Raw)
			response := map[string]interface{}{
				"cert": map[string]interface{}{
					"certificates": []string{certB64},
				},
				"key": map[string]interface{}{
					"algo": []string{"1.2.840.113549.1.1.11"},
				},
				"multisign": 10,
				"SCAL":      1,
			}
			json.NewEncoder(w).Encode(response)

		case "/csc/v1/credentials/authorize":
			response := map[string]interface{}{
				"SAD":       "test-sad-token",
				"expiresIn": 3600,
			}
			json.NewEncoder(w).Encode(response)

		case "/csc/v1/signatures/signHash":
			var req map[string]interface{}
			json.NewDecoder(r.Body).Decode(&req)

			hashes := req["hash"].([]interface{})
			signatures := make([]string, len(hashes))

			for i := range hashes {
				// Create a dummy signature using PKCS#1 v1.5
				hasher := GetHasher("sha256").New()
				hasher.Write([]byte("test"))
				digest := hasher.Sum(nil)
				realSig, _ := key.Sign(rand.Reader, digest, crypto.SHA256)
				signatures[i] = base64.StdEncoding.EncodeToString(realSig)
			}

			response := map[string]interface{}{
				"signatures": signatures,
			}
			json.NewEncoder(w).Encode(response)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	t.Run("FetchCertsInCSCCredential", func(t *testing.T) {
		sessionInfo := NewCSCServiceSessionInfo(server.URL, "cred123")

		credInfo, err := FetchCertsInCSCCredential(context.Background(), nil, sessionInfo)
		if err != nil {
			t.Fatalf("FetchCertsInCSCCredential failed: %v", err)
		}

		if credInfo.SigningCert == nil {
			t.Error("SigningCert is nil")
		}
		if credInfo.MaxBatchSize != 10 {
			t.Errorf("MaxBatchSize = %d, want 10", credInfo.MaxBatchSize)
		}
		if credInfo.HashPinningRequired {
			t.Error("HashPinningRequired should be false for SCAL=1")
		}
	})

	t.Run("CSCSignerBuilder", func(t *testing.T) {
		sessionInfo := NewCSCServiceSessionInfo(server.URL, "cred123")

		signer, err := NewCSCSignerBuilder(sessionInfo).
			WithBatchSize(5).
			WithSignTimeout(30 * time.Second).
			Build(context.Background())

		if err != nil {
			t.Fatalf("Build failed: %v", err)
		}

		if signer.BatchSize != 5 {
			t.Errorf("BatchSize = %d", signer.BatchSize)
		}
	})

	t.Run("OnDemandAuthorizationManager", func(t *testing.T) {
		sessionInfo := NewCSCServiceSessionInfo(server.URL, "cred123")

		credInfo, _ := FetchCertsInCSCCredential(context.Background(), nil, sessionInfo)

		manager := NewOnDemandAuthorizationManager(sessionInfo, credInfo, nil).
			WithPIN("1234").
			WithOTP("567890")

		authInfo, err := manager.AuthorizeSignature(context.Background(), []string{"hash1"})
		if err != nil {
			t.Fatalf("AuthorizeSignature failed: %v", err)
		}

		if authInfo.SAD != "test-sad-token" {
			t.Errorf("SAD = %q", authInfo.SAD)
		}
	})

	t.Run("FullSigningFlow", func(t *testing.T) {
		sessionInfo := NewCSCServiceSessionInfo(server.URL, "cred123")

		signer, err := NewCSCSignerBuilder(sessionInfo).
			WithPIN("1234").
			Build(context.Background())

		if err != nil {
			t.Fatalf("Build failed: %v", err)
		}

		// Sign some data
		data := []byte("test data to sign")
		signature, err := signer.SignRaw(context.Background(), data, "sha256", false)
		if err != nil {
			t.Fatalf("SignRaw failed: %v", err)
		}

		if len(signature) == 0 {
			t.Error("Empty signature")
		}
	})
}

func TestParseCredentialInfoResponse(t *testing.T) {
	cert, _ := generateTestCert()
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	t.Run("Valid", func(t *testing.T) {
		response := map[string]interface{}{
			"cert": map[string]interface{}{
				"certificates": []interface{}{certB64},
			},
			"key": map[string]interface{}{
				"algo": []interface{}{"1.2.840.113549.1.1.11", "1.2.840.10045.4.3.2"},
			},
			"multisign": float64(10),
			"SCAL":      float64(2),
		}

		info, err := ParseCredentialInfoResponse(response)
		if err != nil {
			t.Fatalf("ParseCredentialInfoResponse failed: %v", err)
		}

		if info.SigningCert == nil {
			t.Error("SigningCert is nil")
		}
		if len(info.SupportedMechanisms) != 2 {
			t.Errorf("len(SupportedMechanisms) = %d", len(info.SupportedMechanisms))
		}
		if info.MaxBatchSize != 10 {
			t.Errorf("MaxBatchSize = %d", info.MaxBatchSize)
		}
		if !info.HashPinningRequired {
			t.Error("HashPinningRequired should be true for SCAL=2")
		}
	})

	t.Run("MissingCert", func(t *testing.T) {
		response := map[string]interface{}{
			"key": map[string]interface{}{
				"algo": []interface{}{"1.2.840.113549.1.1.11"},
			},
		}

		_, err := ParseCredentialInfoResponse(response)
		if err == nil {
			t.Error("Expected error for missing cert")
		}
	})

	t.Run("EmptyCertificates", func(t *testing.T) {
		response := map[string]interface{}{
			"cert": map[string]interface{}{
				"certificates": []interface{}{},
			},
			"key": map[string]interface{}{
				"algo": []interface{}{"1.2.840.113549.1.1.11"},
			},
		}

		_, err := ParseCredentialInfoResponse(response)
		if err == nil {
			t.Error("Expected error for empty certificates")
		}
	})

	t.Run("InvalidCertBase64", func(t *testing.T) {
		response := map[string]interface{}{
			"cert": map[string]interface{}{
				"certificates": []interface{}{"not-valid-base64!!!"},
			},
			"key": map[string]interface{}{
				"algo": []interface{}{"1.2.840.113549.1.1.11"},
			},
		}

		_, err := ParseCredentialInfoResponse(response)
		if err == nil {
			t.Error("Expected error for invalid base64")
		}
	})
}

func TestCSCErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrCSCSigningFailed", ErrCSCSigningFailed},
		{"ErrCSCAuthFailed", ErrCSCAuthFailed},
		{"ErrCSCCredentialFailed", ErrCSCCredentialFailed},
		{"ErrCSCInvalidResponse", ErrCSCInvalidResponse},
		{"ErrCSCUnsupportedAlgo", ErrCSCUnsupportedAlgo},
		{"ErrCSCBatchMismatch", ErrCSCBatchMismatch},
		{"ErrCSCSADExpired", ErrCSCSADExpired},
		{"ErrCSCSADUsed", ErrCSCSADUsed},
		{"ErrCSCBatchSizeMismatch", ErrCSCBatchSizeMismatch},
		{"ErrCSCNoSignatureResults", ErrCSCNoSignatureResults},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() == "" {
				t.Errorf("%s should have a message", tt.name)
			}
		})
	}
}

func TestCSCSignerImplementsSigner(t *testing.T) {
	cert, _ := generateTestCert()
	sessionInfo := NewCSCServiceSessionInfo("https://csc.example.com", "cred123")
	credInfo := &CSCCredentialInfo{SigningCert: cert}
	authInfo := &CSCAuthorizationInfo{
		SAD:       "test-sad",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	authManager := NewPrefetchedSADAuthorizationManager(sessionInfo, credInfo, authInfo)

	var _ Signer = NewCSCSigner(authManager, nil)
}

func TestCMSSignerAdapter(t *testing.T) {
	cert, _ := generateTestCert()
	sessionInfo := NewCSCServiceSessionInfo("https://csc.example.com", "cred123")
	credInfo := &CSCCredentialInfo{SigningCert: cert}
	authInfo := &CSCAuthorizationInfo{
		SAD:       "test-sad",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	authManager := NewPrefetchedSADAuthorizationManager(sessionInfo, credInfo, authInfo)

	cscSigner := NewCSCSigner(authManager, nil)
	adapter := NewCMSSignerAdapter(cscSigner, "sha256")

	if adapter.GetCertificate() != cert {
		t.Error("GetCertificate mismatch")
	}
}
