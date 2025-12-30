// Package main demonstrates PDF signing using Cloud Signature Consortium (CSC) API.
// This example targets ETSI PAdES Baseline-B (B-B).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/georgepadayatti/gopdf/sign/fields"
	"github.com/georgepadayatti/gopdf/sign/signers"
)

// CSCConfig holds the configuration for CSC signing
// from the CSC API specification.
type CSCConfig struct {
	ServiceURL   string
	CredentialID string
	OAuthURL     string
	AuthorizeURL string
	ClientID     string
	ClientSecret string
	PIN          string
}

// LoadConfigFromEnv loads CSC configuration from environment variables
func LoadConfigFromEnv() (*CSCConfig, error) {
	config := &CSCConfig{
		ServiceURL:   os.Getenv("CSC_SERVICE_URL"),
		CredentialID: os.Getenv("CSC_CREDENTIAL_ID"),
		OAuthURL:     os.Getenv("CSC_OAUTH_URL"),
		AuthorizeURL: os.Getenv("CSC_AUTHORIZE_URL"),
		ClientID:     os.Getenv("CSC_CLIENT_ID"),
		ClientSecret: os.Getenv("CSC_CLIENT_SECRET"),
		PIN:          os.Getenv("CSC_PIN"),
	}

	var missing []string
	if config.ServiceURL == "" {
		missing = append(missing, "CSC_SERVICE_URL")
	}
	if config.CredentialID == "" {
		missing = append(missing, "CSC_CREDENTIAL_ID")
	}
	if config.OAuthURL == "" {
		missing = append(missing, "CSC_OAUTH_URL")
	}
	if config.ClientID == "" {
		missing = append(missing, "CSC_CLIENT_ID")
	}
	if config.ClientSecret == "" {
		missing = append(missing, "CSC_CLIENT_SECRET")
	}
	if config.PIN == "" {
		missing = append(missing, "CSC_PIN")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	return config, nil
}

// GetOAuthToken obtains an OAuth token from the CSC service using client credentials grant
func GetOAuthToken(ctx context.Context, config *CSCConfig) (string, error) {
	fmt.Println("Requesting OAuth token from CSC service...")

	// Prepare form data for client credentials grant
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", config.OAuthURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create OAuth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("OAuth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read OAuth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OAuth request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse OAuth response: %w", err)
	}

	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("no access_token in OAuth response")
	}

	fmt.Println("Successfully obtained OAuth token")
	return tokenResponse.AccessToken, nil
}

// AuthorizeCredential authorizes the CSC credential with PIN to obtain SAD
func AuthorizeCredential(ctx context.Context, config *CSCConfig, accessToken string) (string, error) {
	fmt.Printf("Authorizing CSC credential: %s\n", config.CredentialID)

	// Determine authorize URL
	authorizeURL := config.AuthorizeURL
	if authorizeURL == "" {
		// Default to standard CSC API endpoint
		authorizeURL = fmt.Sprintf("%s/csc/v1/credentials/authorize", config.ServiceURL)
	}

	// Prepare request body
	requestBody := map[string]any{
		"credentialID":  config.CredentialID,
		"numSignatures": 1,
		"PIN":           config.PIN,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal authorize request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", authorizeURL, bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create authorize request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("authorize request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read authorize response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authorize request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResponse struct {
		SAD       string `json:"SAD"`
		ExpiresIn int    `json:"expiresIn"`
	}

	if err := json.Unmarshal(body, &authResponse); err != nil {
		return "", fmt.Errorf("failed to parse authorize response: %w", err)
	}

	if authResponse.SAD == "" {
		return "", fmt.Errorf("no SAD in authorize response")
	}

	fmt.Println("Successfully authorized CSC credential")
	return authResponse.SAD, nil
}

// SignPDFWithCSC signs a PDF using CSC remote signing (PAdES B-B).
func SignPDFWithCSC(ctx context.Context, pdfData []byte, config *CSCConfig, accessToken, sad string) ([]byte, error) {
	fmt.Println("Setting up CSC signer...")

	// Create CSC session info
	sessionInfo := signers.NewCSCServiceSessionInfo(config.ServiceURL, config.CredentialID)
	sessionInfo.WithOAuthToken(accessToken)

	// Create HTTP client
	httpClient := &http.Client{Timeout: 300 * time.Second}

	// Fetch credential info (certificates)
	fmt.Println("Fetching certificates from CSC service...")
	credentialInfo, err := signers.FetchCertsInCSCCredential(ctx, httpClient, sessionInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credential info: %w", err)
	}

	fmt.Printf("Signing certificate: %s\n", credentialInfo.SigningCert.Subject.CommonName)
	fmt.Printf("Certificate chain: %d certificates\n", len(credentialInfo.Chain))

	// Create authorization info with prefetched SAD
	authInfo := &signers.CSCAuthorizationInfo{
		SAD:       sad,
		ExpiresAt: time.Now().Add(5 * time.Minute), // Assume 5 min validity
	}

	// Create prefetched SAD authorization manager
	authManager := signers.NewPrefetchedSADAuthorizationManager(
		sessionInfo,
		credentialInfo,
		authInfo,
	)

	// Create CSC signer
	signer := signers.NewCSCSigner(authManager, httpClient)
	cmsSigner := signers.NewCMSSignerAdapter(signer, "sha256")

	// Create signature metadata
	metadata := signers.NewSignatureMetadata("CSCSignature")
	metadata.Reason = "Document signed with CSC remote signing"
	metadata.Location = "Cloud"
	metadata.Name = credentialInfo.SigningCert.Subject.CommonName
	metadata.SubFilter = string(fields.SubFilterETSICAdESDetached)

	// Sign the PDF
	fmt.Println("Signing PDF...")
	signedData, err := signers.SignPdfBytes(pdfData, metadata, cmsSigner, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign PDF: %w", err)
	}

	fmt.Println("PDF successfully signed")
	return signedData, nil
}

// getTestdataDir finds the testdata directory
func getTestdataDir() string {
	// Try from current directory
	if _, err := os.Stat("testdata"); err == nil {
		return "testdata"
	}
	// Try from examples/csc_signing_bb directory
	if _, err := os.Stat("../../testdata"); err == nil {
		return "../../testdata"
	}
	// Try from examples directory
	if _, err := os.Stat("../testdata"); err == nil {
		return "../testdata"
	}
	return "testdata"
}

func main() {
	fmt.Println("CSC (Cloud Signature Consortium) PAdES B-B Signing Example")
	fmt.Println("==============================================================")
	fmt.Println()

	// Load configuration from environment
	config, err := LoadConfigFromEnv()
	if err != nil {
		fmt.Printf("Configuration error: %v\n", err)
		fmt.Println("Required environment variables:")
		fmt.Println("  CSC_SERVICE_URL    - Base URL of CSC service")
		fmt.Println("  CSC_CREDENTIAL_ID  - Credential ID for signing")
		fmt.Println("  CSC_OAUTH_URL      - OAuth token endpoint URL")
		fmt.Println("  CSC_CLIENT_ID      - OAuth client ID")
		fmt.Println("  CSC_CLIENT_SECRET  - OAuth client secret")
		fmt.Println("  CSC_PIN            - PIN for credential authorization")
		fmt.Println()
		fmt.Println("Optional environment variables:")
		fmt.Println("  CSC_AUTHORIZE_URL  - Custom authorize endpoint (defaults to CSC standard)")
		os.Exit(1)
	}

	// Get input PDF path
	var pdfPath string
	if len(os.Args) > 1 {
		pdfPath = os.Args[1]
	} else {
		testdataDir := getTestdataDir()
		pdfPath = filepath.Join(testdataDir, "terms.pdf")
	}

	// Get output PDF path
	var outputPath string
	if len(os.Args) > 2 {
		outputPath = os.Args[2]
	} else {
		outputPath = strings.TrimSuffix(pdfPath, filepath.Ext(pdfPath)) + "_csc_bb_signed.pdf"
	}

	fmt.Printf("CSC Service: %s\n", config.ServiceURL)
	fmt.Printf("Credential ID: %s\n", config.CredentialID)
	fmt.Println()

	// Read input PDF
	pdfData, err := os.ReadFile(pdfPath)
	if err != nil {
		fmt.Printf("Failed to read PDF: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Input PDF: %s (%d bytes)\n", pdfPath, len(pdfData))

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Get OAuth token
	accessToken, err := GetOAuthToken(ctx, config)
	if err != nil {
		fmt.Printf("Failed to obtain OAuth token: %v\n", err)
		os.Exit(1)
	}

	// Authorize credential
	sad, err := AuthorizeCredential(ctx, config, accessToken)
	if err != nil {
		fmt.Printf("Failed to authorize credential: %v\n", err)
		os.Exit(1)
	}

	// Sign PDF
	signedData, err := SignPDFWithCSC(ctx, pdfData, config, accessToken, sad)
	if err != nil {
		fmt.Printf("Failed to sign PDF: %v\n", err)
		os.Exit(1)
	}

	// Write output PDF
	if err := os.WriteFile(outputPath, signedData, 0o644); err != nil {
		fmt.Printf("Failed to write signed PDF: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSigned PDF saved: %s (%d bytes)\n", outputPath, len(signedData))
	fmt.Println("\nCSC PAdES B-B signing completed successfully!")
}
