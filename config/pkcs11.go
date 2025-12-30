// Package config provides PKCS#11 configuration for signing operations.
package config

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/georgepadayatti/gopdf/keys"
)

// PKCS11PinEntryMode defines PIN entry behavior.
type PKCS11PinEntryMode int

const (
	// PKCS11PinPrompt indicates the user should be prompted for PIN.
	PKCS11PinPrompt PKCS11PinEntryMode = iota
	// PKCS11PinDefer lets the PKCS#11 module handle authentication (e.g., physical PIN pad).
	PKCS11PinDefer
	// PKCS11PinSkip skips the login process (for devices with external auth).
	PKCS11PinSkip
)

// String returns the string representation of the PIN entry mode.
func (m PKCS11PinEntryMode) String() string {
	switch m {
	case PKCS11PinPrompt:
		return "PROMPT"
	case PKCS11PinDefer:
		return "DEFER"
	case PKCS11PinSkip:
		return "SKIP"
	default:
		return "UNKNOWN"
	}
}

// ParsePKCS11PinEntryMode parses a string into a PKCS11PinEntryMode.
func ParsePKCS11PinEntryMode(s string) (PKCS11PinEntryMode, error) {
	switch s {
	case "PROMPT", "prompt":
		return PKCS11PinPrompt, nil
	case "DEFER", "defer":
		return PKCS11PinDefer, nil
	case "SKIP", "skip":
		return PKCS11PinSkip, nil
	default:
		return PKCS11PinPrompt, fmt.Errorf("invalid PIN entry mode: %s (must be PROMPT, DEFER, or SKIP)", s)
	}
}

// TokenCriteria defines search criteria for finding a PKCS#11 token.
type TokenCriteria struct {
	// Label is the token label to match. If empty, no label constraint is applied.
	Label string `yaml:"label" json:"label,omitempty"`

	// Serial is the token serial number (as bytes). If nil, no serial constraint is applied.
	Serial []byte `yaml:"serial" json:"serial,omitempty"`
}

// NewTokenCriteria creates a new TokenCriteria with the given label.
func NewTokenCriteria(label string) *TokenCriteria {
	return &TokenCriteria{Label: label}
}

// NewTokenCriteriaWithSerial creates a new TokenCriteria with label and serial.
func NewTokenCriteriaWithSerial(label string, serial []byte) *TokenCriteria {
	return &TokenCriteria{Label: label, Serial: serial}
}

// IsEmpty returns true if no criteria are specified.
func (c *TokenCriteria) IsEmpty() bool {
	return c == nil || (c.Label == "" && len(c.Serial) == 0)
}

// String returns a string representation of the criteria.
func (c *TokenCriteria) String() string {
	if c == nil {
		return "<no criteria>"
	}
	parts := []string{}
	if c.Label != "" {
		parts = append(parts, fmt.Sprintf("label=%q", c.Label))
	}
	if len(c.Serial) > 0 {
		parts = append(parts, fmt.Sprintf("serial=%s", hex.EncodeToString(c.Serial)))
	}
	if len(parts) == 0 {
		return "<no criteria>"
	}
	return fmt.Sprintf("TokenCriteria{%s}", joinStrings(parts, ", "))
}

// PKCS11SignatureConfig contains configuration for PKCS#11 signing.
type PKCS11SignatureConfig struct {
	// ModulePath is the path to the PKCS#11 module shared object (.so/.dylib/.dll).
	ModulePath string `yaml:"module-path" json:"module_path"`

	// SlotNo is the slot number to use. If nil, the first matching slot is used.
	SlotNo *int `yaml:"slot-no" json:"slot_no,omitempty"`

	// TokenCriteria specifies criteria for finding the token.
	TokenCriteria *TokenCriteria `yaml:"token-criteria" json:"token_criteria,omitempty"`

	// CertLabel is the PKCS#11 label of the signer's certificate.
	CertLabel string `yaml:"cert-label" json:"cert_label,omitempty"`

	// CertID is the PKCS#11 ID of the signer's certificate (as hex string in config, bytes internally).
	CertID []byte `yaml:"cert-id" json:"cert_id,omitempty"`

	// KeyLabel is the PKCS#11 label of the private key.
	// Defaults to CertLabel if not specified and KeyID is also not specified.
	KeyLabel string `yaml:"key-label" json:"key_label,omitempty"`

	// KeyID is the PKCS#11 ID of the private key (as hex string in config, bytes internally).
	KeyID []byte `yaml:"key-id" json:"key_id,omitempty"`

	// UserPIN is the user PIN for authentication.
	// If empty and PromptPIN is PROMPT, the user will be prompted.
	UserPIN string `yaml:"user-pin" json:"user_pin,omitempty"`

	// PromptPIN specifies PIN entry behavior.
	PromptPIN PKCS11PinEntryMode `yaml:"prompt-pin" json:"prompt_pin"`

	// SigningCertificatePath is an optional path to load the signing certificate from file
	// instead of from the token.
	SigningCertificatePath string `yaml:"signing-certificate" json:"signing_certificate,omitempty"`

	// SigningCertificate is the loaded signing certificate (if loaded from file).
	SigningCertificate *x509.Certificate `yaml:"-" json:"-"`

	// OtherCertsFiles are paths to other certificate files to include.
	OtherCertsFiles []string `yaml:"other-certs" json:"other_certs,omitempty"`

	// OtherCerts contains the loaded additional certificates.
	OtherCerts []*x509.Certificate `yaml:"-" json:"-"`

	// OtherCertsToPull is a list of certificate labels to pull from the token.
	// If nil, all certificates are pulled. If empty slice, no certificates are pulled.
	OtherCertsToPull []string `yaml:"other-certs-to-pull" json:"other_certs_to_pull,omitempty"`

	// BulkFetch indicates whether to fetch all certs at once and filter (true)
	// or fetch requested certs one by one (false).
	BulkFetch bool `yaml:"bulk-fetch" json:"bulk_fetch"`

	// PreferPSS indicates whether to prefer RSASSA-PSS over PKCS#1 v1.5.
	PreferPSS bool `yaml:"prefer-pss" json:"prefer_pss"`

	// RawMechanism indicates whether to use the raw signing mechanism.
	// When true, data is hashed before passing to the token (useful for tokens
	// that don't support hash-then-sign).
	RawMechanism bool `yaml:"raw-mechanism" json:"raw_mechanism"`

	// OnlyResidentCerts limits certificate searches to physically stored certificates.
	OnlyResidentCerts bool `yaml:"only-resident-certs" json:"only_resident_certs"`

	// SignatureMechanism allows specifying the signature mechanism explicitly.
	// Format is ASN.1 OID string (e.g., "1.2.840.113549.1.1.11" for SHA256WithRSA).
	SignatureMechanism string `yaml:"signature-mechanism" json:"signature_mechanism,omitempty"`
}

// Validate validates the PKCS#11 configuration.
func (c *PKCS11SignatureConfig) Validate() error {
	if c.ModulePath == "" {
		return NewConfigError("module-path", "PKCS#11 module path is required")
	}

	// At least one of key_id, key_label, cert_label, or cert_id must be provided
	hasKeyIdentifier := c.KeyID != nil || c.KeyLabel != ""
	hasCertIdentifier := c.CertID != nil || c.CertLabel != ""

	if !hasKeyIdentifier && !hasCertIdentifier {
		return NewConfigError("", "at least one of key-id, key-label, cert-label, or cert-id must be provided")
	}

	return nil
}

// ProcessConfig processes the raw configuration values.
// This should be called after loading from YAML/JSON to resolve defaults.
func (c *PKCS11SignatureConfig) ProcessConfig() error {
	// Default key identifiers from cert identifiers if not set
	if c.KeyLabel == "" && c.KeyID == nil {
		if c.CertID != nil {
			c.KeyID = c.CertID
		}
		if c.CertLabel != "" {
			c.KeyLabel = c.CertLabel
		}
	}

	// Default cert identifiers from key identifiers if not set
	if c.CertLabel == "" && c.CertID == nil && c.SigningCertificatePath == "" {
		if c.KeyID != nil {
			c.CertID = c.KeyID
		}
		if c.KeyLabel != "" {
			c.CertLabel = c.KeyLabel
		}
	}

	// Load signing certificate from file if specified
	if c.SigningCertificatePath != "" {
		cert, err := keys.LoadCertFromPemDer(c.SigningCertificatePath)
		if err != nil {
			return fmt.Errorf("failed to load signing certificate: %w", err)
		}
		c.SigningCertificate = cert
	}

	// Load other certificates from files if specified
	if len(c.OtherCertsFiles) > 0 {
		certs, err := keys.LoadCertsFromPemDerFiles(c.OtherCertsFiles)
		if err != nil {
			return fmt.Errorf("failed to load other certificates: %w", err)
		}
		c.OtherCerts = certs
	}

	return nil
}

// GetKeyLabel returns the effective key label.
func (c *PKCS11SignatureConfig) GetKeyLabel() string {
	if c.KeyLabel != "" {
		return c.KeyLabel
	}
	if c.KeyID == nil && c.CertLabel != "" {
		return c.CertLabel
	}
	return ""
}

// GetKeyID returns the effective key ID.
func (c *PKCS11SignatureConfig) GetKeyID() []byte {
	if c.KeyID != nil {
		return c.KeyID
	}
	if c.KeyLabel == "" && c.CertID != nil {
		return c.CertID
	}
	return nil
}

// GetCertLabel returns the effective cert label.
func (c *PKCS11SignatureConfig) GetCertLabel() string {
	if c.CertLabel != "" {
		return c.CertLabel
	}
	if c.CertID == nil && c.KeyLabel != "" {
		return c.KeyLabel
	}
	return ""
}

// GetCertID returns the effective cert ID.
func (c *PKCS11SignatureConfig) GetCertID() []byte {
	if c.CertID != nil {
		return c.CertID
	}
	if c.CertLabel == "" && c.KeyID != nil {
		return c.KeyID
	}
	return nil
}

// ProcessPKCS11ID converts a PKCS#11 ID value from string (hex) or int to bytes.
func ProcessPKCS11ID(value interface{}) ([]byte, error) {
	switch v := value.(type) {
	case int:
		return []byte{byte(v)}, nil
	case int64:
		return []byte{byte(v)}, nil
	case string:
		return hex.DecodeString(v)
	case []byte:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported PKCS#11 ID type: %T", value)
	}
}

// Helper function to join strings
func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += sep + parts[i]
	}
	return result
}
