package config

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/georgepadayatti/gopdf/keys"
	"gopkg.in/yaml.v3"
)

// Common errors
var (
	ErrConfigurationError   = errors.New("configuration error")
	ErrMissingRequiredField = errors.New("missing required field")
	ErrUnexpectedField      = errors.New("unexpected field in configuration")
	ErrInvalidOID           = errors.New("invalid OID")
	ErrInvalidConfigType    = errors.New("configuration must be a dictionary")
)

// OIDRegex matches OID strings like "1.2.3.4"
var OIDRegex = regexp.MustCompile(`^\d+(\.\d+)+$`)

// ConfigError represents a configuration error with context.
type ConfigError struct {
	Field   string
	Message string
	Err     error
}

func (e *ConfigError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("config error in '%s': %s", e.Field, e.Message)
	}
	return fmt.Sprintf("config error: %s", e.Message)
}

func (e *ConfigError) Unwrap() error {
	return e.Err
}

// NewConfigError creates a new ConfigError.
func NewConfigError(field, message string) *ConfigError {
	return &ConfigError{Field: field, Message: message}
}

// PKCS12SignatureConfig contains configuration for signing using a PKCS#12 file.
type PKCS12SignatureConfig struct {
	// PFXFile is the path to the PKCS#12 file.
	PFXFile string `yaml:"pfx-file" json:"pfx_file"`

	// OtherCertsFiles are paths to other certificate files.
	OtherCertsFiles []string `yaml:"other-certs" json:"other_certs,omitempty"`

	// PFXPassphrase is the PKCS#12 passphrase.
	PFXPassphrase string `yaml:"pfx-passphrase" json:"pfx_passphrase,omitempty"`

	// PromptPassphrase indicates whether to prompt for passphrase.
	PromptPassphrase bool `yaml:"prompt-passphrase" json:"prompt_passphrase"`

	// PreferPSS indicates whether to prefer PSS padding for RSA signatures.
	PreferPSS bool `yaml:"prefer-pss" json:"prefer_pss"`

	// OtherCerts contains the loaded certificates (after processing).
	OtherCerts []*x509.Certificate `yaml:"-" json:"-"`
}

// Validate validates the PKCS12 signature configuration.
func (c *PKCS12SignatureConfig) Validate() error {
	if c.PFXFile == "" {
		return NewConfigError("pfx-file", "required field is missing")
	}
	return nil
}

// LoadOtherCerts loads the additional certificates from the configured files.
func (c *PKCS12SignatureConfig) LoadOtherCerts() error {
	if len(c.OtherCertsFiles) == 0 {
		return nil
	}
	certs, err := keys.LoadCertsFromPemDerFiles(c.OtherCertsFiles)
	if err != nil {
		return fmt.Errorf("failed to load other certs: %w", err)
	}
	c.OtherCerts = certs
	return nil
}

// GetPassphraseBytes returns the passphrase as bytes.
func (c *PKCS12SignatureConfig) GetPassphraseBytes() []byte {
	if c.PFXPassphrase == "" {
		return nil
	}
	return []byte(c.PFXPassphrase)
}

// PemDerSignatureConfig contains configuration for signing using PEM/DER files.
type PemDerSignatureConfig struct {
	// KeyFile is the path to the private key file.
	KeyFile string `yaml:"key-file" json:"key_file"`

	// CertFile is the path to the certificate file.
	CertFile string `yaml:"cert-file" json:"cert_file"`

	// OtherCertsFiles are paths to other certificate files.
	OtherCertsFiles []string `yaml:"other-certs" json:"other_certs,omitempty"`

	// KeyPassphrase is the private key passphrase.
	KeyPassphrase string `yaml:"key-passphrase" json:"key_passphrase,omitempty"`

	// PromptPassphrase indicates whether to prompt for passphrase.
	PromptPassphrase bool `yaml:"prompt-passphrase" json:"prompt_passphrase"`

	// PreferPSS indicates whether to prefer PSS padding for RSA signatures.
	PreferPSS bool `yaml:"prefer-pss" json:"prefer_pss"`

	// Certificate is the loaded certificate (after processing).
	Certificate *x509.Certificate `yaml:"-" json:"-"`

	// PrivateKey is the loaded private key (after processing).
	PrivateKey keys.PrivateKey `yaml:"-" json:"-"`

	// OtherCerts contains the loaded certificates (after processing).
	OtherCerts []*x509.Certificate `yaml:"-" json:"-"`
}

// Validate validates the PEM/DER signature configuration.
func (c *PemDerSignatureConfig) Validate() error {
	if c.KeyFile == "" {
		return NewConfigError("key-file", "required field is missing")
	}
	if c.CertFile == "" {
		return NewConfigError("cert-file", "required field is missing")
	}
	return nil
}

// Load loads the certificate and key from the configured files.
func (c *PemDerSignatureConfig) Load() error {
	if err := c.Validate(); err != nil {
		return err
	}

	cert, key, err := keys.LoadCertAndKeyFromPemDer(
		c.CertFile,
		c.KeyFile,
		c.GetPassphraseBytes(),
	)
	if err != nil {
		return fmt.Errorf("failed to load cert and key: %w", err)
	}
	c.Certificate = cert
	c.PrivateKey = key

	if len(c.OtherCertsFiles) > 0 {
		certs, err := keys.LoadCertsFromPemDerFiles(c.OtherCertsFiles)
		if err != nil {
			return fmt.Errorf("failed to load other certs: %w", err)
		}
		c.OtherCerts = certs
	}

	return nil
}

// GetPassphraseBytes returns the passphrase as bytes.
func (c *PemDerSignatureConfig) GetPassphraseBytes() []byte {
	if c.KeyPassphrase == "" {
		return nil
	}
	return []byte(c.KeyPassphrase)
}

// SigningConfig represents the top-level signing configuration.
type SigningConfig struct {
	// DefaultStamp is the default stamp style.
	DefaultStamp string `yaml:"default-stamp" json:"default_stamp,omitempty"`

	// Stamps contains named stamp configurations.
	Stamps map[string]*StampConfig `yaml:"stamps" json:"stamps,omitempty"`

	// KeySets contains named signing credential configurations.
	KeySets map[string]*KeySetConfig `yaml:"key-sets" json:"key_sets,omitempty"`

	// Validation contains validation configuration.
	Validation *ValidationConfig `yaml:"validation" json:"validation,omitempty"`
}

// KeySetConfig contains configuration for a set of signing credentials.
type KeySetConfig struct {
	// Type is the type of key set ("pemder" or "pkcs12").
	Type string `yaml:"type" json:"type"`

	// PemDer contains PEM/DER configuration (if type is "pemder").
	PemDer *PemDerSignatureConfig `yaml:"pemder" json:"pemder,omitempty"`

	// PKCS12 contains PKCS#12 configuration (if type is "pkcs12").
	PKCS12 *PKCS12SignatureConfig `yaml:"pkcs12" json:"pkcs12,omitempty"`
}

// StampConfig contains configuration for a signature stamp.
type StampConfig struct {
	// Type is the stamp type.
	Type string `yaml:"type" json:"type"`

	// Background is the background appearance.
	Background string `yaml:"background" json:"background,omitempty"`

	// Border is the border configuration.
	Border *BorderConfig `yaml:"border" json:"border,omitempty"`

	// Text contains text configuration.
	Text *TextStampConfig `yaml:"text" json:"text,omitempty"`

	// QRCode contains QR code configuration.
	QRCode *QRCodeConfig `yaml:"qr-code" json:"qr_code,omitempty"`
}

// BorderConfig contains configuration for stamp border.
type BorderConfig struct {
	// Width is the border width in points.
	Width float64 `yaml:"width" json:"width"`

	// Color is the border color.
	Color string `yaml:"color" json:"color,omitempty"`
}

// TextStampConfig contains configuration for text stamps.
type TextStampConfig struct {
	// Font is the font name.
	Font string `yaml:"font" json:"font,omitempty"`

	// FontSize is the font size in points.
	FontSize float64 `yaml:"font-size" json:"font_size,omitempty"`

	// Content is the text content template.
	Content string `yaml:"content" json:"content,omitempty"`
}

// QRCodeConfig contains configuration for QR code stamps.
type QRCodeConfig struct {
	// Content is the QR code content.
	Content string `yaml:"content" json:"content,omitempty"`

	// Size is the QR code size.
	Size float64 `yaml:"size" json:"size,omitempty"`
}

// ValidationConfig contains validation configuration.
type ValidationConfig struct {
	// TrustAnchors contains paths to trust anchor certificate files.
	TrustAnchors []string `yaml:"trust-anchors" json:"trust_anchors,omitempty"`

	// OtherCerts contains paths to other certificate files.
	OtherCerts []string `yaml:"other-certs" json:"other_certs,omitempty"`

	// RevocationMode is the revocation checking mode.
	RevocationMode string `yaml:"revocation-mode" json:"revocation_mode,omitempty"`

	// Signer contains signer-specific validation settings.
	Signer *SignerValidationConfig `yaml:"signer" json:"signer,omitempty"`
}

// SignerValidationConfig contains signer validation settings.
type SignerValidationConfig struct {
	// KeyUsage specifies required key usage.
	KeyUsage []string `yaml:"key-usage" json:"key_usage,omitempty"`

	// ExtKeyUsage specifies required extended key usage.
	ExtKeyUsage []string `yaml:"ext-key-usage" json:"ext_key_usage,omitempty"`
}

// LoadConfig loads a configuration from a YAML file.
func LoadConfig(filename string) (*SigningConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	return ParseConfig(data)
}

// ParseConfig parses configuration from YAML data.
func ParseConfig(data []byte) (*SigningConfig, error) {
	var config SigningConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return &config, nil
}

// LoadConfigFromMap loads configuration from a map.
func LoadConfigFromMap(data map[string]any) (*SigningConfig, error) {
	// Marshal to YAML then unmarshal to struct
	yamlData, err := yaml.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config map: %w", err)
	}
	return ParseConfig(yamlData)
}

// CheckConfigKeys checks if all provided keys are valid for a given configuration type.
func CheckConfigKeys(configName string, expectedKeys, suppliedKeys []string) error {
	expectedSet := make(map[string]bool)
	for _, k := range expectedKeys {
		// Normalize to use dashes
		expectedSet[normalizeKey(k)] = true
	}

	var unexpected []string
	for _, k := range suppliedKeys {
		normalized := normalizeKey(k)
		if !expectedSet[normalized] {
			unexpected = append(unexpected, k)
		}
	}

	if len(unexpected) > 0 {
		keyWord := "key"
		if len(unexpected) > 1 {
			keyWord = "keys"
		}
		return fmt.Errorf("%w: unexpected %s in configuration for %s: %s",
			ErrUnexpectedField, keyWord, configName, strings.Join(unexpected, ", "))
	}

	return nil
}

// normalizeKey normalizes a configuration key (underscores to dashes).
func normalizeKey(key string) string {
	return strings.ReplaceAll(key, "_", "-")
}

// ProcessOID validates and normalizes an OID string.
func ProcessOID(oidString string) (string, error) {
	if oidString == "" {
		return "", NewConfigError("oid", "OID string is empty")
	}

	// Check if it's a numeric OID
	if OIDRegex.MatchString(oidString) {
		return oidString, nil
	}

	// Otherwise assume it's a named OID (e.g., "sha256", "digitalSignature")
	// In a full implementation, we would map these to actual OIDs
	return oidString, nil
}

// ProcessOIDs validates and normalizes a list of OID strings.
func ProcessOIDs(oidStrings []string) ([]string, error) {
	result := make([]string, 0, len(oidStrings))
	for _, oid := range oidStrings {
		processed, err := ProcessOID(oid)
		if err != nil {
			return nil, err
		}
		result = append(result, processed)
	}
	return result, nil
}

// Common X.509 KeyUsage flag names (matching crypto/x509 KeyUsage constants)
var KeyUsageFlags = map[string]bool{
	"digital-signature":  true,
	"digitalSignature":   true,
	"content-commitment": true,
	"contentCommitment":  true,
	"non-repudiation":    true, // Alias for content-commitment
	"nonRepudiation":     true,
	"key-encipherment":   true,
	"keyEncipherment":    true,
	"data-encipherment":  true,
	"dataEncipherment":   true,
	"key-agreement":      true,
	"keyAgreement":       true,
	"key-cert-sign":      true,
	"keyCertSign":        true,
	"crl-sign":           true,
	"cRLSign":            true,
	"encipher-only":      true,
	"encipherOnly":       true,
	"decipher-only":      true,
	"decipherOnly":       true,
}

// Common X.509 ExtKeyUsage flag names
var ExtKeyUsageFlags = map[string]bool{
	"any":                            true,
	"server-auth":                    true,
	"serverAuth":                     true,
	"client-auth":                    true,
	"clientAuth":                     true,
	"code-signing":                   true,
	"codeSigning":                    true,
	"email-protection":               true,
	"emailProtection":                true,
	"ipsec-end-system":               true,
	"ipsecEndSystem":                 true,
	"ipsec-tunnel":                   true,
	"ipsecTunnel":                    true,
	"ipsec-user":                     true,
	"ipsecUser":                      true,
	"time-stamping":                  true,
	"timeStamping":                   true,
	"ocsp-signing":                   true,
	"OCSPSigning":                    true,
	"microsoft-server-gated-crypto": true,
	"netscape-server-gated-crypto":  true,
	"microsoft-commercial-code-signing": true,
	"microsoft-kernel-code-signing":     true,
}

// EnsureStrings ensures the input is a slice of strings.
// It accepts either a single string or a slice of strings.
// This is a helper for processing configuration values that can be
// specified as either a single value or a list.
func EnsureStrings(value any, paramName string) ([]string, error) {
	switch v := value.(type) {
	case string:
		return []string{v}, nil
	case []string:
		return v, nil
	case []any:
		result := make([]string, 0, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, NewConfigError(paramName,
					fmt.Sprintf("item %d is not a string (got %T)", i, item))
			}
			result = append(result, s)
		}
		return result, nil
	default:
		return nil, NewConfigError(paramName,
			fmt.Sprintf("must be specified as a list of strings or a string, got %T", value))
	}
}

// ProcessBitStringFlags validates a list of flag strings against a set of valid flag names.
// This is used for processing configuration values like KeyUsage or ExtKeyUsage flags.
//
// Parameters:
//   - validFlags: a map of valid flag names (the map values are ignored, only keys matter)
//   - strings: the flag strings to validate (can be a single string or slice)
//   - paramName: the parameter name for error messages
//   - flagTypeName: the type name for error messages (e.g., "KeyUsage", "ExtKeyUsage")
//
// Returns the validated flag strings or an error if any flag is invalid.
func ProcessBitStringFlags(validFlags map[string]bool, input any, paramName, flagTypeName string) ([]string, error) {
	strings, err := EnsureStrings(input, paramName)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(strings))
	for _, flagString := range strings {
		if flagString == "" {
			return nil, NewConfigError(paramName, "flag identifier cannot be empty")
		}

		if !validFlags[flagString] {
			// Build list of valid values for error message
			validNames := make([]string, 0, len(validFlags))
			for name := range validFlags {
				validNames = append(validNames, name)
			}
			return nil, NewConfigError(paramName,
				fmt.Sprintf("'%s' is not a valid %s flag name", flagString, flagTypeName))
		}

		result = append(result, flagString)
	}

	return result, nil
}

// ProcessKeyUsageFlags validates and processes KeyUsage flag strings.
// Accepts common KeyUsage names like "digital-signature", "digitalSignature",
// "key-encipherment", "keyEncipherment", etc.
func ProcessKeyUsageFlags(input any, paramName string) ([]string, error) {
	return ProcessBitStringFlags(KeyUsageFlags, input, paramName, "KeyUsage")
}

// ProcessExtKeyUsageFlags validates and processes ExtKeyUsage flag strings.
// Accepts common ExtKeyUsage names like "server-auth", "serverAuth",
// "code-signing", "codeSigning", etc.
func ProcessExtKeyUsageFlags(input any, paramName string) ([]string, error) {
	return ProcessBitStringFlags(ExtKeyUsageFlags, input, paramName, "ExtKeyUsage")
}

// NormalizeKeyUsageFlag normalizes a KeyUsage flag name to its canonical form.
// Converts camelCase to kebab-case for consistency.
func NormalizeKeyUsageFlag(flag string) string {
	// Map common variations to canonical kebab-case form
	normalizations := map[string]string{
		"digitalSignature":   "digital-signature",
		"contentCommitment":  "content-commitment",
		"nonRepudiation":     "non-repudiation",
		"keyEncipherment":    "key-encipherment",
		"dataEncipherment":   "data-encipherment",
		"keyAgreement":       "key-agreement",
		"keyCertSign":        "key-cert-sign",
		"cRLSign":            "crl-sign",
		"encipherOnly":       "encipher-only",
		"decipherOnly":       "decipher-only",
	}
	if normalized, ok := normalizations[flag]; ok {
		return normalized
	}
	return flag
}

// NormalizeExtKeyUsageFlag normalizes an ExtKeyUsage flag name to its canonical form.
func NormalizeExtKeyUsageFlag(flag string) string {
	normalizations := map[string]string{
		"serverAuth":       "server-auth",
		"clientAuth":       "client-auth",
		"codeSigning":      "code-signing",
		"emailProtection":  "email-protection",
		"ipsecEndSystem":   "ipsec-end-system",
		"ipsecTunnel":      "ipsec-tunnel",
		"ipsecUser":        "ipsec-user",
		"timeStamping":     "time-stamping",
		"OCSPSigning":      "ocsp-signing",
	}
	if normalized, ok := normalizations[flag]; ok {
		return normalized
	}
	return flag
}

// TimestampConfig contains timestamp service configuration.
type TimestampConfig struct {
	// URL is the timestamp service URL.
	URL string `yaml:"url" json:"url"`

	// Username for HTTP authentication.
	Username string `yaml:"username" json:"username,omitempty"`

	// Password for HTTP authentication.
	Password string `yaml:"password" json:"password,omitempty"`

	// Timeout is the request timeout in seconds.
	Timeout int `yaml:"timeout" json:"timeout,omitempty"`
}

// Validate validates the timestamp configuration.
func (c *TimestampConfig) Validate() error {
	if c.URL == "" {
		return NewConfigError("url", "timestamp URL is required")
	}
	return nil
}

// LoggingConfig contains logging configuration.
type LoggingConfig struct {
	// Level is the log level (debug, info, warn, error).
	Level string `yaml:"level" json:"level,omitempty"`

	// Format is the log format (text, json).
	Format string `yaml:"format" json:"format,omitempty"`

	// Output is the log output (stdout, stderr, or file path).
	Output string `yaml:"output" json:"output,omitempty"`
}

// SetDefaults sets default values for logging configuration.
func (c *LoggingConfig) SetDefaults() {
	if c.Level == "" {
		c.Level = "info"
	}
	if c.Format == "" {
		c.Format = "text"
	}
	if c.Output == "" {
		c.Output = "stderr"
	}
}

// AppConfig contains the complete application configuration.
type AppConfig struct {
	// Signing contains signing configuration.
	Signing *SigningConfig `yaml:"signing" json:"signing,omitempty"`

	// Logging contains logging configuration.
	Logging *LoggingConfig `yaml:"logging" json:"logging,omitempty"`

	// Timestamp contains default timestamp configuration.
	Timestamp *TimestampConfig `yaml:"timestamp" json:"timestamp,omitempty"`
}

// LoadAppConfig loads the complete application configuration from a file.
func LoadAppConfig(filename string) (*AppConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config AppConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	if config.Logging == nil {
		config.Logging = &LoggingConfig{}
	}
	config.Logging.SetDefaults()

	return &config, nil
}
