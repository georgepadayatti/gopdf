package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewConfigError(t *testing.T) {
	err := NewConfigError("field", "message")
	if err.Field != "field" {
		t.Errorf("Expected field 'field', got '%s'", err.Field)
	}
	if err.Message != "message" {
		t.Errorf("Expected message 'message', got '%s'", err.Message)
	}

	expected := "config error in 'field': message"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestConfigErrorWithoutField(t *testing.T) {
	err := NewConfigError("", "general error")
	expected := "config error: general error"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestOIDRegex(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"1.2.3.4", true},
		{"1.2.840.113549.1.1.1", true},
		{"2.5.4.3", true},
		{"1.2", true},
		{"1", false},
		{"abc", false},
		{"1.2.abc", false},
		{"", false},
	}

	for _, tt := range tests {
		result := OIDRegex.MatchString(tt.input)
		if result != tt.expected {
			t.Errorf("OIDRegex.MatchString(%s) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestProcessOID(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		shouldError bool
	}{
		{"1.2.3.4", "1.2.3.4", false},
		{"sha256", "sha256", false},
		{"", "", true},
	}

	for _, tt := range tests {
		result, err := ProcessOID(tt.input)
		if tt.shouldError {
			if err == nil {
				t.Errorf("ProcessOID(%s) expected error", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("ProcessOID(%s) unexpected error: %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("ProcessOID(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		}
	}
}

func TestProcessOIDs(t *testing.T) {
	oids := []string{"1.2.3.4", "sha256"}
	result, err := ProcessOIDs(oids)
	if err != nil {
		t.Fatalf("ProcessOIDs failed: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("Expected 2 OIDs, got %d", len(result))
	}
}

func TestNormalizeKey(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"key_name", "key-name"},
		{"key-name", "key-name"},
		{"key_name_long", "key-name-long"},
		{"keyname", "keyname"},
	}

	for _, tt := range tests {
		result := normalizeKey(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeKey(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestCheckConfigKeys(t *testing.T) {
	expected := []string{"key-file", "cert-file", "passphrase"}

	// Valid keys
	err := CheckConfigKeys("TestConfig", expected, []string{"key-file", "cert-file"})
	if err != nil {
		t.Errorf("CheckConfigKeys should not error for valid keys: %v", err)
	}

	// Unexpected key
	err = CheckConfigKeys("TestConfig", expected, []string{"key-file", "unknown-key"})
	if err == nil {
		t.Error("CheckConfigKeys should error for unexpected keys")
	}

	// Works with underscores
	err = CheckConfigKeys("TestConfig", expected, []string{"key_file"})
	if err != nil {
		t.Errorf("CheckConfigKeys should accept underscores: %v", err)
	}
}

func TestPemDerSignatureConfigValidate(t *testing.T) {
	// Missing key file
	config := &PemDerSignatureConfig{CertFile: "cert.pem"}
	err := config.Validate()
	if err == nil {
		t.Error("Validate should error when key file is missing")
	}

	// Missing cert file
	config = &PemDerSignatureConfig{KeyFile: "key.pem"}
	err = config.Validate()
	if err == nil {
		t.Error("Validate should error when cert file is missing")
	}

	// Valid config
	config = &PemDerSignatureConfig{KeyFile: "key.pem", CertFile: "cert.pem"}
	err = config.Validate()
	if err != nil {
		t.Errorf("Validate should not error for valid config: %v", err)
	}
}

func TestPemDerSignatureConfigGetPassphraseBytes(t *testing.T) {
	config := &PemDerSignatureConfig{}
	if config.GetPassphraseBytes() != nil {
		t.Error("Empty passphrase should return nil")
	}

	config.KeyPassphrase = "secret"
	passphrase := config.GetPassphraseBytes()
	if string(passphrase) != "secret" {
		t.Errorf("Expected 'secret', got '%s'", string(passphrase))
	}
}

func TestPKCS12SignatureConfigValidate(t *testing.T) {
	config := &PKCS12SignatureConfig{}
	err := config.Validate()
	if err == nil {
		t.Error("Validate should error when PFX file is missing")
	}

	config.PFXFile = "file.p12"
	err = config.Validate()
	if err != nil {
		t.Errorf("Validate should not error for valid config: %v", err)
	}
}

func TestPKCS12SignatureConfigGetPassphraseBytes(t *testing.T) {
	config := &PKCS12SignatureConfig{}
	if config.GetPassphraseBytes() != nil {
		t.Error("Empty passphrase should return nil")
	}

	config.PFXPassphrase = "p12secret"
	passphrase := config.GetPassphraseBytes()
	if string(passphrase) != "p12secret" {
		t.Errorf("Expected 'p12secret', got '%s'", string(passphrase))
	}
}

func TestTimestampConfigValidate(t *testing.T) {
	config := &TimestampConfig{}
	err := config.Validate()
	if err == nil {
		t.Error("Validate should error when URL is missing")
	}

	config.URL = "http://timestamp.example.com"
	err = config.Validate()
	if err != nil {
		t.Errorf("Validate should not error for valid config: %v", err)
	}
}

func TestLoggingConfigSetDefaults(t *testing.T) {
	config := &LoggingConfig{}
	config.SetDefaults()

	if config.Level != "info" {
		t.Errorf("Expected level 'info', got '%s'", config.Level)
	}
	if config.Format != "text" {
		t.Errorf("Expected format 'text', got '%s'", config.Format)
	}
	if config.Output != "stderr" {
		t.Errorf("Expected output 'stderr', got '%s'", config.Output)
	}

	// Values should not be overwritten
	config2 := &LoggingConfig{Level: "debug", Format: "json", Output: "stdout"}
	config2.SetDefaults()
	if config2.Level != "debug" {
		t.Error("SetDefaults should not overwrite existing values")
	}
}

func TestParseConfig(t *testing.T) {
	yamlData := []byte(`
default-stamp: standard
stamps:
  standard:
    type: text
    text:
      font: Helvetica
      font-size: 12
key-sets:
  default:
    type: pemder
    pemder:
      key-file: key.pem
      cert-file: cert.pem
`)

	config, err := ParseConfig(yamlData)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	if config.DefaultStamp != "standard" {
		t.Errorf("Expected default-stamp 'standard', got '%s'", config.DefaultStamp)
	}

	if config.Stamps["standard"] == nil {
		t.Error("Expected stamps.standard to exist")
	}

	if config.KeySets["default"] == nil {
		t.Error("Expected key-sets.default to exist")
	}

	if config.KeySets["default"].Type != "pemder" {
		t.Errorf("Expected type 'pemder', got '%s'", config.KeySets["default"].Type)
	}
}

func TestLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	yamlData := []byte(`
validation:
  trust-anchors:
    - /path/to/ca.pem
  revocation-mode: soft-fail
`)

	if err := os.WriteFile(configFile, yamlData, 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.Validation == nil {
		t.Fatal("Expected validation config")
	}

	if len(config.Validation.TrustAnchors) != 1 {
		t.Errorf("Expected 1 trust anchor, got %d", len(config.Validation.TrustAnchors))
	}

	if config.Validation.RevocationMode != "soft-fail" {
		t.Errorf("Expected revocation-mode 'soft-fail', got '%s'", config.Validation.RevocationMode)
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("LoadConfig should error for non-existent file")
	}
}

func TestLoadAppConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "app.yaml")

	yamlData := []byte(`
logging:
  level: debug
  format: json
timestamp:
  url: http://timestamp.example.com
  timeout: 30
`)

	if err := os.WriteFile(configFile, yamlData, 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadAppConfig(configFile)
	if err != nil {
		t.Fatalf("LoadAppConfig failed: %v", err)
	}

	if config.Logging.Level != "debug" {
		t.Errorf("Expected level 'debug', got '%s'", config.Logging.Level)
	}

	if config.Timestamp == nil {
		t.Fatal("Expected timestamp config")
	}

	if config.Timestamp.URL != "http://timestamp.example.com" {
		t.Errorf("Expected URL 'http://timestamp.example.com', got '%s'", config.Timestamp.URL)
	}
}

func TestLoadAppConfigWithDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "minimal.yaml")

	yamlData := []byte(`{}`)
	if err := os.WriteFile(configFile, yamlData, 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadAppConfig(configFile)
	if err != nil {
		t.Fatalf("LoadAppConfig failed: %v", err)
	}

	if config.Logging == nil {
		t.Fatal("Logging should have default values")
	}
	if config.Logging.Level != "info" {
		t.Errorf("Expected default level 'info', got '%s'", config.Logging.Level)
	}
}

func TestLoadConfigFromMap(t *testing.T) {
	data := map[string]any{
		"default-stamp": "test",
		"stamps": map[string]any{
			"test": map[string]any{
				"type": "text",
			},
		},
	}

	config, err := LoadConfigFromMap(data)
	if err != nil {
		t.Fatalf("LoadConfigFromMap failed: %v", err)
	}

	if config.DefaultStamp != "test" {
		t.Errorf("Expected default-stamp 'test', got '%s'", config.DefaultStamp)
	}
}

func TestStampConfig(t *testing.T) {
	yamlData := []byte(`
stamps:
  withborder:
    type: text
    border:
      width: 2.0
      color: black
    text:
      font: Courier
      font-size: 10
      content: "Signed by {{signer}}"
  withqr:
    type: qrcode
    qr-code:
      content: "https://example.com/verify"
      size: 100
`)

	config, err := ParseConfig(yamlData)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	withBorder := config.Stamps["withborder"]
	if withBorder == nil {
		t.Fatal("Expected withborder stamp")
	}
	if withBorder.Border == nil {
		t.Fatal("Expected border config")
	}
	if withBorder.Border.Width != 2.0 {
		t.Errorf("Expected border width 2.0, got %f", withBorder.Border.Width)
	}
	if withBorder.Text == nil {
		t.Fatal("Expected text config")
	}
	if withBorder.Text.FontSize != 10 {
		t.Errorf("Expected font size 10, got %f", withBorder.Text.FontSize)
	}

	withQR := config.Stamps["withqr"]
	if withQR == nil {
		t.Fatal("Expected withqr stamp")
	}
	if withQR.QRCode == nil {
		t.Fatal("Expected qr-code config")
	}
	if withQR.QRCode.Size != 100 {
		t.Errorf("Expected QR size 100, got %f", withQR.QRCode.Size)
	}
}

func TestValidationConfig(t *testing.T) {
	yamlData := []byte(`
validation:
  trust-anchors:
    - /path/to/ca1.pem
    - /path/to/ca2.pem
  other-certs:
    - /path/to/intermediate.pem
  signer:
    key-usage:
      - digital-signature
      - non-repudiation
    ext-key-usage:
      - code-signing
`)

	config, err := ParseConfig(yamlData)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	if config.Validation == nil {
		t.Fatal("Expected validation config")
	}

	if len(config.Validation.TrustAnchors) != 2 {
		t.Errorf("Expected 2 trust anchors, got %d", len(config.Validation.TrustAnchors))
	}

	if len(config.Validation.OtherCerts) != 1 {
		t.Errorf("Expected 1 other cert, got %d", len(config.Validation.OtherCerts))
	}

	if config.Validation.Signer == nil {
		t.Fatal("Expected signer validation config")
	}

	if len(config.Validation.Signer.KeyUsage) != 2 {
		t.Errorf("Expected 2 key usages, got %d", len(config.Validation.Signer.KeyUsage))
	}
}

func TestKeySetConfig(t *testing.T) {
	yamlData := []byte(`
key-sets:
  pemder-set:
    type: pemder
    pemder:
      key-file: /path/to/key.pem
      cert-file: /path/to/cert.pem
      other-certs:
        - /path/to/intermediate.pem
      key-passphrase: secret
      prefer-pss: true
  pkcs12-set:
    type: pkcs12
    pkcs12:
      pfx-file: /path/to/bundle.p12
      pfx-passphrase: p12secret
      prompt-passphrase: false
`)

	config, err := ParseConfig(yamlData)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	pemderSet := config.KeySets["pemder-set"]
	if pemderSet == nil {
		t.Fatal("Expected pemder-set")
	}
	if pemderSet.Type != "pemder" {
		t.Errorf("Expected type 'pemder', got '%s'", pemderSet.Type)
	}
	if pemderSet.PemDer == nil {
		t.Fatal("Expected PemDer config")
	}
	if pemderSet.PemDer.KeyFile != "/path/to/key.pem" {
		t.Errorf("Expected key-file '/path/to/key.pem', got '%s'", pemderSet.PemDer.KeyFile)
	}
	if !pemderSet.PemDer.PreferPSS {
		t.Error("Expected prefer-pss to be true")
	}

	pkcs12Set := config.KeySets["pkcs12-set"]
	if pkcs12Set == nil {
		t.Fatal("Expected pkcs12-set")
	}
	if pkcs12Set.Type != "pkcs12" {
		t.Errorf("Expected type 'pkcs12', got '%s'", pkcs12Set.Type)
	}
	if pkcs12Set.PKCS12 == nil {
		t.Fatal("Expected PKCS12 config")
	}
	if pkcs12Set.PKCS12.PFXFile != "/path/to/bundle.p12" {
		t.Errorf("Expected pfx-file '/path/to/bundle.p12', got '%s'", pkcs12Set.PKCS12.PFXFile)
	}
}

func TestParseConfigInvalid(t *testing.T) {
	yamlData := []byte(`
invalid yaml: [
`)

	_, err := ParseConfig(yamlData)
	if err == nil {
		t.Error("ParseConfig should error for invalid YAML")
	}
}

func TestEnsureStrings(t *testing.T) {
	tests := []struct {
		name        string
		input       any
		expected    []string
		shouldError bool
	}{
		{
			name:     "single string",
			input:    "value",
			expected: []string{"value"},
		},
		{
			name:     "string slice",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "interface slice with strings",
			input:    []any{"x", "y"},
			expected: []string{"x", "y"},
		},
		{
			name:        "interface slice with non-string",
			input:       []any{"x", 123},
			shouldError: true,
		},
		{
			name:        "invalid type",
			input:       123,
			shouldError: true,
		},
		{
			name:        "nil value",
			input:       nil,
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EnsureStrings(tt.input, "test-param")
			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(result) != len(tt.expected) {
					t.Errorf("Length mismatch: got %d, want %d", len(result), len(tt.expected))
				}
				for i, v := range result {
					if v != tt.expected[i] {
						t.Errorf("Value mismatch at %d: got %s, want %s", i, v, tt.expected[i])
					}
				}
			}
		})
	}
}

func TestProcessBitStringFlags(t *testing.T) {
	testFlags := map[string]bool{
		"flag-one":   true,
		"flag-two":   true,
		"flag-three": true,
	}

	tests := []struct {
		name        string
		input       any
		expected    []string
		shouldError bool
	}{
		{
			name:     "single valid flag",
			input:    "flag-one",
			expected: []string{"flag-one"},
		},
		{
			name:     "multiple valid flags",
			input:    []string{"flag-one", "flag-two"},
			expected: []string{"flag-one", "flag-two"},
		},
		{
			name:        "invalid flag",
			input:       "invalid-flag",
			shouldError: true,
		},
		{
			name:        "empty flag",
			input:       "",
			shouldError: true,
		},
		{
			name:        "mixed valid and invalid",
			input:       []string{"flag-one", "invalid"},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ProcessBitStringFlags(testFlags, tt.input, "test-param", "TestFlag")
			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(result) != len(tt.expected) {
					t.Errorf("Length mismatch: got %d, want %d", len(result), len(tt.expected))
				}
				for i, v := range result {
					if v != tt.expected[i] {
						t.Errorf("Value mismatch at %d: got %s, want %s", i, v, tt.expected[i])
					}
				}
			}
		})
	}
}

func TestProcessKeyUsageFlags(t *testing.T) {
	tests := []struct {
		name        string
		input       any
		expected    []string
		shouldError bool
	}{
		{
			name:     "kebab-case flag",
			input:    "digital-signature",
			expected: []string{"digital-signature"},
		},
		{
			name:     "camelCase flag",
			input:    "digitalSignature",
			expected: []string{"digitalSignature"},
		},
		{
			name:     "multiple flags",
			input:    []string{"digital-signature", "key-encipherment", "crl-sign"},
			expected: []string{"digital-signature", "key-encipherment", "crl-sign"},
		},
		{
			name:        "invalid flag",
			input:       "not-a-real-flag",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ProcessKeyUsageFlags(tt.input, "key-usage")
			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(result) != len(tt.expected) {
					t.Errorf("Length mismatch: got %d, want %d", len(result), len(tt.expected))
				}
			}
		})
	}
}

func TestProcessExtKeyUsageFlags(t *testing.T) {
	tests := []struct {
		name        string
		input       any
		expected    []string
		shouldError bool
	}{
		{
			name:     "kebab-case flag",
			input:    "server-auth",
			expected: []string{"server-auth"},
		},
		{
			name:     "camelCase flag",
			input:    "codeSigning",
			expected: []string{"codeSigning"},
		},
		{
			name:     "multiple flags",
			input:    []string{"server-auth", "client-auth", "time-stamping"},
			expected: []string{"server-auth", "client-auth", "time-stamping"},
		},
		{
			name:        "invalid flag",
			input:       "not-a-real-eku",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ProcessExtKeyUsageFlags(tt.input, "ext-key-usage")
			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(result) != len(tt.expected) {
					t.Errorf("Length mismatch: got %d, want %d", len(result), len(tt.expected))
				}
			}
		})
	}
}

func TestNormalizeKeyUsageFlag(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"digitalSignature", "digital-signature"},
		{"keyEncipherment", "key-encipherment"},
		{"cRLSign", "crl-sign"},
		{"digital-signature", "digital-signature"}, // Already normalized
		{"unknown-flag", "unknown-flag"},           // Unknown flags pass through
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeKeyUsageFlag(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeKeyUsageFlag(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeExtKeyUsageFlag(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"serverAuth", "server-auth"},
		{"codeSigning", "code-signing"},
		{"timeStamping", "time-stamping"},
		{"server-auth", "server-auth"}, // Already normalized
		{"unknown-eku", "unknown-eku"}, // Unknown flags pass through
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeExtKeyUsageFlag(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeExtKeyUsageFlag(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestKeyUsageFlagsCompleteness(t *testing.T) {
	// Ensure all standard KeyUsage flags are present
	requiredFlags := []string{
		"digital-signature", "digitalSignature",
		"content-commitment", "contentCommitment",
		"key-encipherment", "keyEncipherment",
		"data-encipherment", "dataEncipherment",
		"key-agreement", "keyAgreement",
		"key-cert-sign", "keyCertSign",
		"crl-sign", "cRLSign",
		"encipher-only", "encipherOnly",
		"decipher-only", "decipherOnly",
	}

	for _, flag := range requiredFlags {
		if !KeyUsageFlags[flag] {
			t.Errorf("KeyUsageFlags missing required flag: %s", flag)
		}
	}
}

func TestExtKeyUsageFlagsCompleteness(t *testing.T) {
	// Ensure common ExtKeyUsage flags are present
	requiredFlags := []string{
		"any",
		"server-auth", "serverAuth",
		"client-auth", "clientAuth",
		"code-signing", "codeSigning",
		"email-protection", "emailProtection",
		"time-stamping", "timeStamping",
		"ocsp-signing", "OCSPSigning",
	}

	for _, flag := range requiredFlags {
		if !ExtKeyUsageFlags[flag] {
			t.Errorf("ExtKeyUsageFlags missing required flag: %s", flag)
		}
	}
}
