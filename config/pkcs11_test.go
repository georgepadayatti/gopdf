package config

import (
	"encoding/hex"
	"testing"
)

func TestPKCS11PinEntryModeString(t *testing.T) {
	tests := []struct {
		mode     PKCS11PinEntryMode
		expected string
	}{
		{PKCS11PinPrompt, "PROMPT"},
		{PKCS11PinDefer, "DEFER"},
		{PKCS11PinSkip, "SKIP"},
		{PKCS11PinEntryMode(99), "UNKNOWN"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if got := tc.mode.String(); got != tc.expected {
				t.Errorf("String() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestParsePKCS11PinEntryMode(t *testing.T) {
	tests := []struct {
		input    string
		expected PKCS11PinEntryMode
		wantErr  bool
	}{
		{"PROMPT", PKCS11PinPrompt, false},
		{"prompt", PKCS11PinPrompt, false},
		{"DEFER", PKCS11PinDefer, false},
		{"defer", PKCS11PinDefer, false},
		{"SKIP", PKCS11PinSkip, false},
		{"skip", PKCS11PinSkip, false},
		{"invalid", PKCS11PinPrompt, true},
		{"", PKCS11PinPrompt, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParsePKCS11PinEntryMode(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if got != tc.expected {
					t.Errorf("ParsePKCS11PinEntryMode(%q) = %v, want %v", tc.input, got, tc.expected)
				}
			}
		})
	}
}

func TestTokenCriteria(t *testing.T) {
	t.Run("NewTokenCriteria", func(t *testing.T) {
		tc := NewTokenCriteria("MyToken")
		if tc.Label != "MyToken" {
			t.Errorf("Label = %q, want %q", tc.Label, "MyToken")
		}
		if tc.Serial != nil {
			t.Error("Serial should be nil")
		}
	})

	t.Run("NewTokenCriteriaWithSerial", func(t *testing.T) {
		serial := []byte{0x01, 0x02, 0x03}
		tc := NewTokenCriteriaWithSerial("MyToken", serial)
		if tc.Label != "MyToken" {
			t.Errorf("Label = %q, want %q", tc.Label, "MyToken")
		}
		if string(tc.Serial) != string(serial) {
			t.Errorf("Serial = %v, want %v", tc.Serial, serial)
		}
	})

	t.Run("IsEmpty", func(t *testing.T) {
		tests := []struct {
			name     string
			criteria *TokenCriteria
			expected bool
		}{
			{"nil", nil, true},
			{"empty", &TokenCriteria{}, true},
			{"with label", &TokenCriteria{Label: "token"}, false},
			{"with serial", &TokenCriteria{Serial: []byte{0x01}}, false},
			{"with both", &TokenCriteria{Label: "token", Serial: []byte{0x01}}, false},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if got := tc.criteria.IsEmpty(); got != tc.expected {
					t.Errorf("IsEmpty() = %v, want %v", got, tc.expected)
				}
			})
		}
	})

	t.Run("String", func(t *testing.T) {
		tests := []struct {
			name     string
			criteria *TokenCriteria
			contains string
		}{
			{"nil", nil, "<no criteria>"},
			{"empty", &TokenCriteria{}, "<no criteria>"},
			{"with label", &TokenCriteria{Label: "MyToken"}, "label=\"MyToken\""},
			{"with serial", &TokenCriteria{Serial: []byte{0x01, 0x02}}, "serial=0102"},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got := tc.criteria.String()
				if !contains(got, tc.contains) {
					t.Errorf("String() = %q, should contain %q", got, tc.contains)
				}
			})
		}
	})
}

func TestPKCS11SignatureConfig(t *testing.T) {
	t.Run("Validate_MissingModulePath", func(t *testing.T) {
		cfg := &PKCS11SignatureConfig{}
		err := cfg.Validate()
		if err == nil {
			t.Error("expected error for missing module path")
		}
	})

	t.Run("Validate_MissingIdentifiers", func(t *testing.T) {
		cfg := &PKCS11SignatureConfig{
			ModulePath: "/path/to/module.so",
		}
		err := cfg.Validate()
		if err == nil {
			t.Error("expected error for missing identifiers")
		}
	})

	t.Run("Validate_WithCertLabel", func(t *testing.T) {
		cfg := &PKCS11SignatureConfig{
			ModulePath: "/path/to/module.so",
			CertLabel:  "MyCert",
		}
		err := cfg.Validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Validate_WithKeyID", func(t *testing.T) {
		cfg := &PKCS11SignatureConfig{
			ModulePath: "/path/to/module.so",
			KeyID:      []byte{0x01},
		}
		err := cfg.Validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("GetKeyLabel", func(t *testing.T) {
		tests := []struct {
			name     string
			cfg      *PKCS11SignatureConfig
			expected string
		}{
			{
				"direct key label",
				&PKCS11SignatureConfig{KeyLabel: "MyKey"},
				"MyKey",
			},
			{
				"from cert label",
				&PKCS11SignatureConfig{CertLabel: "MyCert"},
				"MyCert",
			},
			{
				"key label takes precedence",
				&PKCS11SignatureConfig{KeyLabel: "MyKey", CertLabel: "MyCert"},
				"MyKey",
			},
			{
				"empty when key id set",
				&PKCS11SignatureConfig{KeyID: []byte{0x01}},
				"",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if got := tc.cfg.GetKeyLabel(); got != tc.expected {
					t.Errorf("GetKeyLabel() = %q, want %q", got, tc.expected)
				}
			})
		}
	})

	t.Run("GetKeyID", func(t *testing.T) {
		keyID := []byte{0x01, 0x02}
		certID := []byte{0x03, 0x04}

		tests := []struct {
			name     string
			cfg      *PKCS11SignatureConfig
			expected []byte
		}{
			{
				"direct key id",
				&PKCS11SignatureConfig{KeyID: keyID},
				keyID,
			},
			{
				"from cert id",
				&PKCS11SignatureConfig{CertID: certID},
				certID,
			},
			{
				"key id takes precedence",
				&PKCS11SignatureConfig{KeyID: keyID, CertID: certID},
				keyID,
			},
			{
				"nil when label set",
				&PKCS11SignatureConfig{KeyLabel: "MyKey"},
				nil,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got := tc.cfg.GetKeyID()
				if !bytesEqual(got, tc.expected) {
					t.Errorf("GetKeyID() = %v, want %v", got, tc.expected)
				}
			})
		}
	})

	t.Run("GetCertLabel", func(t *testing.T) {
		tests := []struct {
			name     string
			cfg      *PKCS11SignatureConfig
			expected string
		}{
			{
				"direct cert label",
				&PKCS11SignatureConfig{CertLabel: "MyCert"},
				"MyCert",
			},
			{
				"from key label",
				&PKCS11SignatureConfig{KeyLabel: "MyKey"},
				"MyKey",
			},
			{
				"cert label takes precedence",
				&PKCS11SignatureConfig{CertLabel: "MyCert", KeyLabel: "MyKey"},
				"MyCert",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if got := tc.cfg.GetCertLabel(); got != tc.expected {
					t.Errorf("GetCertLabel() = %q, want %q", got, tc.expected)
				}
			})
		}
	})

	t.Run("GetCertID", func(t *testing.T) {
		keyID := []byte{0x01, 0x02}
		certID := []byte{0x03, 0x04}

		tests := []struct {
			name     string
			cfg      *PKCS11SignatureConfig
			expected []byte
		}{
			{
				"direct cert id",
				&PKCS11SignatureConfig{CertID: certID},
				certID,
			},
			{
				"from key id",
				&PKCS11SignatureConfig{KeyID: keyID},
				keyID,
			},
			{
				"cert id takes precedence",
				&PKCS11SignatureConfig{CertID: certID, KeyID: keyID},
				certID,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got := tc.cfg.GetCertID()
				if !bytesEqual(got, tc.expected) {
					t.Errorf("GetCertID() = %v, want %v", got, tc.expected)
				}
			})
		}
	})
}

func TestProcessPKCS11ID(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected []byte
		wantErr  bool
	}{
		{
			"int",
			42,
			[]byte{42},
			false,
		},
		{
			"int64",
			int64(255),
			[]byte{255},
			false,
		},
		{
			"hex string",
			"0102030405",
			[]byte{0x01, 0x02, 0x03, 0x04, 0x05},
			false,
		},
		{
			"bytes",
			[]byte{0x01, 0x02},
			[]byte{0x01, 0x02},
			false,
		},
		{
			"invalid hex",
			"gg",
			nil,
			true,
		},
		{
			"unsupported type",
			float64(1.5),
			nil,
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ProcessPKCS11ID(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if !bytesEqual(got, tc.expected) {
					t.Errorf("ProcessPKCS11ID(%v) = %v, want %v", tc.input, got, tc.expected)
				}
			}
		})
	}
}

func TestPKCS11SignatureConfigProcessConfig(t *testing.T) {
	t.Run("DefaultsFromCertToKey", func(t *testing.T) {
		cfg := &PKCS11SignatureConfig{
			ModulePath: "/path/to/module.so",
			CertLabel:  "MyCert",
			CertID:     []byte{0x01},
		}
		err := cfg.ProcessConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.KeyLabel != "MyCert" {
			t.Errorf("KeyLabel should default to CertLabel, got %q", cfg.KeyLabel)
		}
		if !bytesEqual(cfg.KeyID, []byte{0x01}) {
			t.Errorf("KeyID should default to CertID, got %v", cfg.KeyID)
		}
	})

	t.Run("DefaultsFromKeyToCert", func(t *testing.T) {
		cfg := &PKCS11SignatureConfig{
			ModulePath: "/path/to/module.so",
			KeyLabel:   "MyKey",
			KeyID:      []byte{0x02},
		}
		err := cfg.ProcessConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.CertLabel != "MyKey" {
			t.Errorf("CertLabel should default to KeyLabel, got %q", cfg.CertLabel)
		}
		if !bytesEqual(cfg.CertID, []byte{0x02}) {
			t.Errorf("CertID should default to KeyID, got %v", cfg.CertID)
		}
	})
}

// Helper to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Helper to compare byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Test joinStrings helper
func TestJoinStrings(t *testing.T) {
	tests := []struct {
		parts    []string
		sep      string
		expected string
	}{
		{nil, ", ", ""},
		{[]string{}, ", ", ""},
		{[]string{"a"}, ", ", "a"},
		{[]string{"a", "b"}, ", ", "a, b"},
		{[]string{"a", "b", "c"}, "-", "a-b-c"},
	}

	for _, tc := range tests {
		got := joinStrings(tc.parts, tc.sep)
		if got != tc.expected {
			t.Errorf("joinStrings(%v, %q) = %q, want %q", tc.parts, tc.sep, got, tc.expected)
		}
	}
}

// Test hex encoding in TokenCriteria.String
func TestTokenCriteriaStringHex(t *testing.T) {
	serial := []byte{0xAB, 0xCD, 0xEF}
	tc := &TokenCriteria{Serial: serial}
	str := tc.String()

	expectedHex := hex.EncodeToString(serial)
	if !contains(str, expectedHex) {
		t.Errorf("String() = %q, should contain hex %q", str, expectedHex)
	}
}
