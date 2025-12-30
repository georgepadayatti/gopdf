package xml

import (
	"testing"
)

func TestLangValue(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		tests := []struct {
			name     string
			lang     LangValue
			expected string
		}{
			{"empty", LangValueEmpty, ""},
			{"english", LangValue("en"), "en"},
			{"german", LangValue("de"), "de"},
			{"custom", LangValue("en-US"), "en-US"},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if got := tc.lang.String(); got != tc.expected {
					t.Errorf("String() = %q, want %q", got, tc.expected)
				}
			})
		}
	})

	t.Run("IsValid", func(t *testing.T) {
		tests := []struct {
			name     string
			lang     LangValue
			expected bool
		}{
			{"empty", LangValueEmpty, false},
			{"english", LangValue("en"), true},
			{"space only", LangValue(" "), true}, // technically valid as non-empty
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if got := tc.lang.IsValid(); got != tc.expected {
					t.Errorf("IsValid() = %v, want %v", got, tc.expected)
				}
			})
		}
	})
}

func TestNamespace(t *testing.T) {
	expected := "http://www.w3.org/XML/1998/namespace"
	if Namespace != expected {
		t.Errorf("Namespace = %q, want %q", Namespace, expected)
	}
}
