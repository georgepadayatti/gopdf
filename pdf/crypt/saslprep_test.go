package crypt

import (
	"testing"
)

func TestSASLprep(t *testing.T) {
	t.Run("SimpleASCII", func(t *testing.T) {
		result, err := SASLprep("password", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "password" {
			t.Errorf("Expected 'password', got %q", result)
		}
	})

	t.Run("EmptyString", func(t *testing.T) {
		_, err := SASLprep("", false)
		if err != ErrSASLprepEmpty {
			t.Errorf("Expected ErrSASLprepEmpty, got %v", err)
		}
	})

	t.Run("ASCIIWithNumbers", func(t *testing.T) {
		result, err := SASLprep("abc123", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "abc123" {
			t.Errorf("Expected 'abc123', got %q", result)
		}
	})

	t.Run("MixedCase", func(t *testing.T) {
		result, err := SASLprep("AbCdEf", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "AbCdEf" {
			t.Errorf("Expected 'AbCdEf', got %q", result)
		}
	})

	t.Run("WithSpecialChars", func(t *testing.T) {
		result, err := SASLprep("pass!@#$%", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "pass!@#$%" {
			t.Errorf("Expected 'pass!@#$%%', got %q", result)
		}
	})

	t.Run("WithSpace", func(t *testing.T) {
		result, err := SASLprep("pass word", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "pass word" {
			t.Errorf("Expected 'pass word', got %q", result)
		}
	})

	t.Run("UnicodeLetters", func(t *testing.T) {
		// Test with some common Unicode letters
		result, err := SASLprep("café", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "café" {
			t.Errorf("Expected 'café', got %q", result)
		}
	})
}

func TestSASLprepMapping(t *testing.T) {
	t.Run("TableB1_SoftHyphen", func(t *testing.T) {
		// SOFT HYPHEN (U+00AD) should be mapped to nothing
		result, err := SASLprep("pass\u00ADword", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "password" {
			t.Errorf("Expected 'password', got %q", result)
		}
	})

	t.Run("TableB1_ZeroWidthSpace", func(t *testing.T) {
		// ZERO WIDTH SPACE (U+200B) should be mapped to nothing
		result, err := SASLprep("pass\u200Bword", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "password" {
			t.Errorf("Expected 'password', got %q", result)
		}
	})

	t.Run("TableB1_ZeroWidthJoiner", func(t *testing.T) {
		// ZERO WIDTH JOINER (U+200D) should be mapped to nothing
		result, err := SASLprep("pass\u200Dword", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "password" {
			t.Errorf("Expected 'password', got %q", result)
		}
	})

	t.Run("TableB1_CombiningGraphemeJoiner", func(t *testing.T) {
		// COMBINING GRAPHEME JOINER (U+034F) should be mapped to nothing
		result, err := SASLprep("pass\u034Fword", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "password" {
			t.Errorf("Expected 'password', got %q", result)
		}
	})

	t.Run("TableB1_WordJoiner", func(t *testing.T) {
		// WORD JOINER (U+2060) should be mapped to nothing
		result, err := SASLprep("pass\u2060word", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "password" {
			t.Errorf("Expected 'password', got %q", result)
		}
	})

	t.Run("TableC12_NoBreakSpace", func(t *testing.T) {
		// NO-BREAK SPACE (U+00A0) should be mapped to SPACE
		result, err := SASLprep("pass\u00A0word", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "pass word" {
			t.Errorf("Expected 'pass word', got %q", result)
		}
	})

	t.Run("TableC12_EnSpace", func(t *testing.T) {
		// EN SPACE (U+2002) should be mapped to SPACE
		result, err := SASLprep("pass\u2002word", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "pass word" {
			t.Errorf("Expected 'pass word', got %q", result)
		}
	})

	t.Run("TableC12_EmSpace", func(t *testing.T) {
		// EM SPACE (U+2003) should be mapped to SPACE
		result, err := SASLprep("pass\u2003word", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "pass word" {
			t.Errorf("Expected 'pass word', got %q", result)
		}
	})

	t.Run("TableC12_IdeographicSpace", func(t *testing.T) {
		// IDEOGRAPHIC SPACE (U+3000) should be mapped to SPACE
		result, err := SASLprep("pass\u3000word", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "pass word" {
			t.Errorf("Expected 'pass word', got %q", result)
		}
	})
}

func TestSASLprepProhibited(t *testing.T) {
	t.Run("TableC21_ASCIIControl", func(t *testing.T) {
		// NULL (U+0000) is prohibited
		_, err := SASLprep("pass\x00word", false)
		if err != ErrSASLprepProhibited {
			t.Errorf("Expected ErrSASLprepProhibited for NULL, got %v", err)
		}
	})

	t.Run("TableC21_Tab", func(t *testing.T) {
		// TAB (U+0009) is prohibited
		_, err := SASLprep("pass\tword", false)
		if err != ErrSASLprepProhibited {
			t.Errorf("Expected ErrSASLprepProhibited for TAB, got %v", err)
		}
	})

	t.Run("TableC21_Newline", func(t *testing.T) {
		// LINE FEED (U+000A) is prohibited
		_, err := SASLprep("pass\nword", false)
		if err != ErrSASLprepProhibited {
			t.Errorf("Expected ErrSASLprepProhibited for LF, got %v", err)
		}
	})

	t.Run("TableC21_Delete", func(t *testing.T) {
		// DELETE (U+007F) is prohibited
		_, err := SASLprep("pass\x7Fword", false)
		if err != ErrSASLprepProhibited {
			t.Errorf("Expected ErrSASLprepProhibited for DEL, got %v", err)
		}
	})

	t.Run("TableC22_C1Control", func(t *testing.T) {
		// C1 control characters (U+0080-U+009F) are prohibited
		_, err := SASLprep("pass\x80word", false)
		if err != ErrSASLprepProhibited {
			t.Errorf("Expected ErrSASLprepProhibited for C1 control, got %v", err)
		}
	})

	t.Run("TableC3_PrivateUse", func(t *testing.T) {
		// Private use characters (U+E000-U+F8FF) are prohibited
		_, err := SASLprep("pass\uE000word", false)
		if err != ErrSASLprepProhibited {
			t.Errorf("Expected ErrSASLprepProhibited for private use, got %v", err)
		}
	})

	t.Run("TableC4_NonCharacter", func(t *testing.T) {
		// Non-character (U+FFFE, U+FFFF) are prohibited
		_, err := SASLprep("pass\uFFFEword", false)
		if err != ErrSASLprepProhibited {
			t.Errorf("Expected ErrSASLprepProhibited for non-character, got %v", err)
		}
	})

	t.Run("TableC6_ReplacementChar", func(t *testing.T) {
		// REPLACEMENT CHARACTER (U+FFFD) is prohibited
		_, err := SASLprep("pass\uFFFDword", false)
		if err != ErrSASLprepProhibited {
			t.Errorf("Expected ErrSASLprepProhibited for replacement char, got %v", err)
		}
	})

	t.Run("TableC7_IdeographicDescriptor", func(t *testing.T) {
		// IDEOGRAPHIC DESCRIPTION CHARACTERS (U+2FF0-U+2FFB) are prohibited
		_, err := SASLprep("pass\u2FF0word", false)
		if err != ErrSASLprepProhibited {
			t.Errorf("Expected ErrSASLprepProhibited for ideographic descriptor, got %v", err)
		}
	})

	t.Run("TableC8_DeprecatedBidi", func(t *testing.T) {
		// LEFT-TO-RIGHT MARK (U+200E) is prohibited
		_, err := SASLprep("pass\u200Eword", false)
		if err != ErrSASLprepProhibited {
			t.Errorf("Expected ErrSASLprepProhibited for LTR mark, got %v", err)
		}
	})

	t.Run("TableC8_RightToLeftMark", func(t *testing.T) {
		// RIGHT-TO-LEFT MARK (U+200F) is prohibited
		_, err := SASLprep("pass\u200Fword", false)
		if err != ErrSASLprepProhibited {
			t.Errorf("Expected ErrSASLprepProhibited for RTL mark, got %v", err)
		}
	})

	t.Run("TableC9_TaggingChar", func(t *testing.T) {
		// LANGUAGE TAG (U+E0001) is prohibited
		_, err := SASLprep("pass\U000E0001word", false)
		if err != ErrSASLprepProhibited {
			t.Errorf("Expected ErrSASLprepProhibited for tagging char, got %v", err)
		}
	})
}

func TestSASLprepBidirectional(t *testing.T) {
	t.Run("PureRTL_Hebrew", func(t *testing.T) {
		// Pure Hebrew string should pass
		result, err := SASLprep("\u05D0\u05D1\u05D2", false)
		if err != nil {
			t.Fatalf("SASLprep failed for Hebrew: %v", err)
		}
		if result != "\u05D0\u05D1\u05D2" {
			t.Errorf("Hebrew string changed unexpectedly")
		}
	})

	t.Run("PureRTL_Arabic", func(t *testing.T) {
		// Pure Arabic string should pass
		result, err := SASLprep("\u0627\u0628\u062A", false)
		if err != nil {
			t.Fatalf("SASLprep failed for Arabic: %v", err)
		}
		if result != "\u0627\u0628\u062A" {
			t.Errorf("Arabic string changed unexpectedly")
		}
	})
}

func TestSASLprepNormalization(t *testing.T) {
	t.Run("NFKCDecomposition", func(t *testing.T) {
		// LATIN SMALL LETTER A WITH COMBINING ACUTE ACCENT
		// should be normalized to LATIN SMALL LETTER A WITH ACUTE
		result, err := SASLprep("a\u0301", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "á" {
			t.Errorf("Expected 'á' (normalized), got %q", result)
		}
	})

	t.Run("NFKCCompatibility", func(t *testing.T) {
		// FULLWIDTH LATIN SMALL LETTER A (U+FF41) should normalize to 'a'
		result, err := SASLprep("\uFF41", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "a" {
			t.Errorf("Expected 'a' (normalized), got %q", result)
		}
	})

	t.Run("NFKCFullwidthDigits", func(t *testing.T) {
		// FULLWIDTH DIGIT ONE (U+FF11) should normalize to '1'
		result, err := SASLprep("\uFF11\uFF12\uFF13", false)
		if err != nil {
			t.Fatalf("SASLprep failed: %v", err)
		}
		if result != "123" {
			t.Errorf("Expected '123' (normalized), got %q", result)
		}
	})
}

func TestSASLprepStored(t *testing.T) {
	t.Run("SimplePassword", func(t *testing.T) {
		result, err := SASLprepStored("password")
		if err != nil {
			t.Fatalf("SASLprepStored failed: %v", err)
		}
		if result != "password" {
			t.Errorf("Expected 'password', got %q", result)
		}
	})

	t.Run("EmptyPassword", func(t *testing.T) {
		_, err := SASLprepStored("")
		if err != ErrSASLprepEmpty {
			t.Errorf("Expected ErrSASLprepEmpty, got %v", err)
		}
	})
}

func TestSASLprepQuery(t *testing.T) {
	t.Run("SimpleQuery", func(t *testing.T) {
		result, err := SASLprepQuery("query")
		if err != nil {
			t.Fatalf("SASLprepQuery failed: %v", err)
		}
		if result != "query" {
			t.Errorf("Expected 'query', got %q", result)
		}
	})
}

func TestNormalizePDFPassword(t *testing.T) {
	t.Run("EmptyPassword", func(t *testing.T) {
		result, err := NormalizePDFPassword("")
		if err != nil {
			t.Fatalf("NormalizePDFPassword failed: %v", err)
		}
		if result != "" {
			t.Errorf("Expected empty string, got %q", result)
		}
	})

	t.Run("SimplePassword", func(t *testing.T) {
		result, err := NormalizePDFPassword("secret")
		if err != nil {
			t.Fatalf("NormalizePDFPassword failed: %v", err)
		}
		if result != "secret" {
			t.Errorf("Expected 'secret', got %q", result)
		}
	})

	t.Run("PasswordWithNBSP", func(t *testing.T) {
		// NO-BREAK SPACE should be normalized to regular space
		result, err := NormalizePDFPassword("pass\u00A0word")
		if err != nil {
			t.Fatalf("NormalizePDFPassword failed: %v", err)
		}
		if result != "pass word" {
			t.Errorf("Expected 'pass word', got %q", result)
		}
	})

	t.Run("PasswordWithSoftHyphen", func(t *testing.T) {
		// SOFT HYPHEN should be removed
		result, err := NormalizePDFPassword("pass\u00ADword")
		if err != nil {
			t.Fatalf("NormalizePDFPassword failed: %v", err)
		}
		if result != "password" {
			t.Errorf("Expected 'password', got %q", result)
		}
	})
}

func TestNormalizePDFPasswordBytes(t *testing.T) {
	t.Run("EmptyPassword", func(t *testing.T) {
		result, err := NormalizePDFPasswordBytes(nil)
		if err != nil {
			t.Fatalf("NormalizePDFPasswordBytes failed: %v", err)
		}
		if result != nil {
			t.Errorf("Expected nil, got %v", result)
		}
	})

	t.Run("EmptySlice", func(t *testing.T) {
		result, err := NormalizePDFPasswordBytes([]byte{})
		if err != nil {
			t.Fatalf("NormalizePDFPasswordBytes failed: %v", err)
		}
		if result != nil {
			t.Errorf("Expected nil, got %v", result)
		}
	})

	t.Run("SimplePassword", func(t *testing.T) {
		result, err := NormalizePDFPasswordBytes([]byte("secret"))
		if err != nil {
			t.Fatalf("NormalizePDFPasswordBytes failed: %v", err)
		}
		if string(result) != "secret" {
			t.Errorf("Expected 'secret', got %q", string(result))
		}
	})
}

func TestTableB1(t *testing.T) {
	// Test specific B.1 table entries
	tests := []struct {
		name  string
		rune  rune
		want  bool
	}{
		{"SOFT HYPHEN", 0x00AD, true},
		{"COMBINING GRAPHEME JOINER", 0x034F, true},
		{"MONGOLIAN TODO SOFT HYPHEN", 0x1806, true},
		{"MONGOLIAN FREE VARIATION SELECTOR ONE", 0x180B, true},
		{"ZERO WIDTH SPACE", 0x200B, true},
		{"ZERO WIDTH NON-JOINER", 0x200C, true},
		{"ZERO WIDTH JOINER", 0x200D, true},
		{"WORD JOINER", 0x2060, true},
		{"ZERO WIDTH NO-BREAK SPACE", 0xFEFF, true},
		{"VARIATION SELECTOR-1", 0xFE00, true},
		{"VARIATION SELECTOR-16", 0xFE0F, true},
		{"Regular letter A", 'A', false},
		{"Regular space", ' ', false},
		{"Regular digit", '1', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableB1(tt.rune)
			if got != tt.want {
				t.Errorf("inTableB1(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestTableC12(t *testing.T) {
	// Test specific C.1.2 table entries
	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"NO-BREAK SPACE", 0x00A0, true},
		{"OGHAM SPACE MARK", 0x1680, true},
		{"EN QUAD", 0x2000, true},
		{"EM QUAD", 0x2001, true},
		{"EN SPACE", 0x2002, true},
		{"EM SPACE", 0x2003, true},
		{"IDEOGRAPHIC SPACE", 0x3000, true},
		{"Regular space", ' ', false},
		{"Regular letter", 'a', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableC12(tt.rune)
			if got != tt.want {
				t.Errorf("inTableC12(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestTableC21(t *testing.T) {
	// Test ASCII control characters
	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"NULL", 0x00, true},
		{"SOH", 0x01, true},
		{"TAB", 0x09, true},
		{"LF", 0x0A, true},
		{"CR", 0x0D, true},
		{"US", 0x1F, true},
		{"DEL", 0x7F, true},
		{"Space", ' ', false},
		{"Exclamation", '!', false},
		{"Tilde", '~', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableC21(tt.rune)
			if got != tt.want {
				t.Errorf("inTableC21(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestTableC22(t *testing.T) {
	// Test non-ASCII control characters
	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"C1 Control 0x80", 0x80, true},
		{"C1 Control 0x9F", 0x9F, true},
		{"ARABIC END OF AYAH", 0x06DD, true},
		{"LINE SEPARATOR", 0x2028, true},
		{"PARAGRAPH SEPARATOR", 0x2029, true},
		{"BYTE ORDER MARK", 0xFEFF, true},
		{"Regular letter", 'A', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableC22(tt.rune)
			if got != tt.want {
				t.Errorf("inTableC22(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestTableC3(t *testing.T) {
	// Test private use characters
	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"BMP Private Use Start", 0xE000, true},
		{"BMP Private Use End", 0xF8FF, true},
		{"Before Private Use", 0xDFFF, false},
		{"After Private Use", 0xF900, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableC3(tt.rune)
			if got != tt.want {
				t.Errorf("inTableC3(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestTableC4(t *testing.T) {
	// Test non-character code points
	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"FFFE", 0xFFFE, true},
		{"FFFF", 0xFFFF, true},
		{"FDD0", 0xFDD0, true},
		{"FDEF", 0xFDEF, true},
		{"Regular", 0xFDCF, false},
		{"After FDD range", 0xFDF0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableC4(tt.rune)
			if got != tt.want {
				t.Errorf("inTableC4(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestTableC5(t *testing.T) {
	// Test surrogate codes (these shouldn't appear in valid Go strings)
	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"High Surrogate Start", 0xD800, true},
		{"High Surrogate End", 0xDBFF, true},
		{"Low Surrogate Start", 0xDC00, true},
		{"Low Surrogate End", 0xDFFF, true},
		{"Before Surrogate", 0xD7FF, false},
		{"After Surrogate", 0xE000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableC5(tt.rune)
			if got != tt.want {
				t.Errorf("inTableC5(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestTableC6(t *testing.T) {
	// Test inappropriate for plain text
	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"INTERLINEAR ANNOTATION ANCHOR", 0xFFF9, true},
		{"INTERLINEAR ANNOTATION SEPARATOR", 0xFFFA, true},
		{"INTERLINEAR ANNOTATION TERMINATOR", 0xFFFB, true},
		{"OBJECT REPLACEMENT CHARACTER", 0xFFFC, true},
		{"REPLACEMENT CHARACTER", 0xFFFD, true},
		{"Regular", 0xFFF8, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableC6(tt.rune)
			if got != tt.want {
				t.Errorf("inTableC6(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestTableC7(t *testing.T) {
	// Test inappropriate for canonical representation
	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"IDEOGRAPHIC DESCRIPTION CHARACTER LEFT TO RIGHT", 0x2FF0, true},
		{"IDEOGRAPHIC DESCRIPTION CHARACTER ABOVE TO BELOW", 0x2FF1, true},
		{"IDEOGRAPHIC DESCRIPTION CHARACTER OVERLAID", 0x2FFB, true},
		{"Before range", 0x2FEF, false},
		{"After range", 0x2FFC, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableC7(tt.rune)
			if got != tt.want {
				t.Errorf("inTableC7(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestTableC8(t *testing.T) {
	// Test change display properties or deprecated
	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"COMBINING GRAVE TONE MARK", 0x0340, true},
		{"COMBINING ACUTE TONE MARK", 0x0341, true},
		{"LEFT-TO-RIGHT MARK", 0x200E, true},
		{"RIGHT-TO-LEFT MARK", 0x200F, true},
		{"LEFT-TO-RIGHT EMBEDDING", 0x202A, true},
		{"RIGHT-TO-LEFT EMBEDDING", 0x202B, true},
		{"Regular A", 'A', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableC8(tt.rune)
			if got != tt.want {
				t.Errorf("inTableC8(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestTableC9(t *testing.T) {
	// Test tagging characters
	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"LANGUAGE TAG", 0xE0001, true},
		{"TAG SPACE", 0xE0020, true},
		{"TAG TILDE", 0xE007E, true},
		{"CANCEL TAG", 0xE007F, true},
		{"Before range", 0xE001F, false},
		{"After range", 0xE0080, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableC9(tt.rune)
			if got != tt.want {
				t.Errorf("inTableC9(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestTableD1(t *testing.T) {
	// Test RandALCat (RTL characters)
	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"HEBREW LETTER ALEF", 0x05D0, true},
		{"HEBREW LETTER TAV", 0x05EA, true},
		{"ARABIC LETTER ALEF", 0x0627, true},
		{"ARABIC LETTER BEH", 0x0628, true},
		{"Latin A", 'A', false},
		{"Digit 1", '1', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableD1(tt.rune)
			if got != tt.want {
				t.Errorf("inTableD1(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestTableD2(t *testing.T) {
	// Test LCat (LTR characters)
	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"Latin A", 'A', true},
		{"Latin Z", 'Z', true},
		{"Latin a", 'a', true},
		{"Latin z", 'z', true},
		{"Greek Alpha", 0x0391, true},
		{"Cyrillic A", 0x0410, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inTableD2(tt.rune)
			if got != tt.want {
				t.Errorf("inTableD2(%U) = %v, want %v", tt.rune, got, tt.want)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	t.Run("ErrSASLprepProhibited", func(t *testing.T) {
		if ErrSASLprepProhibited.Error() == "" {
			t.Error("ErrSASLprepProhibited should have a message")
		}
	})

	t.Run("ErrSASLprepBidirectional", func(t *testing.T) {
		if ErrSASLprepBidirectional.Error() == "" {
			t.Error("ErrSASLprepBidirectional should have a message")
		}
	})

	t.Run("ErrSASLprepEmpty", func(t *testing.T) {
		if ErrSASLprepEmpty.Error() == "" {
			t.Error("ErrSASLprepEmpty should have a message")
		}
	})
}
