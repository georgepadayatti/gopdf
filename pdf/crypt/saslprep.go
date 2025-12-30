// Package crypt provides PDF encryption and decryption.
// This file implements RFC 4013 SASLprep for password preparation.
//
// SASLprep is used in PDF 2.0 encryption (revision 6) for password
// normalization before hashing.
package crypt

import (
	"errors"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// SASLprep errors
var (
	ErrSASLprepProhibited    = errors.New("SASLprep: prohibited character")
	ErrSASLprepBidirectional = errors.New("SASLprep: failed bidirectional check")
	ErrSASLprepEmpty         = errors.New("SASLprep: empty string")
)

// SASLprep implements RFC 4013 SASLprep.
//
// This function prepares a string for use in SASL authentication mechanisms.
// It performs the following steps:
//  1. Map - Map certain characters to nothing or to space
//  2. Normalize - Apply NFKC normalization
//  3. Prohibit - Check for prohibited characters
//  4. Check bidi - Check bidirectional string requirements
//
// Parameters:
//   - data: The string to SASLprep
//   - prohibitUnassigned: If true, unassigned code points are prohibited
//     (used for "stored strings"). If false, they are allowed (for "queries").
//
// Returns the SASLprep'd string or an error.
func SASLprep(data string, prohibitUnassigned bool) (string, error) {
	if len(data) == 0 {
		return "", ErrSASLprepEmpty
	}

	// Step 1: Map (RFC 3454 Section 2, RFC 4013 Section 2.1)
	// - Map Non-ASCII space characters (Table C.1.2) to U+0020 (SPACE)
	// - Map commonly mapped to nothing characters (Table B.1) to nothing
	var mapped strings.Builder
	mapped.Grow(len(data))

	for _, r := range data {
		if inTableB1(r) {
			// Map to nothing
			continue
		}
		if inTableC12(r) {
			// Map to space
			mapped.WriteRune(' ')
		} else {
			mapped.WriteRune(r)
		}
	}

	// Step 2: Normalize (RFC 3454 Section 2, RFC 4013 Section 2.2)
	// Apply NFKC normalization
	normalized := norm.NFKC.String(mapped.String())

	if len(normalized) == 0 {
		return "", ErrSASLprepEmpty
	}

	// Step 3 & 4: Prohibit and Check bidi (RFC 3454 Section 2)
	runes := []rune(normalized)
	firstChar := runes[0]
	lastChar := runes[len(runes)-1]

	// Check bidirectional requirements (RFC 3454 Section 6)
	hasRandALCat := inTableD1(firstChar)

	if hasRandALCat {
		// If a string contains any RandALCat character, the first and last
		// characters MUST be RandALCat characters
		if !inTableD1(lastChar) {
			return "", ErrSASLprepBidirectional
		}
	}

	// Check each character for prohibited characters
	for _, r := range runes {
		// Check prohibited tables (C.1.2, C.2.1, C.2.2, C.3, C.4, C.5, C.6, C.7, C.8, C.9)
		if isProhibited(r) {
			return "", ErrSASLprepProhibited
		}

		// Check unassigned code points (Table A.1) if required
		if prohibitUnassigned && inTableA1(r) {
			return "", ErrSASLprepProhibited
		}

		// Bidirectional checks
		if hasRandALCat {
			// If string contains RandALCat, it MUST NOT contain any LCat
			if inTableD2(r) {
				return "", ErrSASLprepBidirectional
			}
		} else {
			// If first char is not RandALCat, no other char can be RandALCat
			if inTableD1(r) {
				return "", ErrSASLprepBidirectional
			}
		}
	}

	return normalized, nil
}

// SASLprepStored is a convenience function for stored strings.
// It calls SASLprep with prohibitUnassigned=true.
func SASLprepStored(data string) (string, error) {
	return SASLprep(data, true)
}

// SASLprepQuery is a convenience function for queries.
// It calls SASLprep with prohibitUnassigned=false.
func SASLprepQuery(data string) (string, error) {
	return SASLprep(data, false)
}

// isProhibited checks if a rune is in any prohibited table.
func isProhibited(r rune) bool {
	return inTableC12(r) || // Non-ASCII space (already mapped, but check after normalization)
		inTableC21C22(r) || // Control characters
		inTableC3(r) || // Private use
		inTableC4(r) || // Non-character code points
		inTableC5(r) || // Surrogate codes
		inTableC6(r) || // Inappropriate for plain text
		inTableC7(r) || // Inappropriate for canonical representation
		inTableC8(r) || // Change display properties or deprecated
		inTableC9(r) // Tagging characters
}

// Table B.1 - Commonly mapped to nothing
// Characters that are deleted during stringprep mapping
func inTableB1(r rune) bool {
	switch r {
	case 0x00AD, // SOFT HYPHEN
		0x034F, // COMBINING GRAPHEME JOINER
		0x1806, // MONGOLIAN TODO SOFT HYPHEN
		0x180B, // MONGOLIAN FREE VARIATION SELECTOR ONE
		0x180C, // MONGOLIAN FREE VARIATION SELECTOR TWO
		0x180D, // MONGOLIAN FREE VARIATION SELECTOR THREE
		0x200B, // ZERO WIDTH SPACE
		0x200C, // ZERO WIDTH NON-JOINER
		0x200D, // ZERO WIDTH JOINER
		0x2060, // WORD JOINER
		0xFEFF: // ZERO WIDTH NO-BREAK SPACE
		return true
	}
	// FE00-FE0F: VARIATION SELECTOR-1 to VARIATION SELECTOR-16
	if r >= 0xFE00 && r <= 0xFE0F {
		return true
	}
	return false
}

// Table C.1.2 - Non-ASCII space characters
// Characters that are mapped to SPACE (U+0020)
func inTableC12(r rune) bool {
	switch r {
	case 0x00A0, // NO-BREAK SPACE
		0x1680, // OGHAM SPACE MARK
		0x2000, // EN QUAD
		0x2001, // EM QUAD
		0x2002, // EN SPACE
		0x2003, // EM SPACE
		0x2004, // THREE-PER-EM SPACE
		0x2005, // FOUR-PER-EM SPACE
		0x2006, // SIX-PER-EM SPACE
		0x2007, // FIGURE SPACE
		0x2008, // PUNCTUATION SPACE
		0x2009, // THIN SPACE
		0x200A, // HAIR SPACE
		0x200B, // ZERO WIDTH SPACE
		0x202F, // NARROW NO-BREAK SPACE
		0x205F, // MEDIUM MATHEMATICAL SPACE
		0x3000: // IDEOGRAPHIC SPACE
		return true
	}
	return false
}

// Table C.2.1 - ASCII control characters
func inTableC21(r rune) bool {
	return r <= 0x001F || r == 0x007F
}

// Table C.2.2 - Non-ASCII control characters
func inTableC22(r rune) bool {
	switch {
	case r >= 0x0080 && r <= 0x009F:
		return true
	case r == 0x06DD, r == 0x070F:
		return true
	case r == 0x180E:
		return true
	case r >= 0x200C && r <= 0x200D:
		return true
	case r >= 0x2028 && r <= 0x2029:
		return true
	case r >= 0x2060 && r <= 0x2063:
		return true
	case r >= 0x206A && r <= 0x206F:
		return true
	case r == 0xFEFF:
		return true
	case r >= 0xFFF9 && r <= 0xFFFC:
		return true
	case r >= 0x1D173 && r <= 0x1D17A:
		return true
	}
	return false
}

// Table C.2.1 + C.2.2 combined
func inTableC21C22(r rune) bool {
	return inTableC21(r) || inTableC22(r)
}

// Table C.3 - Private use
func inTableC3(r rune) bool {
	return (r >= 0xE000 && r <= 0xF8FF) ||
		(r >= 0xF0000 && r <= 0xFFFFD) ||
		(r >= 0x100000 && r <= 0x10FFFD)
}

// Table C.4 - Non-character code points
func inTableC4(r rune) bool {
	// FFFE and FFFF for each plane
	if r&0xFFFF == 0xFFFE || r&0xFFFF == 0xFFFF {
		return true
	}
	// FDD0-FDEF
	if r >= 0xFDD0 && r <= 0xFDEF {
		return true
	}
	return false
}

// Table C.5 - Surrogate codes
func inTableC5(r rune) bool {
	return r >= 0xD800 && r <= 0xDFFF
}

// Table C.6 - Inappropriate for plain text
func inTableC6(r rune) bool {
	switch r {
	case 0xFFF9, // INTERLINEAR ANNOTATION ANCHOR
		0xFFFA, // INTERLINEAR ANNOTATION SEPARATOR
		0xFFFB, // INTERLINEAR ANNOTATION TERMINATOR
		0xFFFC, // OBJECT REPLACEMENT CHARACTER
		0xFFFD: // REPLACEMENT CHARACTER
		return true
	}
	return false
}

// Table C.7 - Inappropriate for canonical representation
func inTableC7(r rune) bool {
	return r >= 0x2FF0 && r <= 0x2FFB
}

// Table C.8 - Change display properties or are deprecated
func inTableC8(r rune) bool {
	switch r {
	case 0x0340, // COMBINING GRAVE TONE MARK
		0x0341, // COMBINING ACUTE TONE MARK
		0x200E, // LEFT-TO-RIGHT MARK
		0x200F, // RIGHT-TO-LEFT MARK
		0x202A, // LEFT-TO-RIGHT EMBEDDING
		0x202B, // RIGHT-TO-LEFT EMBEDDING
		0x202C, // POP DIRECTIONAL FORMATTING
		0x202D, // LEFT-TO-RIGHT OVERRIDE
		0x202E, // RIGHT-TO-LEFT OVERRIDE
		0x206A, // INHIBIT SYMMETRIC SWAPPING
		0x206B, // ACTIVATE SYMMETRIC SWAPPING
		0x206C, // INHIBIT ARABIC FORM SHAPING
		0x206D, // ACTIVATE ARABIC FORM SHAPING
		0x206E, // NATIONAL DIGIT SHAPES
		0x206F: // NOMINAL DIGIT SHAPES
		return true
	}
	return false
}

// Table C.9 - Tagging characters
func inTableC9(r rune) bool {
	return r == 0xE0001 || (r >= 0xE0020 && r <= 0xE007F)
}

// Table D.1 - Characters with bidirectional property "R" or "AL" (RandALCat)
func inTableD1(r rune) bool {
	// This is a simplified check using Unicode bidirectional properties
	// Right-to-left characters (Hebrew, Arabic, etc.)
	switch {
	// Hebrew
	case r >= 0x05BE && r <= 0x05C4:
		return true
	case r >= 0x05D0 && r <= 0x05EA:
		return true
	case r >= 0x05F0 && r <= 0x05F4:
		return true
	// Arabic
	case r >= 0x0600 && r <= 0x0603:
		return true
	case r == 0x060B || r == 0x060D:
		return true
	case r >= 0x061B && r <= 0x064A:
		return true
	case r >= 0x066D && r <= 0x066F:
		return true
	case r >= 0x0671 && r <= 0x06D5:
		return true
	case r >= 0x06E5 && r <= 0x06E6:
		return true
	case r >= 0x06EE && r <= 0x06EF:
		return true
	case r >= 0x06FA && r <= 0x070D:
		return true
	case r == 0x0710:
		return true
	case r >= 0x0712 && r <= 0x072F:
		return true
	case r >= 0x074D && r <= 0x07A5:
		return true
	case r == 0x07B1:
		return true
	// Additional RTL blocks
	case r >= 0xFB1D && r <= 0xFB28:
		return true
	case r >= 0xFB2A && r <= 0xFD3D:
		return true
	case r >= 0xFD50 && r <= 0xFDFC:
		return true
	case r >= 0xFE70 && r <= 0xFEFC:
		return true
	}

	// Use Unicode properties for more complete check
	return unicode.Is(unicode.Arabic, r) || unicode.Is(unicode.Hebrew, r)
}

// Table D.2 - Characters with bidirectional property "L" (LCat)
func inTableD2(r rune) bool {
	// Left-to-right characters
	// Most Latin, Greek, Cyrillic, etc. characters are LCat
	// This is a simplified check

	// Check if it's a letter that's not RTL
	if unicode.IsLetter(r) && !inTableD1(r) {
		return true
	}

	// Common L characters
	switch {
	case r >= 0x0041 && r <= 0x005A: // A-Z
		return true
	case r >= 0x0061 && r <= 0x007A: // a-z
		return true
	case r >= 0x00C0 && r <= 0x00D6: // Latin Extended-A
		return true
	case r >= 0x00D8 && r <= 0x00F6:
		return true
	case r >= 0x00F8 && r <= 0x0220:
		return true
	case r >= 0x0222 && r <= 0x0233:
		return true
	case r >= 0x0250 && r <= 0x02AD: // IPA Extensions
		return true
	case r >= 0x02B0 && r <= 0x02B8: // Spacing Modifier Letters
		return true
	case r >= 0x02BB && r <= 0x02C1:
		return true
	case r >= 0x02D0 && r <= 0x02D1:
		return true
	case r >= 0x02E0 && r <= 0x02E4:
		return true
	case r == 0x02EE:
		return true
	case r == 0x037A:
		return true
	case r == 0x0386:
		return true
	case r >= 0x0388 && r <= 0x038A: // Greek
		return true
	case r == 0x038C:
		return true
	case r >= 0x038E && r <= 0x03A1:
		return true
	case r >= 0x03A3 && r <= 0x03CE:
		return true
	case r >= 0x03D0 && r <= 0x03F5:
		return true
	case r >= 0x0400 && r <= 0x0482: // Cyrillic
		return true
	case r >= 0x048A && r <= 0x04CE:
		return true
	case r >= 0x04D0 && r <= 0x04F5:
		return true
	case r >= 0x04F8 && r <= 0x04F9:
		return true
	}

	return false
}

// Table A.1 - Unassigned code points in Unicode 3.2
// This is a simplified implementation that checks for unassigned ranges
func inTableA1(r rune) bool {
	// Check if the character is not assigned in Unicode 3.2
	// This is approximated by checking if it's in certain unassigned ranges
	// A complete implementation would require the full Unicode 3.2 database

	// Most common case: standard characters are assigned
	if r < 0x0380 {
		// Check specific unassigned points in lower range
		switch r {
		case 0x0221, 0x0234, 0x0235, 0x0236, 0x0237, 0x0238, 0x0239, 0x023A,
			0x023B, 0x023C, 0x023D, 0x023E, 0x023F, 0x0240, 0x0241, 0x0242,
			0x0243, 0x0244, 0x0245, 0x0246, 0x0247, 0x0248, 0x0249, 0x024A,
			0x024B, 0x024C, 0x024D, 0x024E, 0x024F:
			return true
		}
		return false
	}

	// Check various unassigned ranges
	switch {
	case r >= 0x0380 && r <= 0x0383:
		return true
	case r == 0x038B || r == 0x038D || r == 0x03A2:
		return true
	case r >= 0x03CF && r <= 0x03CF:
		return true
	case r >= 0x0487 && r <= 0x0489:
		return true
	case r >= 0x04CF && r <= 0x04CF:
		return true
	case r >= 0x04F6 && r <= 0x04F7:
		return true
	case r >= 0x04FA && r <= 0x04FF:
		return true
		// Many more ranges exist but this covers common cases
		// For a complete implementation, use a comprehensive Unicode 3.2 database
	}

	// Characters beyond the BMP that weren't assigned in Unicode 3.2
	if r > 0xFFFF && r < 0x10000 {
		return true // Simplified: many supplementary characters weren't in 3.2
	}

	return false
}

// NormalizePDFPassword normalizes a password for PDF 2.0 encryption.
// This is a convenience function that applies SASLprep with stored string rules.
func NormalizePDFPassword(password string) (string, error) {
	if len(password) == 0 {
		return "", nil // Empty password is valid
	}
	return SASLprepStored(password)
}

// NormalizePDFPasswordBytes normalizes a password from bytes for PDF 2.0 encryption.
func NormalizePDFPasswordBytes(password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, nil
	}

	normalized, err := SASLprepStored(string(password))
	if err != nil {
		return nil, err
	}

	return []byte(normalized), nil
}
