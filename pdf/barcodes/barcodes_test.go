// Package barcodes provides barcode generation tests.
package barcodes

import (
	"strings"
	"testing"
)

// BarcodeType tests

func TestBarcodeTypeString(t *testing.T) {
	tests := []struct {
		btype    BarcodeType
		expected string
	}{
		{TypeCode128, "Code128"},
		{TypeCode128A, "Code128A"},
		{TypeCode128B, "Code128B"},
		{TypeCode128C, "Code128C"},
		{TypeCode39, "Code39"},
		{TypeCode39Extended, "Code39Extended"},
		{TypeEAN13, "EAN-13"},
		{TypeEAN8, "EAN-8"},
		{TypeUPCA, "UPC-A"},
		{TypeUPCE, "UPC-E"},
		{TypeITF, "ITF"},
		{TypeCodabar, "Codabar"},
		{BarcodeType(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		result := tt.btype.String()
		if result != tt.expected {
			t.Errorf("BarcodeType(%d).String() = %q, want %q", tt.btype, result, tt.expected)
		}
	}
}

// Barcode tests

func TestBarcodeWidth(t *testing.T) {
	barcode := &Barcode{
		Encoded: make([]bool, 100),
	}
	if barcode.Width() != 100 {
		t.Errorf("Width() = %d, want 100", barcode.Width())
	}
}

func TestBarcodePattern(t *testing.T) {
	barcode := &Barcode{
		Encoded: []bool{true, false, true, true, false},
	}
	pattern := barcode.Pattern()
	if pattern != "10110" {
		t.Errorf("Pattern() = %q, want %q", pattern, "10110")
	}
}

// Code128 tests

func TestEncodeCode128(t *testing.T) {
	barcode, err := EncodeCode128("TEST123")
	if err != nil {
		t.Fatalf("EncodeCode128 failed: %v", err)
	}
	if barcode.Type != TypeCode128 {
		t.Errorf("Type = %v, want TypeCode128", barcode.Type)
	}
	if barcode.Data != "TEST123" {
		t.Errorf("Data = %q, want %q", barcode.Data, "TEST123")
	}
	if len(barcode.Encoded) == 0 {
		t.Error("Encoded should not be empty")
	}
}

func TestEncodeCode128Empty(t *testing.T) {
	_, err := EncodeCode128("")
	if err != ErrInvalidData {
		t.Errorf("Expected ErrInvalidData, got %v", err)
	}
}

func TestEncodeCode128B(t *testing.T) {
	barcode, err := EncodeCode128B("Hello World")
	if err != nil {
		t.Fatalf("EncodeCode128B failed: %v", err)
	}
	if barcode.Data != "Hello World" {
		t.Errorf("Data = %q, want %q", barcode.Data, "Hello World")
	}
}

func TestEncodeCode128C(t *testing.T) {
	barcode, err := EncodeCode128C("123456")
	if err != nil {
		t.Fatalf("EncodeCode128C failed: %v", err)
	}
	if barcode.Data != "123456" {
		t.Errorf("Data = %q, want %q", barcode.Data, "123456")
	}
}

func TestEncodeCode128CInvalidChar(t *testing.T) {
	_, err := EncodeCode128C("12A456")
	if err != ErrInvalidCharacter {
		t.Errorf("Expected ErrInvalidCharacter, got %v", err)
	}
}

func TestEncodeCode128COddLength(t *testing.T) {
	_, err := EncodeCode128C("12345")
	if err != ErrInvalidLength {
		t.Errorf("Expected ErrInvalidLength, got %v", err)
	}
}

func TestEncodeCode128Checksum(t *testing.T) {
	barcode, _ := EncodeCode128("TEST")
	if barcode.Checksum < 0 || barcode.Checksum > 102 {
		t.Errorf("Checksum = %d, should be 0-102", barcode.Checksum)
	}
}

// Code39 tests

func TestEncodeCode39(t *testing.T) {
	barcode, err := EncodeCode39("HELLO123")
	if err != nil {
		t.Fatalf("EncodeCode39 failed: %v", err)
	}
	if barcode.Type != TypeCode39 {
		t.Errorf("Type = %v, want TypeCode39", barcode.Type)
	}
	if barcode.Data != "HELLO123" {
		t.Errorf("Data = %q, want %q", barcode.Data, "HELLO123")
	}
}

func TestEncodeCode39Lowercase(t *testing.T) {
	barcode, err := EncodeCode39("hello")
	if err != nil {
		t.Fatalf("EncodeCode39 failed: %v", err)
	}
	// Should be converted to uppercase
	if barcode.Data != "HELLO" {
		t.Errorf("Data = %q, want %q", barcode.Data, "HELLO")
	}
}

func TestEncodeCode39InvalidChar(t *testing.T) {
	_, err := EncodeCode39("HELLO@WORLD")
	if err != ErrInvalidCharacter {
		t.Errorf("Expected ErrInvalidCharacter, got %v", err)
	}
}

func TestEncodeCode39SpecialChars(t *testing.T) {
	// Test valid special characters
	data := "TEST-. $"
	barcode, err := EncodeCode39(data)
	if err != nil {
		t.Fatalf("EncodeCode39 failed: %v", err)
	}
	if barcode.Data != data {
		t.Errorf("Data = %q, want %q", barcode.Data, data)
	}
}

func TestEncodeCode39WithChecksum(t *testing.T) {
	barcode, err := EncodeCode39WithChecksum("TEST")
	if err != nil {
		t.Fatalf("EncodeCode39WithChecksum failed: %v", err)
	}
	// Should have check digit appended
	if len(barcode.Data) != 5 {
		t.Errorf("Data length = %d, want 5", len(barcode.Data))
	}
}

// EAN-13 tests

func TestEncodeEAN13(t *testing.T) {
	// Valid EAN-13 with checksum
	barcode, err := EncodeEAN13("5901234123457")
	if err != nil {
		t.Fatalf("EncodeEAN13 failed: %v", err)
	}
	if barcode.Type != TypeEAN13 {
		t.Errorf("Type = %v, want TypeEAN13", barcode.Type)
	}
	if len(barcode.Data) != 13 {
		t.Errorf("Data length = %d, want 13", len(barcode.Data))
	}
}

func TestEncodeEAN13WithoutChecksum(t *testing.T) {
	// Without checksum - should be calculated
	barcode, err := EncodeEAN13("590123412345")
	if err != nil {
		t.Fatalf("EncodeEAN13 failed: %v", err)
	}
	if len(barcode.Data) != 13 {
		t.Errorf("Data length = %d, want 13", len(barcode.Data))
	}
}

func TestEncodeEAN13InvalidLength(t *testing.T) {
	_, err := EncodeEAN13("12345")
	if err != ErrInvalidLength {
		t.Errorf("Expected ErrInvalidLength, got %v", err)
	}
}

func TestEncodeEAN13InvalidChar(t *testing.T) {
	_, err := EncodeEAN13("59012341234A")
	if err != ErrInvalidCharacter {
		t.Errorf("Expected ErrInvalidCharacter, got %v", err)
	}
}

func TestEncodeEAN13WrongChecksum(t *testing.T) {
	_, err := EncodeEAN13("5901234123450") // Wrong checksum
	if err != ErrChecksumMismatch {
		t.Errorf("Expected ErrChecksumMismatch, got %v", err)
	}
}

func TestEncodeEAN13Width(t *testing.T) {
	barcode, _ := EncodeEAN13("590123412345")
	// EAN-13 should be: 3 (start) + 42 (left) + 5 (center) + 42 (right) + 3 (end) = 95 modules
	if barcode.Width() != 95 {
		t.Errorf("Width = %d, want 95", barcode.Width())
	}
}

// EAN-8 tests

func TestEncodeEAN8(t *testing.T) {
	barcode, err := EncodeEAN8("96385074")
	if err != nil {
		t.Fatalf("EncodeEAN8 failed: %v", err)
	}
	if barcode.Type != TypeEAN8 {
		t.Errorf("Type = %v, want TypeEAN8", barcode.Type)
	}
	if len(barcode.Data) != 8 {
		t.Errorf("Data length = %d, want 8", len(barcode.Data))
	}
}

func TestEncodeEAN8WithoutChecksum(t *testing.T) {
	barcode, err := EncodeEAN8("9638507")
	if err != nil {
		t.Fatalf("EncodeEAN8 failed: %v", err)
	}
	if len(barcode.Data) != 8 {
		t.Errorf("Data length = %d, want 8", len(barcode.Data))
	}
}

func TestEncodeEAN8InvalidLength(t *testing.T) {
	_, err := EncodeEAN8("12345")
	if err != ErrInvalidLength {
		t.Errorf("Expected ErrInvalidLength, got %v", err)
	}
}

func TestEncodeEAN8WrongChecksum(t *testing.T) {
	_, err := EncodeEAN8("96385070") // Wrong checksum
	if err != ErrChecksumMismatch {
		t.Errorf("Expected ErrChecksumMismatch, got %v", err)
	}
}

func TestEncodeEAN8Width(t *testing.T) {
	barcode, _ := EncodeEAN8("9638507")
	// EAN-8 should be: 3 (start) + 28 (left) + 5 (center) + 28 (right) + 3 (end) = 67 modules
	if barcode.Width() != 67 {
		t.Errorf("Width = %d, want 67", barcode.Width())
	}
}

// UPC-A tests

func TestEncodeUPCA(t *testing.T) {
	barcode, err := EncodeUPCA("03600029145")
	if err != nil {
		t.Fatalf("EncodeUPCA failed: %v", err)
	}
	if barcode.Type != TypeUPCA {
		t.Errorf("Type = %v, want TypeUPCA", barcode.Type)
	}
}

func TestEncodeUPCAInvalidLength(t *testing.T) {
	_, err := EncodeUPCA("12345")
	if err != ErrInvalidLength {
		t.Errorf("Expected ErrInvalidLength, got %v", err)
	}
}

// ITF tests

func TestEncodeITF(t *testing.T) {
	barcode, err := EncodeITF("1234567890")
	if err != nil {
		t.Fatalf("EncodeITF failed: %v", err)
	}
	if barcode.Type != TypeITF {
		t.Errorf("Type = %v, want TypeITF", barcode.Type)
	}
	if barcode.Data != "1234567890" {
		t.Errorf("Data = %q, want %q", barcode.Data, "1234567890")
	}
}

func TestEncodeITFOddLength(t *testing.T) {
	_, err := EncodeITF("12345")
	if err != ErrInvalidLength {
		t.Errorf("Expected ErrInvalidLength, got %v", err)
	}
}

func TestEncodeITFInvalidChar(t *testing.T) {
	_, err := EncodeITF("12A456")
	if err != ErrInvalidCharacter {
		t.Errorf("Expected ErrInvalidCharacter, got %v", err)
	}
}

func TestEncodeITF14(t *testing.T) {
	barcode, err := EncodeITF14("1234567890123")
	if err != nil {
		t.Fatalf("EncodeITF14 failed: %v", err)
	}
	if len(barcode.Data) != 14 {
		t.Errorf("Data length = %d, want 14", len(barcode.Data))
	}
}

func TestEncodeITF14InvalidLength(t *testing.T) {
	_, err := EncodeITF14("12345")
	if err != ErrInvalidLength {
		t.Errorf("Expected ErrInvalidLength, got %v", err)
	}
}

// Codabar tests

func TestEncodeCodabar(t *testing.T) {
	barcode, err := EncodeCodabar("123456", 'A')
	if err != nil {
		t.Fatalf("EncodeCodabar failed: %v", err)
	}
	if barcode.Type != TypeCodabar {
		t.Errorf("Type = %v, want TypeCodabar", barcode.Type)
	}
	if barcode.Data != "123456" {
		t.Errorf("Data = %q, want %q", barcode.Data, "123456")
	}
}

func TestEncodeCodabarSpecialChars(t *testing.T) {
	// Codabar supports: 0-9 - $ : / . +
	barcode, err := EncodeCodabar("123-45.67", 'B')
	if err != nil {
		t.Fatalf("EncodeCodabar failed: %v", err)
	}
	if barcode.Data != "123-45.67" {
		t.Errorf("Data = %q, want %q", barcode.Data, "123-45.67")
	}
}

func TestEncodeCodabarInvalidChar(t *testing.T) {
	_, err := EncodeCodabar("123@456", 'A')
	if err != ErrInvalidCharacter {
		t.Errorf("Expected ErrInvalidCharacter, got %v", err)
	}
}

func TestEncodeCodabarDefaultStartStop(t *testing.T) {
	// Invalid start/stop should default to 'A'
	barcode, err := EncodeCodabar("123", 'X')
	if err != nil {
		t.Fatalf("EncodeCodabar failed: %v", err)
	}
	if barcode == nil {
		t.Error("Barcode should not be nil")
	}
}

// BarcodeRenderer tests

func TestDefaultRenderer(t *testing.T) {
	r := DefaultRenderer()
	if r.BarWidth != 1.0 {
		t.Errorf("BarWidth = %f, want 1.0", r.BarWidth)
	}
	if r.BarHeight != 50.0 {
		t.Errorf("BarHeight = %f, want 50.0", r.BarHeight)
	}
	if r.QuietZone != 10.0 {
		t.Errorf("QuietZone = %f, want 10.0", r.QuietZone)
	}
	if !r.ShowText {
		t.Error("ShowText should be true")
	}
}

func TestRendererTotalWidth(t *testing.T) {
	r := DefaultRenderer()
	barcode := &Barcode{Encoded: make([]bool, 100)}
	width := r.TotalWidth(barcode)
	expected := 10.0*2 + 100*1.0
	if width != expected {
		t.Errorf("TotalWidth = %f, want %f", width, expected)
	}
}

func TestRendererTotalHeight(t *testing.T) {
	r := DefaultRenderer()
	height := r.TotalHeight()
	expected := 50.0 + 12.0
	if height != expected {
		t.Errorf("TotalHeight = %f, want %f", height, expected)
	}

	r.ShowText = false
	height = r.TotalHeight()
	if height != 50.0 {
		t.Errorf("TotalHeight without text = %f, want 50.0", height)
	}
}

func TestRendererToSVG(t *testing.T) {
	r := DefaultRenderer()
	barcode, _ := EncodeCode128("TEST")
	svg := r.ToSVG(barcode)

	if !strings.HasPrefix(svg, "<svg") {
		t.Error("SVG should start with <svg")
	}
	if !strings.HasSuffix(svg, "</svg>") {
		t.Error("SVG should end with </svg>")
	}
	if !strings.Contains(svg, "TEST") {
		t.Error("SVG should contain barcode data")
	}
}

func TestRendererToPDFContentStream(t *testing.T) {
	r := DefaultRenderer()
	barcode, _ := EncodeCode128("TEST")
	content := r.ToPDFContentStream(barcode, 100, 200)

	if !strings.Contains(content, "q") {
		t.Error("PDF content should contain save state (q)")
	}
	if !strings.Contains(content, "Q") {
		t.Error("PDF content should contain restore state (Q)")
	}
	if !strings.Contains(content, "re f") {
		t.Error("PDF content should contain rectangle fill")
	}
}

// Checksum validation tests

func TestValidateCheckDigitEAN13(t *testing.T) {
	valid, err := ValidateCheckDigit(TypeEAN13, "5901234123457")
	if err != nil {
		t.Fatalf("ValidateCheckDigit failed: %v", err)
	}
	if !valid {
		t.Error("Should be valid")
	}

	valid, _ = ValidateCheckDigit(TypeEAN13, "5901234123450")
	if valid {
		t.Error("Should be invalid")
	}
}

func TestValidateCheckDigitEAN8(t *testing.T) {
	valid, err := ValidateCheckDigit(TypeEAN8, "96385074")
	if err != nil {
		t.Fatalf("ValidateCheckDigit failed: %v", err)
	}
	if !valid {
		t.Error("Should be valid")
	}
}

func TestValidateCheckDigitUPCA(t *testing.T) {
	valid, err := ValidateCheckDigit(TypeUPCA, "036000291452")
	if err != nil {
		t.Fatalf("ValidateCheckDigit failed: %v", err)
	}
	if !valid {
		t.Error("Should be valid")
	}
}

func TestValidateCheckDigitInvalidLength(t *testing.T) {
	_, err := ValidateCheckDigit(TypeEAN13, "12345")
	if err != ErrInvalidLength {
		t.Errorf("Expected ErrInvalidLength, got %v", err)
	}
}

func TestValidateCheckDigitUnsupported(t *testing.T) {
	_, err := ValidateCheckDigit(TypeCode39, "TEST")
	if err != ErrUnsupportedType {
		t.Errorf("Expected ErrUnsupportedType, got %v", err)
	}
}

// GenerateCheckDigit tests

func TestGenerateCheckDigitEAN13(t *testing.T) {
	check, err := GenerateCheckDigit(TypeEAN13, "590123412345")
	if err != nil {
		t.Fatalf("GenerateCheckDigit failed: %v", err)
	}
	if check != 7 {
		t.Errorf("Check digit = %d, want 7", check)
	}
}

func TestGenerateCheckDigitEAN8(t *testing.T) {
	check, err := GenerateCheckDigit(TypeEAN8, "9638507")
	if err != nil {
		t.Fatalf("GenerateCheckDigit failed: %v", err)
	}
	if check != 4 {
		t.Errorf("Check digit = %d, want 4", check)
	}
}

func TestGenerateCheckDigitUPCA(t *testing.T) {
	check, err := GenerateCheckDigit(TypeUPCA, "03600029145")
	if err != nil {
		t.Fatalf("GenerateCheckDigit failed: %v", err)
	}
	if check != 2 {
		t.Errorf("Check digit = %d, want 2", check)
	}
}

func TestGenerateCheckDigitInvalidLength(t *testing.T) {
	_, err := GenerateCheckDigit(TypeEAN13, "12345")
	if err != ErrInvalidLength {
		t.Errorf("Expected ErrInvalidLength, got %v", err)
	}
}

// Error tests

func TestErrors(t *testing.T) {
	errors := []error{
		ErrInvalidData,
		ErrInvalidLength,
		ErrInvalidCharacter,
		ErrChecksumMismatch,
		ErrUnsupportedType,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("Error should have non-empty message: %v", err)
		}
	}
}

// Pattern helper tests

func TestPatternToBools(t *testing.T) {
	pattern := "10110"
	result := patternToBools(pattern)

	expected := []bool{true, false, true, true, false}
	if len(result) != len(expected) {
		t.Fatalf("Length = %d, want %d", len(result), len(expected))
	}
	for i, v := range expected {
		if result[i] != v {
			t.Errorf("result[%d] = %v, want %v", i, result[i], v)
		}
	}
}

// Deterministic encoding tests

func TestDeterministicEncoding(t *testing.T) {
	// Same input should produce same output
	b1, _ := EncodeCode128("TEST123")
	b2, _ := EncodeCode128("TEST123")

	if b1.Pattern() != b2.Pattern() {
		t.Error("Encoding should be deterministic")
	}
}

// Integration tests

func TestMultipleBarcodesSequential(t *testing.T) {
	codes := []string{"A001", "A002", "A003", "A004", "A005"}
	for _, code := range codes {
		barcode, err := EncodeCode128(code)
		if err != nil {
			t.Errorf("Failed to encode %s: %v", code, err)
		}
		if barcode.Data != code {
			t.Errorf("Data = %q, want %q", barcode.Data, code)
		}
	}
}

func TestAllBarcodeTypes(t *testing.T) {
	// Test that we can create at least one of each type
	tests := []struct {
		name   string
		encode func() (*Barcode, error)
	}{
		{"Code128", func() (*Barcode, error) { return EncodeCode128("TEST") }},
		{"Code128B", func() (*Barcode, error) { return EncodeCode128B("Test") }},
		{"Code128C", func() (*Barcode, error) { return EncodeCode128C("123456") }},
		{"Code39", func() (*Barcode, error) { return EncodeCode39("TEST") }},
		{"EAN13", func() (*Barcode, error) { return EncodeEAN13("590123412345") }},
		{"EAN8", func() (*Barcode, error) { return EncodeEAN8("9638507") }},
		{"UPCA", func() (*Barcode, error) { return EncodeUPCA("03600029145") }},
		{"ITF", func() (*Barcode, error) { return EncodeITF("1234567890") }},
		{"Codabar", func() (*Barcode, error) { return EncodeCodabar("123456", 'A') }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			barcode, err := tt.encode()
			if err != nil {
				t.Fatalf("Failed to encode %s: %v", tt.name, err)
			}
			if barcode.Width() == 0 {
				t.Error("Barcode width should not be 0")
			}
		})
	}
}
