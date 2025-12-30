package fonts

import (
	"bytes"
	"strings"
	"testing"
)

func TestIsStandardFont(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"Helvetica", true},
		{"Helvetica-Bold", true},
		{"Times-Roman", true},
		{"Courier", true},
		{"Symbol", true},
		{"ZapfDingbats", true},
		{"Arial", false},
		{"CustomFont", false},
	}

	for _, tt := range tests {
		result := IsStandardFont(tt.name)
		if result != tt.expected {
			t.Errorf("IsStandardFont(%s) = %v, want %v", tt.name, result, tt.expected)
		}
	}
}

func TestNewFontMetrics(t *testing.T) {
	m := NewFontMetrics()

	if m.UnitsPerEm != 1000 {
		t.Errorf("Expected UnitsPerEm 1000, got %f", m.UnitsPerEm)
	}
	if m.Ascender != 800 {
		t.Errorf("Expected Ascender 800, got %f", m.Ascender)
	}
	if m.Descender != -200 {
		t.Errorf("Expected Descender -200, got %f", m.Descender)
	}
	if m.Widths == nil {
		t.Error("Widths map should not be nil")
	}
}

func TestFontMetricsGetWidth(t *testing.T) {
	m := NewFontMetrics()
	m.Widths['A'] = 667
	m.Widths['B'] = 722
	m.DefaultWidth = 500

	if m.GetWidth('A') != 667 {
		t.Errorf("Expected width 667 for 'A', got %f", m.GetWidth('A'))
	}
	if m.GetWidth('Z') != 500 {
		t.Errorf("Expected default width 500 for 'Z', got %f", m.GetWidth('Z'))
	}
}

func TestFontMetricsGetStringWidth(t *testing.T) {
	m := NewFontMetrics()
	m.Widths['H'] = 722
	m.Widths['i'] = 278
	m.UnitsPerEm = 1000

	// "Hi" = 722 + 278 = 1000 units
	// At fontSize 10: 1000 * 10 / 1000 = 10
	width := m.GetStringWidth("Hi", 10)
	if width != 10 {
		t.Errorf("Expected width 10, got %f", width)
	}
}

func TestFontMetricsGetLineHeight(t *testing.T) {
	m := NewFontMetrics()
	m.Ascender = 800
	m.Descender = -200
	m.LineGap = 0
	m.UnitsPerEm = 1000

	// LineHeight = (800 - (-200) + 0) * 12 / 1000 = 12
	height := m.GetLineHeight(12)
	if height != 12 {
		t.Errorf("Expected line height 12, got %f", height)
	}
}

func TestNewStandardFont(t *testing.T) {
	fonts := []StandardFont{
		Helvetica, HelveticaBold, HelveticaOblique, HelveticaBoldOblique,
		Times, TimesBold, TimesItalic, TimesBoldItalic,
		Courier, CourierBold, CourierOblique, CourierBoldOblique,
		Symbol, ZapfDingbats,
	}

	for _, name := range fonts {
		font := NewStandardFont(name)
		if font == nil {
			t.Errorf("NewStandardFont(%s) returned nil", name)
			continue
		}
		if font.Name() != string(name) {
			t.Errorf("Expected name %s, got %s", name, font.Name())
		}
		if font.Type() != FontTypeType1 {
			t.Errorf("Expected Type1, got %s", font.Type())
		}
		if font.Metrics() == nil {
			t.Errorf("Metrics() returned nil for %s", name)
		}
	}
}

func TestStandardFontEncode(t *testing.T) {
	font := NewStandardFont(Helvetica)

	encoded := font.Encode("Hello")
	if len(encoded) != 5 {
		t.Errorf("Expected 5 bytes, got %d", len(encoded))
	}
	if string(encoded) != "Hello" {
		t.Errorf("Expected 'Hello', got '%s'", string(encoded))
	}
}

func TestStandardFontEncodeToGlyphs(t *testing.T) {
	font := NewStandardFont(Helvetica)

	glyphs := font.EncodeToGlyphs("AB")
	if len(glyphs) != 2 {
		t.Errorf("Expected 2 glyphs, got %d", len(glyphs))
	}
	if glyphs[0] != 65 {
		t.Errorf("Expected glyph 65 for 'A', got %d", glyphs[0])
	}
	if glyphs[1] != 66 {
		t.Errorf("Expected glyph 66 for 'B', got %d", glyphs[1])
	}
}

func TestEncodeWinAnsi(t *testing.T) {
	// ASCII
	result := encodeWinAnsi("Hello")
	if string(result) != "Hello" {
		t.Errorf("Expected 'Hello', got '%s'", string(result))
	}

	// Special characters
	result = encodeWinAnsi("€")
	if len(result) != 1 || result[0] != 0x80 {
		t.Errorf("Expected Euro to encode as 0x80")
	}

	// Extended ASCII
	result = encodeWinAnsi("é")
	if len(result) != 1 || result[0] != 0xE9 {
		t.Errorf("Expected é to encode as 0xE9")
	}
}

func TestHelveticaWidths(t *testing.T) {
	font := NewStandardFont(Helvetica)
	m := font.Metrics()

	// Check some known widths
	if m.Widths[' '] != 278 {
		t.Errorf("Expected space width 278, got %f", m.Widths[' '])
	}
	if m.Widths['A'] != 667 {
		t.Errorf("Expected 'A' width 667, got %f", m.Widths['A'])
	}
}

func TestHelveticaBoldWidths(t *testing.T) {
	font := NewStandardFont(HelveticaBold)
	m := font.Metrics()

	// Bold is wider
	if m.Widths['A'] != 722 {
		t.Errorf("Expected 'A' width 722, got %f", m.Widths['A'])
	}
}

func TestTimesWidths(t *testing.T) {
	font := NewStandardFont(Times)
	m := font.Metrics()

	if m.Widths[' '] != 250 {
		t.Errorf("Expected space width 250, got %f", m.Widths[' '])
	}
}

func TestCourierWidths(t *testing.T) {
	font := NewStandardFont(Courier)
	m := font.Metrics()

	// Courier is monospace - all 600
	if m.Widths['A'] != 600 {
		t.Errorf("Expected 'A' width 600, got %f", m.Widths['A'])
	}
	if m.Widths['i'] != 600 {
		t.Errorf("Expected 'i' width 600, got %f", m.Widths['i'])
	}
}

func TestFontRegistry(t *testing.T) {
	registry := NewFontRegistry()

	font := NewStandardFont(Helvetica)
	ref := registry.Register(font)

	if ref != "F1" {
		t.Errorf("Expected ref 'F1', got '%s'", ref)
	}

	// Registering same font should return same ref
	ref2 := registry.Register(font)
	if ref2 != "F1" {
		t.Errorf("Expected same ref 'F1', got '%s'", ref2)
	}

	// Register another font
	font2 := NewStandardFont(Times)
	ref3 := registry.Register(font2)
	if ref3 != "F2" {
		t.Errorf("Expected ref 'F2', got '%s'", ref3)
	}
}

func TestFontRegistryGet(t *testing.T) {
	registry := NewFontRegistry()
	font := NewStandardFont(Helvetica)
	registry.Register(font)

	retrieved := registry.Get("Helvetica")
	if retrieved == nil {
		t.Error("Expected to retrieve font")
	}
	if retrieved.Name() != "Helvetica" {
		t.Errorf("Expected 'Helvetica', got '%s'", retrieved.Name())
	}

	// Non-existent
	missing := registry.Get("Arial")
	if missing != nil {
		t.Error("Expected nil for non-existent font")
	}
}

func TestFontRegistryGetByRef(t *testing.T) {
	registry := NewFontRegistry()
	font := NewStandardFont(Helvetica)
	registry.Register(font)

	retrieved := registry.GetByRef("F1")
	if retrieved == nil {
		t.Error("Expected to retrieve font by ref")
	}
	if retrieved.Name() != "Helvetica" {
		t.Errorf("Expected 'Helvetica', got '%s'", retrieved.Name())
	}
}

func TestFontRegistryAll(t *testing.T) {
	registry := NewFontRegistry()
	registry.Register(NewStandardFont(Helvetica))
	registry.Register(NewStandardFont(Times))

	all := registry.All()
	if len(all) != 2 {
		t.Errorf("Expected 2 fonts, got %d", len(all))
	}
}

func TestTextLayout(t *testing.T) {
	font := NewStandardFont(Helvetica)
	layout := NewTextLayout(font, 12)

	if layout.FontSize != 12 {
		t.Errorf("Expected fontSize 12, got %f", layout.FontSize)
	}
	if layout.Font != font {
		t.Error("Font mismatch")
	}
}

func TestTextLayoutMeasureString(t *testing.T) {
	font := NewStandardFont(Helvetica)
	layout := NewTextLayout(font, 10)

	// "A" at 10pt with width 667 = 667 * 10 / 1000 = 6.67
	width := layout.MeasureString("A")
	expected := 667.0 * 10.0 / 1000.0
	if width != expected {
		t.Errorf("Expected width %f, got %f", expected, width)
	}
}

func TestTextLayoutMeasureLines(t *testing.T) {
	font := NewStandardFont(Helvetica)
	layout := NewTextLayout(font, 12)

	// Single line
	height := layout.MeasureLines([]string{"Test"})
	lineHeight := font.Metrics().GetLineHeight(12)
	if height != lineHeight {
		t.Errorf("Expected height %f, got %f", lineHeight, height)
	}

	// Two lines
	height = layout.MeasureLines([]string{"Line1", "Line2"})
	expected := 2 * lineHeight
	if height != expected {
		t.Errorf("Expected height %f, got %f", expected, height)
	}
}

func TestTextLayoutWrapText(t *testing.T) {
	font := NewStandardFont(Helvetica)
	layout := NewTextLayout(font, 10)

	lines := layout.WrapText("Hello World Test", 50)
	if len(lines) < 2 {
		t.Errorf("Expected at least 2 lines for narrow width")
	}

	// Very wide - should be single line
	lines = layout.WrapText("Hello World", 1000)
	if len(lines) != 1 {
		t.Errorf("Expected 1 line for wide width, got %d", len(lines))
	}

	// Empty text
	lines = layout.WrapText("", 100)
	if len(lines) != 0 {
		t.Errorf("Expected 0 lines for empty text")
	}
}

func TestCalculateFontHash(t *testing.T) {
	data := []byte("test font data")
	hash := CalculateFontHash(data)

	if len(hash) != 16 {
		t.Errorf("Expected 16 character hash, got %d", len(hash))
	}

	// Same data should produce same hash
	hash2 := CalculateFontHash(data)
	if hash != hash2 {
		t.Error("Same data should produce same hash")
	}

	// Different data should produce different hash
	hash3 := CalculateFontHash([]byte("other data"))
	if hash == hash3 {
		t.Error("Different data should produce different hash")
	}
}

func TestTrueTypeFontInvalidData(t *testing.T) {
	_, err := LoadTrueTypeFont("test", []byte{1, 2, 3})
	if err != ErrInvalidFont {
		t.Errorf("Expected ErrInvalidFont, got %v", err)
	}
}

func TestTrueTypeFontUnsupportedFormat(t *testing.T) {
	data := []byte("xxxx" + strings.Repeat("\x00", 20))
	_, err := LoadTrueTypeFont("test", data)
	if err != ErrUnsupportedFormat {
		t.Errorf("Expected ErrUnsupportedFormat, got %v", err)
	}
}

// Helper to create minimal TrueType font data for testing
func createMinimalTTF() []byte {
	data := make([]byte, 200)

	// Header (offset 0)
	data[0] = 0x00
	data[1] = 0x01
	data[2] = 0x00
	data[3] = 0x00 // version
	data[4] = 0x00
	data[5] = 0x02 // numTables = 2
	data[6] = 0x00
	data[7] = 0x20 // searchRange
	data[8] = 0x00
	data[9] = 0x01 // entrySelector
	data[10] = 0x00
	data[11] = 0x00 // rangeShift

	// Table directory entry 1: head (offset 12)
	copy(data[12:16], []byte("head"))
	data[16] = 0x00
	data[17] = 0x00
	data[18] = 0x00
	data[19] = 0x00 // checksum
	data[20] = 0x00
	data[21] = 0x00
	data[22] = 0x00
	data[23] = 0x3C // offset = 60
	data[24] = 0x00
	data[25] = 0x00
	data[26] = 0x00
	data[27] = 0x36 // length = 54

	// Table directory entry 2: hhea (offset 28)
	copy(data[28:32], []byte("hhea"))
	data[32] = 0x00
	data[33] = 0x00
	data[34] = 0x00
	data[35] = 0x00 // checksum
	data[36] = 0x00
	data[37] = 0x00
	data[38] = 0x00
	data[39] = 0x72 // offset = 114
	data[40] = 0x00
	data[41] = 0x00
	data[42] = 0x00
	data[43] = 0x24 // length = 36

	// head table (offset 60, 54 bytes)
	// unitsPerEm at offset 18 within head = data[78:80]
	data[78] = 0x03
	data[79] = 0xE8 // 1000

	// hhea table (offset 114, 36 bytes)
	// ascender at offset 4 within hhea = data[118:120]
	data[118] = 0x03
	data[119] = 0x20 // 800
	// descender at offset 6 within hhea = data[120:122]
	data[120] = 0xFF
	data[121] = 0x38 // -200

	return data
}

func TestLoadTrueTypeFont(t *testing.T) {
	data := createMinimalTTF()
	font, err := LoadTrueTypeFont("TestFont", data)
	if err != nil {
		t.Fatalf("LoadTrueTypeFont failed: %v", err)
	}

	if font.Name() != "TestFont" {
		t.Errorf("Expected name 'TestFont', got '%s'", font.Name())
	}
	if font.Type() != FontTypeTrueType {
		t.Errorf("Expected TrueType, got %s", font.Type())
	}

	m := font.Metrics()
	if m.UnitsPerEm != 1000 {
		t.Errorf("Expected UnitsPerEm 1000, got %f", m.UnitsPerEm)
	}
}

func TestLoadFont(t *testing.T) {
	data := createMinimalTTF()
	reader := bytes.NewReader(data)

	font, err := LoadFont("TestFont", reader)
	if err != nil {
		t.Fatalf("LoadFont failed: %v", err)
	}
	if font.Name() != "TestFont" {
		t.Errorf("Expected name 'TestFont', got '%s'", font.Name())
	}
}

func TestLoadFontUnsupported(t *testing.T) {
	reader := bytes.NewReader([]byte("not a font"))
	_, err := LoadFont("test", reader)
	if err != ErrUnsupportedFormat {
		t.Errorf("Expected ErrUnsupportedFormat, got %v", err)
	}
}

func TestTrueTypeFontEncode(t *testing.T) {
	data := createMinimalTTF()
	font, err := LoadTrueTypeFont("TestFont", data)
	if err != nil {
		t.Fatalf("LoadTrueTypeFont failed: %v", err)
	}

	// Without cmap, encoding will produce zeros
	encoded := font.Encode("A")
	if len(encoded) != 2 {
		t.Errorf("Expected 2 bytes, got %d", len(encoded))
	}
}

func TestTrueTypeFontData(t *testing.T) {
	data := createMinimalTTF()
	font, err := LoadTrueTypeFont("TestFont", data)
	if err != nil {
		t.Fatalf("LoadTrueTypeFont failed: %v", err)
	}

	if !bytes.Equal(font.Data(), data) {
		t.Error("Data() should return original data")
	}
}

func TestTrueTypeFontDescriptor(t *testing.T) {
	data := createMinimalTTF()
	font, err := LoadTrueTypeFont("TestFont", data)
	if err != nil {
		t.Fatalf("LoadTrueTypeFont failed: %v", err)
	}

	desc := font.FontDescriptor()
	if desc["Type"] != "FontDescriptor" {
		t.Error("Expected Type=FontDescriptor")
	}
	if desc["FontName"] != "TestFont" {
		t.Error("Expected FontName=TestFont")
	}
}

func TestFontTypesString(t *testing.T) {
	if FontTypeType1 != "Type1" {
		t.Error("FontTypeType1 should be 'Type1'")
	}
	if FontTypeTrueType != "TrueType" {
		t.Error("FontTypeTrueType should be 'TrueType'")
	}
	if FontTypeType0 != "Type0" {
		t.Error("FontTypeType0 should be 'Type0'")
	}
	if FontTypeCIDFont != "CIDFontType2" {
		t.Error("FontTypeCIDFont should be 'CIDFontType2'")
	}
}

func TestFontMetricsFlags(t *testing.T) {
	courier := NewStandardFont(Courier)
	if courier.Metrics().Flags&1 == 0 {
		t.Error("Courier should have FixedPitch flag")
	}

	symbol := NewStandardFont(Symbol)
	if symbol.Metrics().Flags&4 == 0 {
		t.Error("Symbol should have Symbolic flag")
	}
}

func repeatString(s string, n int) string {
	var buf bytes.Buffer
	for i := 0; i < n; i++ {
		buf.WriteString(s)
	}
	return buf.String()
}
