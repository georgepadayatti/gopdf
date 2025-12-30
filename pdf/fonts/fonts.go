// Package fonts provides PDF font handling.
package fonts

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Common errors
var (
	ErrInvalidFont       = errors.New("invalid font data")
	ErrFontNotFound      = errors.New("font not found")
	ErrGlyphNotFound     = errors.New("glyph not found")
	ErrUnsupportedFormat = errors.New("unsupported font format")
)

// FontType represents the type of a PDF font.
type FontType string

const (
	FontTypeType1    FontType = "Type1"
	FontTypeTrueType FontType = "TrueType"
	FontTypeType0    FontType = "Type0"
	FontTypeCIDFont  FontType = "CIDFontType2"
)

// StandardFont represents a PDF standard font name.
type StandardFont string

// Standard 14 fonts available in all PDF readers
const (
	Helvetica            StandardFont = "Helvetica"
	HelveticaBold        StandardFont = "Helvetica-Bold"
	HelveticaOblique     StandardFont = "Helvetica-Oblique"
	HelveticaBoldOblique StandardFont = "Helvetica-BoldOblique"
	Times                StandardFont = "Times-Roman"
	TimesBold            StandardFont = "Times-Bold"
	TimesItalic          StandardFont = "Times-Italic"
	TimesBoldItalic      StandardFont = "Times-BoldItalic"
	Courier              StandardFont = "Courier"
	CourierBold          StandardFont = "Courier-Bold"
	CourierOblique       StandardFont = "Courier-Oblique"
	CourierBoldOblique   StandardFont = "Courier-BoldOblique"
	Symbol               StandardFont = "Symbol"
	ZapfDingbats         StandardFont = "ZapfDingbats"
)

// IsStandardFont checks if a font name is a standard font.
func IsStandardFont(name string) bool {
	switch StandardFont(name) {
	case Helvetica, HelveticaBold, HelveticaOblique, HelveticaBoldOblique,
		Times, TimesBold, TimesItalic, TimesBoldItalic,
		Courier, CourierBold, CourierOblique, CourierBoldOblique,
		Symbol, ZapfDingbats:
		return true
	}
	return false
}

// FontMetrics holds font metrics for text layout.
type FontMetrics struct {
	// Ascender height above baseline
	Ascender float64
	// Descender depth below baseline
	Descender float64
	// Line gap between lines
	LineGap float64
	// Units per em
	UnitsPerEm float64
	// Character widths (indexed by character code or glyph ID)
	Widths map[rune]float64
	// Default width for missing glyphs
	DefaultWidth float64
	// Font bounding box [xMin, yMin, xMax, yMax]
	BBox [4]float64
	// Italic angle
	ItalicAngle float64
	// Cap height
	CapHeight float64
	// X height
	XHeight float64
	// Stem width
	StemV float64
	// Flags
	Flags int
}

// NewFontMetrics creates new font metrics with defaults.
func NewFontMetrics() *FontMetrics {
	return &FontMetrics{
		Ascender:     800,
		Descender:    -200,
		LineGap:      0,
		UnitsPerEm:   1000,
		Widths:       make(map[rune]float64),
		DefaultWidth: 600,
		BBox:         [4]float64{0, -200, 1000, 800},
		CapHeight:    700,
		XHeight:      500,
		StemV:        80,
	}
}

// GetWidth returns the width of a character.
func (m *FontMetrics) GetWidth(r rune) float64 {
	if w, ok := m.Widths[r]; ok {
		return w
	}
	return m.DefaultWidth
}

// GetStringWidth calculates the width of a string at a given font size.
func (m *FontMetrics) GetStringWidth(s string, fontSize float64) float64 {
	var width float64
	for _, r := range s {
		width += m.GetWidth(r)
	}
	return width * fontSize / m.UnitsPerEm
}

// GetLineHeight returns the line height at a given font size.
func (m *FontMetrics) GetLineHeight(fontSize float64) float64 {
	return (m.Ascender - m.Descender + m.LineGap) * fontSize / m.UnitsPerEm
}

// Font represents a font that can be used in PDF documents.
type Font interface {
	// Name returns the font name.
	Name() string
	// Type returns the font type.
	Type() FontType
	// Metrics returns the font metrics.
	Metrics() *FontMetrics
	// Encode encodes a string for use in a PDF content stream.
	Encode(s string) []byte
	// EncodeToGlyphs encodes a string to glyph IDs.
	EncodeToGlyphs(s string) []uint16
}

// StandardType1Font represents a standard Type 1 font.
type StandardType1Font struct {
	name    StandardFont
	metrics *FontMetrics
}

// NewStandardFont creates a new standard font.
func NewStandardFont(name StandardFont) *StandardType1Font {
	f := &StandardType1Font{
		name:    name,
		metrics: getStandardFontMetrics(name),
	}
	return f
}

// Name returns the font name.
func (f *StandardType1Font) Name() string {
	return string(f.name)
}

// Type returns the font type.
func (f *StandardType1Font) Type() FontType {
	return FontTypeType1
}

// Metrics returns the font metrics.
func (f *StandardType1Font) Metrics() *FontMetrics {
	return f.metrics
}

// Encode encodes a string for use in a PDF content stream.
func (f *StandardType1Font) Encode(s string) []byte {
	// Standard fonts use WinAnsiEncoding by default
	return encodeWinAnsi(s)
}

// EncodeToGlyphs encodes a string to glyph IDs (same as char codes for Type1).
func (f *StandardType1Font) EncodeToGlyphs(s string) []uint16 {
	glyphs := make([]uint16, 0, len(s))
	for _, r := range s {
		if r < 256 {
			glyphs = append(glyphs, uint16(r))
		} else {
			glyphs = append(glyphs, 0) // Replacement
		}
	}
	return glyphs
}

// getStandardFontMetrics returns metrics for standard fonts.
func getStandardFontMetrics(name StandardFont) *FontMetrics {
	metrics := NewFontMetrics()

	// Set font-specific metrics
	switch name {
	case Helvetica, HelveticaBold, HelveticaOblique, HelveticaBoldOblique:
		metrics.Ascender = 718
		metrics.Descender = -207
		metrics.BBox = [4]float64{-166, -225, 1000, 931}
		metrics.CapHeight = 718
		metrics.XHeight = 523
		metrics.StemV = 88
		if name == HelveticaBold || name == HelveticaBoldOblique {
			metrics.StemV = 140
		}
		// Set widths for common characters
		setHelveticaWidths(metrics.Widths, name == HelveticaBold || name == HelveticaBoldOblique)

	case Times, TimesBold, TimesItalic, TimesBoldItalic:
		metrics.Ascender = 683
		metrics.Descender = -217
		metrics.BBox = [4]float64{-168, -218, 1000, 898}
		metrics.CapHeight = 662
		metrics.XHeight = 450
		metrics.StemV = 84
		if name == TimesBold || name == TimesBoldItalic {
			metrics.StemV = 121
		}
		setTimesWidths(metrics.Widths, name == TimesBold || name == TimesBoldItalic)

	case Courier, CourierBold, CourierOblique, CourierBoldOblique:
		metrics.Ascender = 629
		metrics.Descender = -157
		metrics.BBox = [4]float64{-23, -250, 715, 805}
		metrics.CapHeight = 562
		metrics.XHeight = 426
		metrics.StemV = 51
		metrics.DefaultWidth = 600
		// Courier is monospace - all characters are 600 units
		metrics.Flags |= 1 // FixedPitch
		for i := 32; i < 256; i++ {
			metrics.Widths[rune(i)] = 600
		}

	case Symbol:
		metrics.Ascender = 800
		metrics.Descender = -200
		metrics.BBox = [4]float64{-180, -293, 1090, 1010}
		metrics.CapHeight = 800
		metrics.Flags |= 4 // Symbolic

	case ZapfDingbats:
		metrics.Ascender = 800
		metrics.Descender = -200
		metrics.BBox = [4]float64{-1, -143, 981, 820}
		metrics.CapHeight = 800
		metrics.Flags |= 4 // Symbolic
	}

	return metrics
}

// setHelveticaWidths sets character widths for Helvetica.
func setHelveticaWidths(widths map[rune]float64, bold bool) {
	// Common character widths for Helvetica
	if bold {
		widths[' '] = 278
		widths['!'] = 333
		widths['"'] = 474
		widths['#'] = 556
		widths['$'] = 556
		widths['%'] = 889
		widths['&'] = 722
		widths['\''] = 238
		widths['('] = 333
		widths[')'] = 333
		widths['*'] = 389
		widths['+'] = 584
		widths[','] = 278
		widths['-'] = 333
		widths['.'] = 278
		widths['/'] = 278
		for i := '0'; i <= '9'; i++ {
			widths[i] = 556
		}
		widths[':'] = 333
		widths[';'] = 333
		widths['<'] = 584
		widths['='] = 584
		widths['>'] = 584
		widths['?'] = 611
		widths['@'] = 975
		// Uppercase
		widths['A'] = 722
		widths['B'] = 722
		widths['C'] = 722
		widths['D'] = 722
		widths['E'] = 667
		widths['F'] = 611
		widths['G'] = 778
		widths['H'] = 722
		widths['I'] = 278
		widths['J'] = 556
		widths['K'] = 722
		widths['L'] = 611
		widths['M'] = 833
		widths['N'] = 722
		widths['O'] = 778
		widths['P'] = 667
		widths['Q'] = 778
		widths['R'] = 722
		widths['S'] = 667
		widths['T'] = 611
		widths['U'] = 722
		widths['V'] = 667
		widths['W'] = 944
		widths['X'] = 667
		widths['Y'] = 667
		widths['Z'] = 611
		// Lowercase
		widths['a'] = 556
		widths['b'] = 611
		widths['c'] = 556
		widths['d'] = 611
		widths['e'] = 556
		widths['f'] = 333
		widths['g'] = 611
		widths['h'] = 611
		widths['i'] = 278
		widths['j'] = 278
		widths['k'] = 556
		widths['l'] = 278
		widths['m'] = 889
		widths['n'] = 611
		widths['o'] = 611
		widths['p'] = 611
		widths['q'] = 611
		widths['r'] = 389
		widths['s'] = 556
		widths['t'] = 333
		widths['u'] = 611
		widths['v'] = 556
		widths['w'] = 778
		widths['x'] = 556
		widths['y'] = 556
		widths['z'] = 500
	} else {
		widths[' '] = 278
		widths['!'] = 278
		widths['"'] = 355
		widths['#'] = 556
		widths['$'] = 556
		widths['%'] = 889
		widths['&'] = 667
		widths['\''] = 191
		widths['('] = 333
		widths[')'] = 333
		widths['*'] = 389
		widths['+'] = 584
		widths[','] = 278
		widths['-'] = 333
		widths['.'] = 278
		widths['/'] = 278
		for i := '0'; i <= '9'; i++ {
			widths[i] = 556
		}
		widths[':'] = 278
		widths[';'] = 278
		widths['<'] = 584
		widths['='] = 584
		widths['>'] = 584
		widths['?'] = 556
		widths['@'] = 1015
		// Uppercase
		widths['A'] = 667
		widths['B'] = 667
		widths['C'] = 722
		widths['D'] = 722
		widths['E'] = 667
		widths['F'] = 611
		widths['G'] = 778
		widths['H'] = 722
		widths['I'] = 278
		widths['J'] = 500
		widths['K'] = 667
		widths['L'] = 556
		widths['M'] = 833
		widths['N'] = 722
		widths['O'] = 778
		widths['P'] = 667
		widths['Q'] = 778
		widths['R'] = 722
		widths['S'] = 667
		widths['T'] = 611
		widths['U'] = 722
		widths['V'] = 667
		widths['W'] = 944
		widths['X'] = 667
		widths['Y'] = 667
		widths['Z'] = 611
		// Lowercase
		widths['a'] = 556
		widths['b'] = 556
		widths['c'] = 500
		widths['d'] = 556
		widths['e'] = 556
		widths['f'] = 278
		widths['g'] = 556
		widths['h'] = 556
		widths['i'] = 222
		widths['j'] = 222
		widths['k'] = 500
		widths['l'] = 222
		widths['m'] = 833
		widths['n'] = 556
		widths['o'] = 556
		widths['p'] = 556
		widths['q'] = 556
		widths['r'] = 333
		widths['s'] = 500
		widths['t'] = 278
		widths['u'] = 556
		widths['v'] = 500
		widths['w'] = 722
		widths['x'] = 500
		widths['y'] = 500
		widths['z'] = 500
	}
}

// setTimesWidths sets character widths for Times.
func setTimesWidths(widths map[rune]float64, bold bool) {
	if bold {
		widths[' '] = 250
		widths['!'] = 333
		widths['"'] = 555
		widths['#'] = 500
		widths['$'] = 500
		widths['%'] = 1000
		widths['&'] = 833
		widths['\''] = 278
		widths['('] = 333
		widths[')'] = 333
		widths['*'] = 500
		widths['+'] = 570
		widths[','] = 250
		widths['-'] = 333
		widths['.'] = 250
		widths['/'] = 278
		for i := '0'; i <= '9'; i++ {
			widths[i] = 500
		}
		widths[':'] = 333
		widths[';'] = 333
		widths['<'] = 570
		widths['='] = 570
		widths['>'] = 570
		widths['?'] = 500
		widths['@'] = 930
		// Uppercase
		widths['A'] = 722
		widths['B'] = 667
		widths['C'] = 722
		widths['D'] = 722
		widths['E'] = 667
		widths['F'] = 611
		widths['G'] = 778
		widths['H'] = 778
		widths['I'] = 389
		widths['J'] = 500
		widths['K'] = 778
		widths['L'] = 667
		widths['M'] = 944
		widths['N'] = 722
		widths['O'] = 778
		widths['P'] = 611
		widths['Q'] = 778
		widths['R'] = 722
		widths['S'] = 556
		widths['T'] = 667
		widths['U'] = 722
		widths['V'] = 722
		widths['W'] = 1000
		widths['X'] = 722
		widths['Y'] = 722
		widths['Z'] = 667
		// Lowercase
		widths['a'] = 500
		widths['b'] = 556
		widths['c'] = 444
		widths['d'] = 556
		widths['e'] = 444
		widths['f'] = 333
		widths['g'] = 500
		widths['h'] = 556
		widths['i'] = 278
		widths['j'] = 333
		widths['k'] = 556
		widths['l'] = 278
		widths['m'] = 833
		widths['n'] = 556
		widths['o'] = 500
		widths['p'] = 556
		widths['q'] = 556
		widths['r'] = 444
		widths['s'] = 389
		widths['t'] = 333
		widths['u'] = 556
		widths['v'] = 500
		widths['w'] = 722
		widths['x'] = 500
		widths['y'] = 500
		widths['z'] = 444
	} else {
		widths[' '] = 250
		widths['!'] = 333
		widths['"'] = 408
		widths['#'] = 500
		widths['$'] = 500
		widths['%'] = 833
		widths['&'] = 778
		widths['\''] = 180
		widths['('] = 333
		widths[')'] = 333
		widths['*'] = 500
		widths['+'] = 564
		widths[','] = 250
		widths['-'] = 333
		widths['.'] = 250
		widths['/'] = 278
		for i := '0'; i <= '9'; i++ {
			widths[i] = 500
		}
		widths[':'] = 278
		widths[';'] = 278
		widths['<'] = 564
		widths['='] = 564
		widths['>'] = 564
		widths['?'] = 444
		widths['@'] = 921
		// Uppercase
		widths['A'] = 722
		widths['B'] = 667
		widths['C'] = 667
		widths['D'] = 722
		widths['E'] = 611
		widths['F'] = 556
		widths['G'] = 722
		widths['H'] = 722
		widths['I'] = 333
		widths['J'] = 389
		widths['K'] = 722
		widths['L'] = 611
		widths['M'] = 889
		widths['N'] = 722
		widths['O'] = 722
		widths['P'] = 556
		widths['Q'] = 722
		widths['R'] = 667
		widths['S'] = 556
		widths['T'] = 611
		widths['U'] = 722
		widths['V'] = 722
		widths['W'] = 944
		widths['X'] = 722
		widths['Y'] = 722
		widths['Z'] = 611
		// Lowercase
		widths['a'] = 444
		widths['b'] = 500
		widths['c'] = 444
		widths['d'] = 500
		widths['e'] = 444
		widths['f'] = 333
		widths['g'] = 500
		widths['h'] = 500
		widths['i'] = 278
		widths['j'] = 278
		widths['k'] = 500
		widths['l'] = 278
		widths['m'] = 778
		widths['n'] = 500
		widths['o'] = 500
		widths['p'] = 500
		widths['q'] = 500
		widths['r'] = 333
		widths['s'] = 389
		widths['t'] = 278
		widths['u'] = 500
		widths['v'] = 500
		widths['w'] = 722
		widths['x'] = 500
		widths['y'] = 500
		widths['z'] = 444
	}
}

// winAnsiMap maps Unicode code points to Windows-1252 encoding.
var winAnsiMap = map[rune]byte{
	0x20AC: 0x80, // €
	0x201A: 0x82, // ‚
	0x0192: 0x83, // ƒ
	0x201E: 0x84, // „
	0x2026: 0x85, // …
	0x2020: 0x86, // †
	0x2021: 0x87, // ‡
	0x02C6: 0x88, // ˆ
	0x2030: 0x89, // ‰
	0x0160: 0x8A, // Š
	0x2039: 0x8B, // ‹
	0x0152: 0x8C, // Œ
	0x017D: 0x8E, // Ž
	0x2018: 0x91, // '
	0x2019: 0x92, // '
	0x201C: 0x93, // "
	0x201D: 0x94, // "
	0x2022: 0x95, // •
	0x2013: 0x96, // –
	0x2014: 0x97, // —
	0x02DC: 0x98, // ˜
	0x2122: 0x99, // ™
	0x0161: 0x9A, // š
	0x203A: 0x9B, // ›
	0x0153: 0x9C, // œ
	0x017E: 0x9E, // ž
	0x0178: 0x9F, // Ÿ
}

// encodeWinAnsi encodes a string to Windows-1252 encoding.
func encodeWinAnsi(s string) []byte {
	var buf bytes.Buffer
	for _, r := range s {
		if r < 128 {
			buf.WriteByte(byte(r))
		} else if b, ok := winAnsiMap[r]; ok {
			buf.WriteByte(b)
		} else if r >= 0xA0 && r <= 0xFF {
			buf.WriteByte(byte(r))
		} else {
			buf.WriteByte('?') // Replacement
		}
	}
	return buf.Bytes()
}

// TrueTypeFont represents an embedded TrueType font.
type TrueTypeFont struct {
	name        string
	data        []byte
	metrics     *FontMetrics
	cmap        map[rune]uint16 // Unicode to glyph ID
	glyphWidths map[uint16]float64
}

// LoadTrueTypeFont loads a TrueType font from data.
func LoadTrueTypeFont(name string, data []byte) (*TrueTypeFont, error) {
	if len(data) < 12 {
		return nil, ErrInvalidFont
	}

	// Check for TrueType signature
	if string(data[0:4]) != "\x00\x01\x00\x00" && string(data[0:4]) != "true" && string(data[0:4]) != "OTTO" {
		return nil, ErrUnsupportedFormat
	}

	f := &TrueTypeFont{
		name:        name,
		data:        data,
		metrics:     NewFontMetrics(),
		cmap:        make(map[rune]uint16),
		glyphWidths: make(map[uint16]float64),
	}

	// Parse font tables
	if err := f.parseTables(); err != nil {
		return nil, err
	}

	return f, nil
}

// parseTables parses the TrueType font tables.
func (f *TrueTypeFont) parseTables() error {
	if len(f.data) < 12 {
		return ErrInvalidFont
	}

	numTables := int(binary.BigEndian.Uint16(f.data[4:6]))

	tables := make(map[string]tableEntry)
	offset := 12
	for i := 0; i < numTables && offset+16 <= len(f.data); i++ {
		tag := string(f.data[offset : offset+4])
		tables[tag] = tableEntry{
			offset: int(binary.BigEndian.Uint32(f.data[offset+8 : offset+12])),
			length: int(binary.BigEndian.Uint32(f.data[offset+12 : offset+16])),
		}
		offset += 16
	}

	// Parse head table
	if head, ok := tables["head"]; ok {
		if err := f.parseHead(head); err != nil {
			return err
		}
	}

	// Parse hhea table
	if hhea, ok := tables["hhea"]; ok {
		if err := f.parseHhea(hhea); err != nil {
			return err
		}
	}

	// Parse cmap table
	if cmap, ok := tables["cmap"]; ok {
		if err := f.parseCmap(cmap); err != nil {
			return err
		}
	}

	// Parse hmtx table
	if hmtx, ok := tables["hmtx"]; ok {
		numGlyphs := 0
		if maxp, ok := tables["maxp"]; ok && maxp.offset+6 <= len(f.data) {
			numGlyphs = int(binary.BigEndian.Uint16(f.data[maxp.offset+4 : maxp.offset+6]))
		}
		numHMetrics := 0
		if hhea, ok := tables["hhea"]; ok && hhea.offset+36 <= len(f.data) {
			numHMetrics = int(binary.BigEndian.Uint16(f.data[hhea.offset+34 : hhea.offset+36]))
		}
		if err := f.parseHmtx(hmtx, numGlyphs, numHMetrics); err != nil {
			return err
		}
	}

	// Parse OS/2 table for additional metrics
	if os2, ok := tables["OS/2"]; ok {
		f.parseOS2(os2)
	}

	return nil
}

type tableEntry struct {
	offset int
	length int
}

func (f *TrueTypeFont) parseHead(entry tableEntry) error {
	if entry.offset+54 > len(f.data) {
		return ErrInvalidFont
	}

	d := f.data[entry.offset:]
	f.metrics.UnitsPerEm = float64(binary.BigEndian.Uint16(d[18:20]))

	// BBox
	xMin := int16(binary.BigEndian.Uint16(d[36:38]))
	yMin := int16(binary.BigEndian.Uint16(d[38:40]))
	xMax := int16(binary.BigEndian.Uint16(d[40:42]))
	yMax := int16(binary.BigEndian.Uint16(d[42:44]))
	f.metrics.BBox = [4]float64{float64(xMin), float64(yMin), float64(xMax), float64(yMax)}

	return nil
}

func (f *TrueTypeFont) parseHhea(entry tableEntry) error {
	if entry.offset+36 > len(f.data) {
		return ErrInvalidFont
	}

	d := f.data[entry.offset:]
	f.metrics.Ascender = float64(int16(binary.BigEndian.Uint16(d[4:6])))
	f.metrics.Descender = float64(int16(binary.BigEndian.Uint16(d[6:8])))
	f.metrics.LineGap = float64(int16(binary.BigEndian.Uint16(d[8:10])))

	return nil
}

func (f *TrueTypeFont) parseCmap(entry tableEntry) error {
	if entry.offset+4 > len(f.data) {
		return ErrInvalidFont
	}

	d := f.data[entry.offset:]
	numTables := int(binary.BigEndian.Uint16(d[2:4]))

	// Find Unicode cmap subtable
	var subtableOffset int
	for i := 0; i < numTables && 4+i*8+8 <= len(d); i++ {
		platformID := binary.BigEndian.Uint16(d[4+i*8 : 4+i*8+2])
		encodingID := binary.BigEndian.Uint16(d[4+i*8+2 : 4+i*8+4])
		offset := int(binary.BigEndian.Uint32(d[4+i*8+4 : 4+i*8+8]))

		// Prefer Windows Unicode BMP (3, 1) or Unicode (0, 3)
		if (platformID == 3 && encodingID == 1) || (platformID == 0 && encodingID == 3) {
			subtableOffset = offset
			break
		}
		// Fallback to any Unicode
		if platformID == 0 || (platformID == 3 && encodingID == 1) {
			subtableOffset = offset
		}
	}

	if subtableOffset == 0 {
		return nil // No Unicode cmap found
	}

	if entry.offset+subtableOffset+6 > len(f.data) {
		return ErrInvalidFont
	}

	subtable := f.data[entry.offset+subtableOffset:]
	format := binary.BigEndian.Uint16(subtable[0:2])

	switch format {
	case 4:
		return f.parseCmapFormat4(subtable)
	case 12:
		return f.parseCmapFormat12(subtable)
	}

	return nil
}

func (f *TrueTypeFont) parseCmapFormat4(data []byte) error {
	if len(data) < 14 {
		return ErrInvalidFont
	}

	segCount := int(binary.BigEndian.Uint16(data[6:8])) / 2
	if len(data) < 14+segCount*8 {
		return nil
	}

	endCodes := data[14 : 14+segCount*2]
	startCodes := data[16+segCount*2 : 16+segCount*4]
	idDeltas := data[16+segCount*4 : 16+segCount*6]
	idRangeOffsets := data[16+segCount*6 : 16+segCount*8]

	for i := 0; i < segCount; i++ {
		endCode := int(binary.BigEndian.Uint16(endCodes[i*2 : i*2+2]))
		startCode := int(binary.BigEndian.Uint16(startCodes[i*2 : i*2+2]))
		idDelta := int(int16(binary.BigEndian.Uint16(idDeltas[i*2 : i*2+2])))
		idRangeOffset := int(binary.BigEndian.Uint16(idRangeOffsets[i*2 : i*2+2]))

		if startCode == 0xFFFF {
			break
		}

		for c := startCode; c <= endCode; c++ {
			var glyphID uint16
			if idRangeOffset == 0 {
				glyphID = uint16((c + idDelta) & 0xFFFF)
			} else {
				idx := idRangeOffset/2 + (c - startCode) + i - segCount
				if idx*2+2 <= len(idRangeOffsets) {
					glyphID = binary.BigEndian.Uint16(idRangeOffsets[idx*2 : idx*2+2])
					if glyphID != 0 {
						glyphID = uint16((int(glyphID) + idDelta) & 0xFFFF)
					}
				}
			}
			f.cmap[rune(c)] = glyphID
		}
	}

	return nil
}

func (f *TrueTypeFont) parseCmapFormat12(data []byte) error {
	if len(data) < 16 {
		return ErrInvalidFont
	}

	numGroups := int(binary.BigEndian.Uint32(data[12:16]))

	for i := 0; i < numGroups && 16+i*12+12 <= len(data); i++ {
		startCharCode := binary.BigEndian.Uint32(data[16+i*12 : 16+i*12+4])
		endCharCode := binary.BigEndian.Uint32(data[16+i*12+4 : 16+i*12+8])
		startGlyphID := binary.BigEndian.Uint32(data[16+i*12+8 : 16+i*12+12])

		for c := startCharCode; c <= endCharCode; c++ {
			f.cmap[rune(c)] = uint16(startGlyphID + (c - startCharCode))
		}
	}

	return nil
}

func (f *TrueTypeFont) parseHmtx(entry tableEntry, numGlyphs, numHMetrics int) error {
	d := f.data[entry.offset:]

	// Parse horizontal metrics
	for i := 0; i < numHMetrics && i*4+2 <= len(d); i++ {
		advanceWidth := binary.BigEndian.Uint16(d[i*4 : i*4+2])
		f.glyphWidths[uint16(i)] = float64(advanceWidth)
	}

	// Remaining glyphs use last advance width
	if numHMetrics > 0 && numHMetrics*4-2 >= 0 && numHMetrics*4 <= len(d) {
		lastWidth := float64(binary.BigEndian.Uint16(d[(numHMetrics-1)*4 : (numHMetrics-1)*4+2]))
		for i := numHMetrics; i < numGlyphs; i++ {
			f.glyphWidths[uint16(i)] = lastWidth
		}
	}

	// Build character widths map
	for r, glyphID := range f.cmap {
		if w, ok := f.glyphWidths[glyphID]; ok {
			f.metrics.Widths[r] = w
		}
	}

	return nil
}

func (f *TrueTypeFont) parseOS2(entry tableEntry) {
	if entry.offset+88 > len(f.data) {
		return
	}

	d := f.data[entry.offset:]

	// Cap height and x-height (version 2+)
	if len(d) >= 88 {
		f.metrics.CapHeight = float64(int16(binary.BigEndian.Uint16(d[86:88])))
	}
	if len(d) >= 90 {
		f.metrics.XHeight = float64(int16(binary.BigEndian.Uint16(d[88:90])))
	}

	// Typographic ascender/descender
	if len(d) >= 72 {
		typoAscender := float64(int16(binary.BigEndian.Uint16(d[68:70])))
		typoDescender := float64(int16(binary.BigEndian.Uint16(d[70:72])))
		if typoAscender != 0 {
			f.metrics.Ascender = typoAscender
		}
		if typoDescender != 0 {
			f.metrics.Descender = typoDescender
		}
	}
}

// Name returns the font name.
func (f *TrueTypeFont) Name() string {
	return f.name
}

// Type returns the font type.
func (f *TrueTypeFont) Type() FontType {
	return FontTypeTrueType
}

// Metrics returns the font metrics.
func (f *TrueTypeFont) Metrics() *FontMetrics {
	return f.metrics
}

// Encode encodes a string for use in a PDF content stream.
func (f *TrueTypeFont) Encode(s string) []byte {
	var buf bytes.Buffer
	for _, r := range s {
		if glyphID, ok := f.cmap[r]; ok {
			buf.WriteByte(byte(glyphID >> 8))
			buf.WriteByte(byte(glyphID & 0xFF))
		} else {
			buf.WriteByte(0)
			buf.WriteByte(0)
		}
	}
	return buf.Bytes()
}

// EncodeToGlyphs encodes a string to glyph IDs.
func (f *TrueTypeFont) EncodeToGlyphs(s string) []uint16 {
	glyphs := make([]uint16, 0, len(s))
	for _, r := range s {
		if glyphID, ok := f.cmap[r]; ok {
			glyphs = append(glyphs, glyphID)
		} else {
			glyphs = append(glyphs, 0)
		}
	}
	return glyphs
}

// Data returns the raw font data.
func (f *TrueTypeFont) Data() []byte {
	return f.data
}

// FontSubset returns a subset of the font containing only the used glyphs.
func (f *TrueTypeFont) FontSubset(glyphs []uint16) ([]byte, error) {
	// For now, return the full font
	// Full subsetting would require complex table manipulation
	return f.data, nil
}

// FontDescriptor returns font descriptor values for PDF embedding.
func (f *TrueTypeFont) FontDescriptor() map[string]interface{} {
	m := f.metrics
	flags := 32 // Non-symbolic

	return map[string]interface{}{
		"Type":        "FontDescriptor",
		"FontName":    f.name,
		"Flags":       flags,
		"FontBBox":    m.BBox,
		"ItalicAngle": m.ItalicAngle,
		"Ascent":      m.Ascender * 1000 / m.UnitsPerEm,
		"Descent":     m.Descender * 1000 / m.UnitsPerEm,
		"CapHeight":   m.CapHeight * 1000 / m.UnitsPerEm,
		"XHeight":     m.XHeight * 1000 / m.UnitsPerEm,
		"StemV":       m.StemV,
	}
}

// FontRegistry manages fonts for a document.
type FontRegistry struct {
	fonts    map[string]Font
	fontRefs map[string]string // font name -> PDF resource name
	nextRef  int
}

// NewFontRegistry creates a new font registry.
func NewFontRegistry() *FontRegistry {
	return &FontRegistry{
		fonts:    make(map[string]Font),
		fontRefs: make(map[string]string),
		nextRef:  1,
	}
}

// Register registers a font and returns its PDF resource name.
func (r *FontRegistry) Register(font Font) string {
	name := font.Name()
	if ref, ok := r.fontRefs[name]; ok {
		return ref
	}

	ref := fmt.Sprintf("F%d", r.nextRef)
	r.nextRef++
	r.fonts[name] = font
	r.fontRefs[name] = ref
	return ref
}

// Get retrieves a font by name.
func (r *FontRegistry) Get(name string) Font {
	return r.fonts[name]
}

// GetByRef retrieves a font by PDF resource name.
func (r *FontRegistry) GetByRef(ref string) Font {
	for name, fontRef := range r.fontRefs {
		if fontRef == ref {
			return r.fonts[name]
		}
	}
	return nil
}

// All returns all registered fonts.
func (r *FontRegistry) All() map[string]Font {
	return r.fonts
}

// FontRefs returns the font reference mapping.
func (r *FontRegistry) FontRefs() map[string]string {
	return r.fontRefs
}

// TextLayout provides text layout utilities.
type TextLayout struct {
	Font     Font
	FontSize float64
	LineGap  float64
}

// NewTextLayout creates a new text layout.
func NewTextLayout(font Font, fontSize float64) *TextLayout {
	return &TextLayout{
		Font:     font,
		FontSize: fontSize,
		LineGap:  0,
	}
}

// MeasureString measures the width of a string.
func (l *TextLayout) MeasureString(s string) float64 {
	return l.Font.Metrics().GetStringWidth(s, l.FontSize)
}

// MeasureLines measures the height of multiple lines.
func (l *TextLayout) MeasureLines(lines []string) float64 {
	if len(lines) == 0 {
		return 0
	}
	lineHeight := l.Font.Metrics().GetLineHeight(l.FontSize)
	return float64(len(lines))*lineHeight + float64(len(lines)-1)*l.LineGap
}

// WrapText wraps text to fit within a width.
func (l *TextLayout) WrapText(text string, maxWidth float64) []string {
	var lines []string
	words := strings.Fields(text)

	if len(words) == 0 {
		return lines
	}

	currentLine := words[0]
	for _, word := range words[1:] {
		testLine := currentLine + " " + word
		if l.MeasureString(testLine) <= maxWidth {
			currentLine = testLine
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}
	lines = append(lines, currentLine)

	return lines
}

// CalculateFontHash calculates a hash for a font (for embedding).
func CalculateFontHash(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%X", hash[:8])
}

// LoadFont loads a font from a reader.
func LoadFont(name string, r io.Reader) (Font, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Try TrueType
	if len(data) >= 4 {
		sig := string(data[0:4])
		if sig == "\x00\x01\x00\x00" || sig == "true" || sig == "OTTO" {
			return LoadTrueTypeFont(name, data)
		}
	}

	return nil, ErrUnsupportedFormat
}
