// Package barcodes provides barcode generation for PDF documents.
package barcodes

import (
	"errors"
	"fmt"
	"strings"
)

// Common errors
var (
	ErrInvalidData      = errors.New("invalid barcode data")
	ErrInvalidLength    = errors.New("invalid data length")
	ErrInvalidCharacter = errors.New("invalid character in data")
	ErrChecksumMismatch = errors.New("checksum mismatch")
	ErrUnsupportedType  = errors.New("unsupported barcode type")
)

// BarcodeType represents the type of barcode.
type BarcodeType int

const (
	TypeCode128 BarcodeType = iota
	TypeCode128A
	TypeCode128B
	TypeCode128C
	TypeCode39
	TypeCode39Extended
	TypeEAN13
	TypeEAN8
	TypeUPCA
	TypeUPCE
	TypeITF // Interleaved 2 of 5
	TypeCodabar
)

// String returns the string representation of barcode type.
func (t BarcodeType) String() string {
	switch t {
	case TypeCode128:
		return "Code128"
	case TypeCode128A:
		return "Code128A"
	case TypeCode128B:
		return "Code128B"
	case TypeCode128C:
		return "Code128C"
	case TypeCode39:
		return "Code39"
	case TypeCode39Extended:
		return "Code39Extended"
	case TypeEAN13:
		return "EAN-13"
	case TypeEAN8:
		return "EAN-8"
	case TypeUPCA:
		return "UPC-A"
	case TypeUPCE:
		return "UPC-E"
	case TypeITF:
		return "ITF"
	case TypeCodabar:
		return "Codabar"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// Barcode represents an encoded barcode.
type Barcode struct {
	Type     BarcodeType
	Data     string
	Encoded  []bool // true = bar, false = space
	Checksum int
}

// Width returns the width of the barcode in modules.
func (b *Barcode) Width() int {
	return len(b.Encoded)
}

// Pattern returns the barcode pattern as a string (1=bar, 0=space).
func (b *Barcode) Pattern() string {
	var sb strings.Builder
	for _, bar := range b.Encoded {
		if bar {
			sb.WriteByte('1')
		} else {
			sb.WriteByte('0')
		}
	}
	return sb.String()
}

// Code128 encoding tables
var (
	code128Patterns = []string{
		"11011001100", "11001101100", "11001100110", "10010011000", "10010001100", // 0-4
		"10001001100", "10011001000", "10011000100", "10001100100", "11001001000", // 5-9
		"11001000100", "11000100100", "10110011100", "10011011100", "10011001110", // 10-14
		"10111001100", "10011101100", "10011100110", "11001110010", "11001011100", // 15-19
		"11001001110", "11011100100", "11001110100", "11101101110", "11101001100", // 20-24
		"11100101100", "11100100110", "11101100100", "11100110100", "11100110010", // 25-29
		"11011011000", "11011000110", "11000110110", "10100011000", "10001011000", // 30-34
		"10001000110", "10110001000", "10001101000", "10001100010", "11010001000", // 35-39
		"11000101000", "11000100010", "10110111000", "10110001110", "10001101110", // 40-44
		"10111011000", "10111000110", "10001110110", "11101110110", "11010001110", // 45-49
		"11000101110", "11011101000", "11011100010", "11011101110", "11101011000", // 50-54
		"11101000110", "11100010110", "11101101000", "11101100010", "11100011010", // 55-59
		"11101111010", "11001000010", "11110001010", "10100110000", "10100001100", // 60-64
		"10010110000", "10010000110", "10000101100", "10000100110", "10110010000", // 65-69
		"10110000100", "10011010000", "10011000010", "10000110100", "10000110010", // 70-74
		"11000010010", "11001010000", "11110111010", "11000010100", "10001111010", // 75-79
		"10100111100", "10010111100", "10010011110", "10111100100", "10011110100", // 80-84
		"10011110010", "11110100100", "11110010100", "11110010010", "11011011110", // 85-89
		"11011110110", "11110110110", "10101111000", "10100011110", "10001011110", // 90-94
		"10111101000", "10111100010", "11110101000", "11110100010", "10111011110", // 95-99
		"10111101110", "11101011110", "11110101110", "11010000100", "11010010000", // 100-104
		"11010011100", "1100011101011", // 105-106 (STOP)
	}

	code128Start = map[byte]int{
		'A': 103, // START A
		'B': 104, // START B
		'C': 105, // START C
	}

	code128AChars = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_" + string(rune(0)) + string(rune(1)) + string(rune(2)) + string(rune(3)) + string(rune(4)) + string(rune(5)) + string(rune(6)) + string(rune(7)) + string(rune(8)) + string(rune(9)) + string(rune(10)) + string(rune(11)) + string(rune(12)) + string(rune(13)) + string(rune(14)) + string(rune(15)) + string(rune(16)) + string(rune(17)) + string(rune(18)) + string(rune(19)) + string(rune(20)) + string(rune(21)) + string(rune(22)) + string(rune(23)) + string(rune(24)) + string(rune(25)) + string(rune(26)) + string(rune(27)) + string(rune(28)) + string(rune(29)) + string(rune(30)) + string(rune(31))
	code128BChars = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~" + string(rune(127))
)

// EncodeCode128 encodes data as Code 128 barcode.
func EncodeCode128(data string) (*Barcode, error) {
	if len(data) == 0 {
		return nil, ErrInvalidData
	}

	// Determine best encoding mode
	mode := determineCode128Mode(data)
	return encodeCode128WithMode(data, mode)
}

// EncodeCode128B encodes data as Code 128B barcode.
func EncodeCode128B(data string) (*Barcode, error) {
	return encodeCode128WithMode(data, 'B')
}

// EncodeCode128C encodes data as Code 128C barcode (numeric only).
func EncodeCode128C(data string) (*Barcode, error) {
	// Validate numeric only
	for _, c := range data {
		if c < '0' || c > '9' {
			return nil, ErrInvalidCharacter
		}
	}
	if len(data)%2 != 0 {
		return nil, ErrInvalidLength
	}
	return encodeCode128WithMode(data, 'C')
}

func determineCode128Mode(data string) byte {
	// Check if all numeric
	allNumeric := true
	for _, c := range data {
		if c < '0' || c > '9' {
			allNumeric = false
			break
		}
	}
	if allNumeric && len(data) >= 2 && len(data)%2 == 0 {
		return 'C'
	}
	return 'B'
}

func encodeCode128WithMode(data string, mode byte) (*Barcode, error) {
	var encoded []bool
	var values []int

	// Add start code
	startCode := code128Start[mode]
	values = append(values, startCode)
	encoded = append(encoded, patternToBools(code128Patterns[startCode])...)

	// Encode data
	switch mode {
	case 'B':
		for _, c := range data {
			idx := strings.IndexRune(code128BChars, c)
			if idx < 0 {
				return nil, ErrInvalidCharacter
			}
			values = append(values, idx)
			encoded = append(encoded, patternToBools(code128Patterns[idx])...)
		}
	case 'C':
		for i := 0; i < len(data); i += 2 {
			val := int(data[i]-'0')*10 + int(data[i+1]-'0')
			values = append(values, val)
			encoded = append(encoded, patternToBools(code128Patterns[val])...)
		}
	}

	// Calculate checksum
	checksum := values[0]
	for i := 1; i < len(values); i++ {
		checksum += i * values[i]
	}
	checksum %= 103

	// Add checksum
	encoded = append(encoded, patternToBools(code128Patterns[checksum])...)

	// Add stop code
	encoded = append(encoded, patternToBools(code128Patterns[106])...)

	return &Barcode{
		Type:     TypeCode128,
		Data:     data,
		Encoded:  encoded,
		Checksum: checksum,
	}, nil
}

func patternToBools(pattern string) []bool {
	result := make([]bool, len(pattern))
	for i, c := range pattern {
		result[i] = c == '1'
	}
	return result
}

// Code39 encoding
var (
	code39Chars    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-. $/+%"
	code39Patterns = map[rune]string{
		'0': "101001101101", '1': "110100101011", '2': "101100101011", '3': "110110010101",
		'4': "101001101011", '5': "110100110101", '6': "101100110101", '7': "101001011011",
		'8': "110100101101", '9': "101100101101", 'A': "110101001011", 'B': "101101001011",
		'C': "110110100101", 'D': "101011001011", 'E': "110101100101", 'F': "101101100101",
		'G': "101010011011", 'H': "110101001101", 'I': "101101001101", 'J': "101011001101",
		'K': "110101010011", 'L': "101101010011", 'M': "110110101001", 'N': "101011010011",
		'O': "110101101001", 'P': "101101101001", 'Q': "101010110011", 'R': "110101011001",
		'S': "101101011001", 'T': "101011011001", 'U': "110010101011", 'V': "100110101011",
		'W': "110011010101", 'X': "100101101011", 'Y': "110010110101", 'Z': "100110110101",
		'-': "100101011011", '.': "110010101101", ' ': "100110101101", '$': "100100100101",
		'/': "100100101001", '+': "100101001001", '%': "101001001001", '*': "100101101101",
	}
)

// EncodeCode39 encodes data as Code 39 barcode.
func EncodeCode39(data string) (*Barcode, error) {
	data = strings.ToUpper(data)

	// Validate characters
	for _, c := range data {
		if _, ok := code39Patterns[c]; !ok {
			return nil, ErrInvalidCharacter
		}
	}

	var encoded []bool

	// Add start character (*)
	encoded = append(encoded, patternToBools(code39Patterns['*'])...)
	encoded = append(encoded, false) // Inter-character gap

	// Encode data
	for _, c := range data {
		encoded = append(encoded, patternToBools(code39Patterns[c])...)
		encoded = append(encoded, false) // Inter-character gap
	}

	// Add stop character (*)
	encoded = append(encoded, patternToBools(code39Patterns['*'])...)

	return &Barcode{
		Type:    TypeCode39,
		Data:    data,
		Encoded: encoded,
	}, nil
}

// EncodeCode39WithChecksum encodes data as Code 39 with checksum.
func EncodeCode39WithChecksum(data string) (*Barcode, error) {
	data = strings.ToUpper(data)

	// Calculate checksum
	sum := 0
	for _, c := range data {
		idx := strings.IndexRune(code39Chars, c)
		if idx < 0 {
			return nil, ErrInvalidCharacter
		}
		sum += idx
	}
	checkDigit := rune(code39Chars[sum%43])

	// Encode with checksum
	return EncodeCode39(data + string(checkDigit))
}

// EAN/UPC encoding
var (
	eanLPatterns = []string{
		"0001101", "0011001", "0010011", "0111101", "0100011",
		"0110001", "0101111", "0111011", "0110111", "0001011",
	}
	eanGPatterns = []string{
		"0100111", "0110011", "0011011", "0100001", "0011101",
		"0111001", "0000101", "0010001", "0001001", "0010111",
	}
	eanRPatterns = []string{
		"1110010", "1100110", "1101100", "1000010", "1011100",
		"1001110", "1010000", "1000100", "1001000", "1110100",
	}
	ean13Parity = []string{
		"LLLLLL", "LLGLGG", "LLGGLG", "LLGGGL", "LGLLGG",
		"LGGLLG", "LGGGLL", "LGLGLG", "LGLGGL", "LGGLGL",
	}
)

// EncodeEAN13 encodes data as EAN-13 barcode.
func EncodeEAN13(data string) (*Barcode, error) {
	// Validate length and digits
	if len(data) != 12 && len(data) != 13 {
		return nil, ErrInvalidLength
	}
	for _, c := range data {
		if c < '0' || c > '9' {
			return nil, ErrInvalidCharacter
		}
	}

	// Calculate or verify checksum
	checksum := calculateEANChecksum(data[:12])
	if len(data) == 13 {
		if int(data[12]-'0') != checksum {
			return nil, ErrChecksumMismatch
		}
	} else {
		data = data + string(rune('0'+checksum))
	}

	var encoded []bool

	// Start guard (101)
	encoded = append(encoded, true, false, true)

	// First digit determines parity pattern
	parityPattern := ean13Parity[int(data[0]-'0')]

	// Encode left side (digits 2-7)
	for i := 1; i <= 6; i++ {
		digit := int(data[i] - '0')
		var pattern string
		if parityPattern[i-1] == 'L' {
			pattern = eanLPatterns[digit]
		} else {
			pattern = eanGPatterns[digit]
		}
		encoded = append(encoded, patternToBools(pattern)...)
	}

	// Center guard (01010)
	encoded = append(encoded, false, true, false, true, false)

	// Encode right side (digits 8-13)
	for i := 7; i <= 12; i++ {
		digit := int(data[i] - '0')
		encoded = append(encoded, patternToBools(eanRPatterns[digit])...)
	}

	// End guard (101)
	encoded = append(encoded, true, false, true)

	return &Barcode{
		Type:     TypeEAN13,
		Data:     data,
		Encoded:  encoded,
		Checksum: checksum,
	}, nil
}

// EncodeEAN8 encodes data as EAN-8 barcode.
func EncodeEAN8(data string) (*Barcode, error) {
	// Validate length and digits
	if len(data) != 7 && len(data) != 8 {
		return nil, ErrInvalidLength
	}
	for _, c := range data {
		if c < '0' || c > '9' {
			return nil, ErrInvalidCharacter
		}
	}

	// Calculate or verify checksum
	checksum := calculateEAN8Checksum(data[:7])
	if len(data) == 8 {
		if int(data[7]-'0') != checksum {
			return nil, ErrChecksumMismatch
		}
	} else {
		data = data + string(rune('0'+checksum))
	}

	var encoded []bool

	// Start guard (101)
	encoded = append(encoded, true, false, true)

	// Encode left side (digits 1-4) with L patterns
	for i := 0; i < 4; i++ {
		digit := int(data[i] - '0')
		encoded = append(encoded, patternToBools(eanLPatterns[digit])...)
	}

	// Center guard (01010)
	encoded = append(encoded, false, true, false, true, false)

	// Encode right side (digits 5-8) with R patterns
	for i := 4; i < 8; i++ {
		digit := int(data[i] - '0')
		encoded = append(encoded, patternToBools(eanRPatterns[digit])...)
	}

	// End guard (101)
	encoded = append(encoded, true, false, true)

	return &Barcode{
		Type:     TypeEAN8,
		Data:     data,
		Encoded:  encoded,
		Checksum: checksum,
	}, nil
}

// EncodeUPCA encodes data as UPC-A barcode.
func EncodeUPCA(data string) (*Barcode, error) {
	// UPC-A is essentially EAN-13 with leading 0
	if len(data) != 11 && len(data) != 12 {
		return nil, ErrInvalidLength
	}

	ean13Data := "0" + data
	barcode, err := EncodeEAN13(ean13Data)
	if err != nil {
		return nil, err
	}
	barcode.Type = TypeUPCA
	barcode.Data = data
	return barcode, nil
}

func calculateEANChecksum(data string) int {
	sum := 0
	for i := 0; i < len(data); i++ {
		digit := int(data[i] - '0')
		if i%2 == 0 {
			sum += digit
		} else {
			sum += digit * 3
		}
	}
	return (10 - (sum % 10)) % 10
}

func calculateEAN8Checksum(data string) int {
	sum := 0
	for i := 0; i < len(data); i++ {
		digit := int(data[i] - '0')
		if i%2 == 0 {
			sum += digit * 3
		} else {
			sum += digit
		}
	}
	return (10 - (sum % 10)) % 10
}

// Interleaved 2 of 5 (ITF) encoding
var itfPatterns = []string{
	"00110", "10001", "01001", "11000", "00101",
	"10100", "01100", "00011", "10010", "01010",
}

// EncodeITF encodes data as Interleaved 2 of 5 barcode.
func EncodeITF(data string) (*Barcode, error) {
	// Must be even length and numeric
	if len(data)%2 != 0 {
		return nil, ErrInvalidLength
	}
	for _, c := range data {
		if c < '0' || c > '9' {
			return nil, ErrInvalidCharacter
		}
	}

	var encoded []bool

	// Start pattern (narrow bar, narrow space, narrow bar, narrow space)
	encoded = append(encoded, true, false, true, false)

	// Encode pairs of digits
	for i := 0; i < len(data); i += 2 {
		d1 := int(data[i] - '0')
		d2 := int(data[i+1] - '0')

		p1 := itfPatterns[d1]
		p2 := itfPatterns[d2]

		// Interleave the patterns
		for j := 0; j < 5; j++ {
			// Bar (from first digit)
			if p1[j] == '1' {
				encoded = append(encoded, true, true) // Wide bar
			} else {
				encoded = append(encoded, true) // Narrow bar
			}
			// Space (from second digit)
			if p2[j] == '1' {
				encoded = append(encoded, false, false) // Wide space
			} else {
				encoded = append(encoded, false) // Narrow space
			}
		}
	}

	// Stop pattern (wide bar, narrow space, narrow bar)
	encoded = append(encoded, true, true, false, true)

	return &Barcode{
		Type:    TypeITF,
		Data:    data,
		Encoded: encoded,
	}, nil
}

// EncodeITF14 encodes data as ITF-14 barcode (with checksum).
func EncodeITF14(data string) (*Barcode, error) {
	if len(data) != 13 && len(data) != 14 {
		return nil, ErrInvalidLength
	}

	// Calculate or verify checksum
	checksum := calculateITF14Checksum(data[:13])
	if len(data) == 14 {
		if int(data[13]-'0') != checksum {
			return nil, ErrChecksumMismatch
		}
	} else {
		data = data + string(rune('0'+checksum))
	}

	barcode, err := EncodeITF(data)
	if err != nil {
		return nil, err
	}
	barcode.Checksum = checksum
	return barcode, nil
}

func calculateITF14Checksum(data string) int {
	sum := 0
	for i := 0; i < len(data); i++ {
		digit := int(data[i] - '0')
		if i%2 == 0 {
			sum += digit * 3
		} else {
			sum += digit
		}
	}
	return (10 - (sum % 10)) % 10
}

// Codabar encoding
var codabarPatterns = map[rune]string{
	'0': "1010100110", '1': "1010110010", '2': "1010010110", '3': "1100101010",
	'4': "1011010010", '5': "1101010010", '6': "1001010110", '7': "1001011010",
	'8': "1001101010", '9': "1101001010", '-': "1010011010", '$': "1011001010",
	':': "1101011110", '/': "1101110110", '.': "1110110110", '+': "1011110110",
	'A': "1011001110", 'B': "1110010110", 'C': "1010011110", 'D': "1010001110",
}

// EncodeCodabar encodes data as Codabar barcode.
func EncodeCodabar(data string, startStop rune) (*Barcode, error) {
	data = strings.ToUpper(data)

	// Validate start/stop character
	if startStop != 'A' && startStop != 'B' && startStop != 'C' && startStop != 'D' {
		startStop = 'A'
	}

	// Validate characters
	for _, c := range data {
		if _, ok := codabarPatterns[c]; !ok {
			return nil, ErrInvalidCharacter
		}
	}

	var encoded []bool

	// Start character
	encoded = append(encoded, patternToBools(codabarPatterns[startStop])...)
	encoded = append(encoded, false) // Gap

	// Encode data
	for _, c := range data {
		encoded = append(encoded, patternToBools(codabarPatterns[c])...)
		encoded = append(encoded, false) // Gap
	}

	// Stop character
	encoded = append(encoded, patternToBools(codabarPatterns[startStop])...)

	return &Barcode{
		Type:    TypeCodabar,
		Data:    data,
		Encoded: encoded,
	}, nil
}

// BarcodeRenderer renders barcodes to various formats.
type BarcodeRenderer struct {
	BarWidth   float64 // Width of narrow bar in points
	BarHeight  float64 // Height of bars in points
	QuietZone  float64 // Quiet zone width in points
	ShowText   bool    // Whether to show human-readable text
	TextHeight float64 // Height of text area
}

// DefaultRenderer returns a renderer with default settings.
func DefaultRenderer() *BarcodeRenderer {
	return &BarcodeRenderer{
		BarWidth:   1.0,
		BarHeight:  50.0,
		QuietZone:  10.0,
		ShowText:   true,
		TextHeight: 12.0,
	}
}

// TotalWidth returns the total width of the rendered barcode.
func (r *BarcodeRenderer) TotalWidth(barcode *Barcode) float64 {
	return r.QuietZone*2 + float64(barcode.Width())*r.BarWidth
}

// TotalHeight returns the total height of the rendered barcode.
func (r *BarcodeRenderer) TotalHeight() float64 {
	if r.ShowText {
		return r.BarHeight + r.TextHeight
	}
	return r.BarHeight
}

// ToSVG renders the barcode as SVG.
func (r *BarcodeRenderer) ToSVG(barcode *Barcode) string {
	width := r.TotalWidth(barcode)
	height := r.TotalHeight()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%.2f" height="%.2f">`, width, height))
	sb.WriteString(fmt.Sprintf(`<rect width="%.2f" height="%.2f" fill="white"/>`, width, height))

	x := r.QuietZone
	for _, bar := range barcode.Encoded {
		if bar {
			sb.WriteString(fmt.Sprintf(`<rect x="%.2f" y="0" width="%.2f" height="%.2f" fill="black"/>`,
				x, r.BarWidth, r.BarHeight))
		}
		x += r.BarWidth
	}

	if r.ShowText {
		textY := r.BarHeight + r.TextHeight - 2
		sb.WriteString(fmt.Sprintf(`<text x="%.2f" y="%.2f" text-anchor="middle" font-family="monospace" font-size="%.2f">%s</text>`,
			width/2, textY, r.TextHeight*0.8, barcode.Data))
	}

	sb.WriteString("</svg>")
	return sb.String()
}

// ToPDFContentStream generates PDF content stream commands for the barcode.
func (r *BarcodeRenderer) ToPDFContentStream(barcode *Barcode, x, y float64) string {
	var sb strings.Builder

	// Save graphics state
	sb.WriteString("q\n")

	// Set fill color to black
	sb.WriteString("0 0 0 rg\n")

	// Draw bars
	bx := x + r.QuietZone
	for _, bar := range barcode.Encoded {
		if bar {
			sb.WriteString(fmt.Sprintf("%.4f %.4f %.4f %.4f re f\n",
				bx, y, r.BarWidth, r.BarHeight))
		}
		bx += r.BarWidth
	}

	// Restore graphics state
	sb.WriteString("Q\n")

	return sb.String()
}

// ValidateCheckDigit validates the check digit for various barcode types.
func ValidateCheckDigit(barcodeType BarcodeType, data string) (bool, error) {
	switch barcodeType {
	case TypeEAN13:
		if len(data) != 13 {
			return false, ErrInvalidLength
		}
		expected := calculateEANChecksum(data[:12])
		return int(data[12]-'0') == expected, nil
	case TypeEAN8:
		if len(data) != 8 {
			return false, ErrInvalidLength
		}
		expected := calculateEAN8Checksum(data[:7])
		return int(data[7]-'0') == expected, nil
	case TypeUPCA:
		if len(data) != 12 {
			return false, ErrInvalidLength
		}
		expected := calculateEANChecksum("0" + data[:11])
		return int(data[11]-'0') == expected, nil
	default:
		return false, ErrUnsupportedType
	}
}

// GenerateCheckDigit generates the check digit for various barcode types.
func GenerateCheckDigit(barcodeType BarcodeType, data string) (int, error) {
	switch barcodeType {
	case TypeEAN13:
		if len(data) != 12 {
			return 0, ErrInvalidLength
		}
		return calculateEANChecksum(data), nil
	case TypeEAN8:
		if len(data) != 7 {
			return 0, ErrInvalidLength
		}
		return calculateEAN8Checksum(data), nil
	case TypeUPCA:
		if len(data) != 11 {
			return 0, ErrInvalidLength
		}
		return calculateEANChecksum("0" + data), nil
	default:
		return 0, ErrUnsupportedType
	}
}
