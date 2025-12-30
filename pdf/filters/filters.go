// Package filters provides PDF stream filter implementations.
package filters

import (
	"bytes"
	"compress/zlib"
	"encoding/ascii85"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Common errors
var (
	ErrUnsupportedFilter = errors.New("unsupported filter")
	ErrDecodeFailed      = errors.New("decode failed")
)

// Filter represents a PDF stream filter.
type Filter interface {
	// Decode decodes the data.
	Decode(data []byte, params map[string]interface{}) ([]byte, error)
	// Encode encodes the data.
	Encode(data []byte, params map[string]interface{}) ([]byte, error)
	// Name returns the filter name.
	Name() string
}

// FlateDecodeFilter implements the FlateDecode filter (zlib compression).
type FlateDecodeFilter struct{}

// Name implements Filter.
func (f *FlateDecodeFilter) Name() string {
	return "FlateDecode"
}

// Decode implements Filter.
func (f *FlateDecodeFilter) Decode(data []byte, params map[string]interface{}) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}
	defer r.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}

	result := buf.Bytes()

	// Apply predictor if specified
	if params != nil {
		if predictor, ok := params["Predictor"].(int); ok && predictor > 1 {
			result, err = applyPredictor(result, params)
			if err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

// Encode implements Filter.
func (f *FlateDecodeFilter) Encode(data []byte, params map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("flate encode failed: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("flate encode failed: %w", err)
	}
	return buf.Bytes(), nil
}

// applyPredictor applies PNG predictor decoding.
func applyPredictor(data []byte, params map[string]interface{}) ([]byte, error) {
	predictor := 1
	if p, ok := params["Predictor"].(int); ok {
		predictor = p
	}

	if predictor == 1 {
		return data, nil
	}

	columns := 1
	if c, ok := params["Columns"].(int); ok {
		columns = c
	}

	colors := 1
	if c, ok := params["Colors"].(int); ok {
		colors = c
	}

	bitsPerComponent := 8
	if b, ok := params["BitsPerComponent"].(int); ok {
		bitsPerComponent = b
	}

	bytesPerPixel := (colors*bitsPerComponent + 7) / 8
	rowLength := (columns*colors*bitsPerComponent+7)/8 + 1 // +1 for filter byte

	if predictor >= 10 && predictor <= 15 {
		// PNG predictors
		return decodePNGPredictor(data, rowLength, bytesPerPixel)
	}

	return data, nil
}

// decodePNGPredictor decodes PNG predictor.
func decodePNGPredictor(data []byte, rowLength, bytesPerPixel int) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	numRows := len(data) / rowLength
	if len(data)%rowLength != 0 {
		numRows++
	}

	output := make([]byte, 0, numRows*(rowLength-1))
	prevRow := make([]byte, rowLength-1)

	for i := 0; i < len(data); i += rowLength {
		if i+rowLength > len(data) {
			break
		}

		filterType := data[i]
		row := data[i+1 : i+rowLength]
		decodedRow := make([]byte, len(row))

		switch filterType {
		case 0: // None
			copy(decodedRow, row)
		case 1: // Sub
			for j := range row {
				left := byte(0)
				if j >= bytesPerPixel {
					left = decodedRow[j-bytesPerPixel]
				}
				decodedRow[j] = row[j] + left
			}
		case 2: // Up
			for j := range row {
				decodedRow[j] = row[j] + prevRow[j]
			}
		case 3: // Average
			for j := range row {
				left := byte(0)
				if j >= bytesPerPixel {
					left = decodedRow[j-bytesPerPixel]
				}
				up := prevRow[j]
				decodedRow[j] = row[j] + byte((int(left)+int(up))/2)
			}
		case 4: // Paeth
			for j := range row {
				left := byte(0)
				if j >= bytesPerPixel {
					left = decodedRow[j-bytesPerPixel]
				}
				up := prevRow[j]
				upLeft := byte(0)
				if j >= bytesPerPixel {
					upLeft = prevRow[j-bytesPerPixel]
				}
				decodedRow[j] = row[j] + paethPredictor(left, up, upLeft)
			}
		default:
			copy(decodedRow, row)
		}

		output = append(output, decodedRow...)
		copy(prevRow, decodedRow)
	}

	return output, nil
}

// paethPredictor implements the Paeth predictor function.
func paethPredictor(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa := abs(p - int(a))
	pb := abs(p - int(b))
	pc := abs(p - int(c))

	if pa <= pb && pa <= pc {
		return a
	} else if pb <= pc {
		return b
	}
	return c
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ASCIIHexDecodeFilter implements the ASCIIHexDecode filter.
type ASCIIHexDecodeFilter struct{}

// Name implements Filter.
func (f *ASCIIHexDecodeFilter) Name() string {
	return "ASCIIHexDecode"
}

// Decode implements Filter.
func (f *ASCIIHexDecodeFilter) Decode(data []byte, params map[string]interface{}) ([]byte, error) {
	// Remove whitespace and trailing '>'
	var cleaned bytes.Buffer
	for _, b := range data {
		if b == '>' {
			break
		}
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			cleaned.WriteByte(b)
		}
	}

	hexStr := cleaned.String()
	if len(hexStr)%2 != 0 {
		hexStr += "0"
	}

	return hex.DecodeString(hexStr)
}

// Encode implements Filter.
func (f *ASCIIHexDecodeFilter) Encode(data []byte, params map[string]interface{}) ([]byte, error) {
	return []byte(hex.EncodeToString(data) + ">"), nil
}

// ASCII85DecodeFilter implements the ASCII85Decode filter.
type ASCII85DecodeFilter struct{}

// Name implements Filter.
func (f *ASCII85DecodeFilter) Name() string {
	return "ASCII85Decode"
}

// Decode implements Filter.
func (f *ASCII85DecodeFilter) Decode(data []byte, params map[string]interface{}) ([]byte, error) {
	// Find and remove ~> end marker
	end := bytes.Index(data, []byte("~>"))
	if end != -1 {
		data = data[:end]
	}

	// Remove whitespace
	var cleaned bytes.Buffer
	for _, b := range data {
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			cleaned.WriteByte(b)
		}
	}

	decoder := ascii85.NewDecoder(bytes.NewReader(cleaned.Bytes()))
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, decoder); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}

	return buf.Bytes(), nil
}

// Encode implements Filter.
func (f *ASCII85DecodeFilter) Encode(data []byte, params map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	encoder := ascii85.NewEncoder(&buf)
	if _, err := encoder.Write(data); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	buf.WriteString("~>")
	return buf.Bytes(), nil
}

// LZWDecodeFilter implements the LZWDecode filter.
type LZWDecodeFilter struct{}

// Name implements Filter.
func (f *LZWDecodeFilter) Name() string {
	return "LZWDecode"
}

// Decode implements Filter.
func (f *LZWDecodeFilter) Decode(data []byte, params map[string]interface{}) ([]byte, error) {
	// PDF uses early-change LZW which differs from standard LZW
	return lzwDecode(data, params)
}

// Encode implements Filter.
func (f *LZWDecodeFilter) Encode(data []byte, params map[string]interface{}) ([]byte, error) {
	return nil, fmt.Errorf("%w: LZW encoding not implemented", ErrUnsupportedFilter)
}

// lzwDecode implements PDF LZW decoding.
func lzwDecode(data []byte, params map[string]interface{}) ([]byte, error) {
	// LZW parameters
	earlyChange := 1
	if ec, ok := params["EarlyChange"].(int); ok {
		earlyChange = ec
	}

	// Initialize dictionary
	const clearCode = 256
	const eodCode = 257

	dict := make(map[int][]byte)
	for i := 0; i < 256; i++ {
		dict[i] = []byte{byte(i)}
	}

	nextCode := 258
	codeLen := 9

	// Bit reader
	bitPos := 0
	readCode := func() int {
		if bitPos+codeLen > len(data)*8 {
			return eodCode
		}

		code := 0
		for i := 0; i < codeLen; i++ {
			byteIdx := (bitPos + i) / 8
			bitIdx := 7 - ((bitPos + i) % 8)
			if byteIdx < len(data) && (data[byteIdx]>>bitIdx)&1 == 1 {
				code |= 1 << (codeLen - 1 - i)
			}
		}
		bitPos += codeLen
		return code
	}

	var output bytes.Buffer
	var prevSeq []byte

	for {
		code := readCode()

		if code == eodCode {
			break
		}

		if code == clearCode {
			// Reset dictionary
			dict = make(map[int][]byte)
			for i := 0; i < 256; i++ {
				dict[i] = []byte{byte(i)}
			}
			nextCode = 258
			codeLen = 9
			prevSeq = nil
			continue
		}

		var seq []byte
		if s, ok := dict[code]; ok {
			seq = s
		} else if code == nextCode && prevSeq != nil {
			seq = append(prevSeq, prevSeq[0])
		} else {
			return nil, fmt.Errorf("invalid LZW code: %d", code)
		}

		output.Write(seq)

		if prevSeq != nil {
			dict[nextCode] = append(prevSeq, seq[0])
			nextCode++

			// Update code length
			threshold := 512
			if earlyChange == 1 {
				threshold = 511
			}
			if nextCode >= threshold && codeLen < 12 {
				codeLen++
				threshold = 1 << codeLen
				if earlyChange == 1 {
					threshold--
				}
			}
		}

		prevSeq = seq
	}

	result := output.Bytes()

	// Apply predictor if specified
	if params != nil {
		if predictor, ok := params["Predictor"].(int); ok && predictor > 1 {
			var err error
			result, err = applyPredictor(result, params)
			if err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

// RunLengthDecodeFilter implements the RunLengthDecode filter.
type RunLengthDecodeFilter struct{}

// Name implements Filter.
func (f *RunLengthDecodeFilter) Name() string {
	return "RunLengthDecode"
}

// Decode implements Filter.
func (f *RunLengthDecodeFilter) Decode(data []byte, params map[string]interface{}) ([]byte, error) {
	var output bytes.Buffer
	i := 0

	for i < len(data) {
		length := int(data[i])
		i++

		if length == 128 {
			// EOD
			break
		} else if length < 128 {
			// Copy next length+1 bytes literally
			count := length + 1
			if i+count > len(data) {
				return nil, fmt.Errorf("%w: truncated run-length data", ErrDecodeFailed)
			}
			output.Write(data[i : i+count])
			i += count
		} else {
			// Repeat next byte (257-length) times
			count := 257 - length
			if i >= len(data) {
				return nil, fmt.Errorf("%w: truncated run-length data", ErrDecodeFailed)
			}
			for j := 0; j < count; j++ {
				output.WriteByte(data[i])
			}
			i++
		}
	}

	return output.Bytes(), nil
}

// Encode implements Filter.
func (f *RunLengthDecodeFilter) Encode(data []byte, params map[string]interface{}) ([]byte, error) {
	var output bytes.Buffer
	i := 0

	for i < len(data) {
		// Look for runs
		runStart := i
		for i < len(data)-1 && data[i] == data[i+1] && i-runStart < 127 {
			i++
		}

		runLength := i - runStart + 1
		if runLength > 1 {
			// Encode run
			output.WriteByte(byte(257 - runLength))
			output.WriteByte(data[runStart])
			i++
		} else {
			// Encode literal sequence
			literalStart := i
			for i < len(data) && (i == len(data)-1 || data[i] != data[i+1]) && i-literalStart < 127 {
				i++
			}
			literalLength := i - literalStart
			output.WriteByte(byte(literalLength - 1))
			output.Write(data[literalStart:i])
		}
	}

	output.WriteByte(128) // EOD
	return output.Bytes(), nil
}

// Registry holds all registered filters.
var Registry = map[string]Filter{
	"FlateDecode":     &FlateDecodeFilter{},
	"Fl":              &FlateDecodeFilter{},
	"ASCIIHexDecode":  &ASCIIHexDecodeFilter{},
	"AHx":             &ASCIIHexDecodeFilter{},
	"ASCII85Decode":   &ASCII85DecodeFilter{},
	"A85":             &ASCII85DecodeFilter{},
	"LZWDecode":       &LZWDecodeFilter{},
	"LZW":             &LZWDecodeFilter{},
	"RunLengthDecode": &RunLengthDecodeFilter{},
	"RL":              &RunLengthDecodeFilter{},
}

// GetFilter returns a filter by name.
func GetFilter(name string) (Filter, error) {
	if f, ok := Registry[name]; ok {
		return f, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedFilter, name)
}

// DecodeStream decodes stream data using the specified filters.
func DecodeStream(data []byte, filters []string, decodeParms []map[string]interface{}) ([]byte, error) {
	result := data

	for i, filterName := range filters {
		filter, err := GetFilter(filterName)
		if err != nil {
			return nil, err
		}

		var params map[string]interface{}
		if i < len(decodeParms) {
			params = decodeParms[i]
		}

		result, err = filter.Decode(result, params)
		if err != nil {
			return nil, fmt.Errorf("filter %s decode failed: %w", filterName, err)
		}
	}

	return result, nil
}

// EncodeStream encodes stream data using the specified filters.
func EncodeStream(data []byte, filters []string, encodeParms []map[string]interface{}) ([]byte, error) {
	result := data

	// Apply filters in reverse order for encoding
	for i := len(filters) - 1; i >= 0; i-- {
		filterName := filters[i]
		filter, err := GetFilter(filterName)
		if err != nil {
			return nil, err
		}

		var params map[string]interface{}
		if i < len(encodeParms) {
			params = encodeParms[i]
		}

		result, err = filter.Encode(result, params)
		if err != nil {
			return nil, fmt.Errorf("filter %s encode failed: %w", filterName, err)
		}
	}

	return result, nil
}
