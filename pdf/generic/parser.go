package generic

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Common errors
var (
	ErrUnexpectedEOF     = errors.New("unexpected end of file")
	ErrInvalidPDF        = errors.New("invalid PDF format")
	ErrInvalidObject     = errors.New("invalid PDF object")
	ErrInvalidStream     = errors.New("invalid PDF stream")
	ErrInvalidDictionary = errors.New("invalid PDF dictionary")
	ErrInvalidArray      = errors.New("invalid PDF array")
	ErrInvalidString     = errors.New("invalid PDF string")
	ErrInvalidName       = errors.New("invalid PDF name")
	ErrInvalidNumber     = errors.New("invalid PDF number")
	ErrInvalidReference  = errors.New("invalid PDF reference")
)

// Parser parses PDF objects from a byte stream.
type Parser struct {
	reader *bufio.Reader
	data   []byte
	pos    int64
}

// NewParser creates a new parser.
func NewParser(r io.Reader) *Parser {
	return &Parser{
		reader: bufio.NewReader(r),
	}
}

// NewParserFromBytes creates a parser from a byte slice.
func NewParserFromBytes(data []byte) *Parser {
	return &Parser{
		data: data,
		pos:  0,
	}
}

// readByte reads a single byte.
func (p *Parser) readByte() (byte, error) {
	if p.data != nil {
		if p.pos >= int64(len(p.data)) {
			return 0, io.EOF
		}
		b := p.data[p.pos]
		p.pos++
		return b, nil
	}
	return p.reader.ReadByte()
}

// unreadByte unreads the last byte.
func (p *Parser) unreadByte() error {
	if p.data != nil {
		if p.pos > 0 {
			p.pos--
		}
		return nil
	}
	return p.reader.UnreadByte()
}

// peekByte peeks at the next byte without consuming it.
func (p *Parser) peekByte() (byte, error) {
	b, err := p.readByte()
	if err != nil {
		return 0, err
	}
	return b, p.unreadByte()
}

// skipWhitespace skips whitespace and comments.
func (p *Parser) skipWhitespace() error {
	for {
		b, err := p.readByte()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		switch b {
		case ' ', '\t', '\n', '\r', '\x00', '\x0c':
			continue
		case '%':
			// Comment - skip until end of line
			for {
				c, err := p.readByte()
				if err != nil {
					if err == io.EOF {
						return nil
					}
					return err
				}
				if c == '\n' || c == '\r' {
					break
				}
			}
		default:
			return p.unreadByte()
		}
	}
}

// isWhitespace returns true if the byte is PDF whitespace.
func isWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\x00' || b == '\x0c'
}

// isDelimiter returns true if the byte is a PDF delimiter.
func isDelimiter(b byte) bool {
	return b == '(' || b == ')' || b == '<' || b == '>' ||
		b == '[' || b == ']' || b == '{' || b == '}' ||
		b == '/' || b == '%'
}

// readToken reads a token (sequence of non-whitespace, non-delimiter characters).
func (p *Parser) readToken() (string, error) {
	if err := p.skipWhitespace(); err != nil {
		return "", err
	}

	var buf bytes.Buffer
	for {
		b, err := p.readByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}

		if isWhitespace(b) || isDelimiter(b) {
			if err := p.unreadByte(); err != nil {
				return "", err
			}
			break
		}
		buf.WriteByte(b)
	}

	return buf.String(), nil
}

// ParseObject parses a PDF object.
func (p *Parser) ParseObject() (PdfObject, error) {
	if err := p.skipWhitespace(); err != nil {
		return nil, err
	}

	b, err := p.peekByte()
	if err != nil {
		return nil, err
	}

	switch b {
	case '(':
		return p.parseString()
	case '<':
		return p.parseHexOrDict()
	case '[':
		return p.parseArray()
	case '/':
		return p.parseName()
	case 't', 'f':
		return p.parseBoolean()
	case 'n':
		return p.parseNull()
	default:
		if b == '-' || b == '+' || b == '.' || (b >= '0' && b <= '9') {
			return p.parseNumber()
		}
		return nil, fmt.Errorf("%w: unexpected character '%c'", ErrInvalidObject, b)
	}
}

// parseString parses a literal string.
func (p *Parser) parseString() (*StringObject, error) {
	b, err := p.readByte()
	if err != nil {
		return nil, err
	}
	if b != '(' {
		return nil, ErrInvalidString
	}

	var buf bytes.Buffer
	depth := 1

	for depth > 0 {
		b, err := p.readByte()
		if err != nil {
			return nil, fmt.Errorf("%w: unterminated string", ErrInvalidString)
		}

		switch b {
		case '(':
			depth++
			buf.WriteByte(b)
		case ')':
			depth--
			if depth > 0 {
				buf.WriteByte(b)
			}
		case '\\':
			escaped, err := p.readByte()
			if err != nil {
				return nil, err
			}
			switch escaped {
			case 'n':
				buf.WriteByte('\n')
			case 'r':
				buf.WriteByte('\r')
			case 't':
				buf.WriteByte('\t')
			case 'b':
				buf.WriteByte('\b')
			case 'f':
				buf.WriteByte('\f')
			case '(', ')', '\\':
				buf.WriteByte(escaped)
			case '\r':
				// Line continuation
				next, err := p.peekByte()
				if err == nil && next == '\n' {
					p.readByte()
				}
			case '\n':
				// Line continuation
			default:
				if escaped >= '0' && escaped <= '7' {
					// Octal escape
					octal := string(escaped)
					for i := 0; i < 2; i++ {
						next, err := p.peekByte()
						if err != nil || next < '0' || next > '7' {
							break
						}
						p.readByte()
						octal += string(next)
					}
					val, _ := strconv.ParseInt(octal, 8, 16)
					buf.WriteByte(byte(val))
				} else {
					buf.WriteByte(escaped)
				}
			}
		default:
			buf.WriteByte(b)
		}
	}

	return &StringObject{Value: buf.Bytes(), IsHex: false}, nil
}

// parseHexOrDict parses a hex string or dictionary.
func (p *Parser) parseHexOrDict() (PdfObject, error) {
	first, err := p.readByte()
	if err != nil {
		return nil, err
	}
	if first != '<' {
		return nil, fmt.Errorf("%w: expected '<'", ErrInvalidObject)
	}

	second, err := p.peekByte()
	if err != nil {
		return nil, err
	}

	if second == '<' {
		p.readByte()
		return p.parseDictionary()
	}

	return p.parseHexString()
}

// parseHexString parses a hexadecimal string.
func (p *Parser) parseHexString() (*StringObject, error) {
	var buf bytes.Buffer

	for {
		b, err := p.readByte()
		if err != nil {
			return nil, fmt.Errorf("%w: unterminated hex string", ErrInvalidString)
		}

		if b == '>' {
			break
		}

		if isWhitespace(b) {
			continue
		}

		buf.WriteByte(b)
	}

	hexStr := buf.String()
	if len(hexStr)%2 != 0 {
		hexStr += "0"
	}

	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex string: %v", ErrInvalidString, err)
	}

	return &StringObject{Value: data, IsHex: true}, nil
}

// parseDictionary parses a dictionary (after << has been consumed).
func (p *Parser) parseDictionary() (*DictionaryObject, error) {
	dict := NewDictionary()

	for {
		if err := p.skipWhitespace(); err != nil {
			return nil, err
		}

		b, err := p.peekByte()
		if err != nil {
			return nil, err
		}

		if b == '>' {
			p.readByte()
			next, err := p.readByte()
			if err != nil || next != '>' {
				return nil, fmt.Errorf("%w: expected '>>'", ErrInvalidDictionary)
			}
			break
		}

		// Parse key (must be a name)
		key, err := p.parseName()
		if err != nil {
			return nil, fmt.Errorf("%w: invalid dictionary key: %v", ErrInvalidDictionary, err)
		}

		// Parse value
		value, err := p.ParseObjectOrReference()
		if err != nil {
			return nil, fmt.Errorf("%w: invalid dictionary value for key '%s': %v", ErrInvalidDictionary, key, err)
		}

		dict.Set(string(key), value)
	}

	return dict, nil
}

// parseArray parses an array.
func (p *Parser) parseArray() (ArrayObject, error) {
	b, err := p.readByte()
	if err != nil {
		return nil, err
	}
	if b != '[' {
		return nil, ErrInvalidArray
	}

	var arr ArrayObject

	for {
		if err := p.skipWhitespace(); err != nil {
			return nil, err
		}

		b, err := p.peekByte()
		if err != nil {
			return nil, err
		}

		if b == ']' {
			p.readByte()
			break
		}

		obj, err := p.ParseObjectOrReference()
		if err != nil {
			return nil, fmt.Errorf("%w: invalid array element: %v", ErrInvalidArray, err)
		}

		arr = append(arr, obj)
	}

	return arr, nil
}

// parseName parses a name object.
func (p *Parser) parseName() (NameObject, error) {
	b, err := p.readByte()
	if err != nil {
		return "", err
	}
	if b != '/' {
		return "", ErrInvalidName
	}

	var buf bytes.Buffer

	for {
		b, err := p.readByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}

		if isWhitespace(b) || isDelimiter(b) {
			p.unreadByte()
			break
		}

		if b == '#' {
			// Hex escape
			hex1, err := p.readByte()
			if err != nil {
				return "", err
			}
			hex2, err := p.readByte()
			if err != nil {
				return "", err
			}
			val, err := strconv.ParseInt(string([]byte{hex1, hex2}), 16, 16)
			if err != nil {
				return "", fmt.Errorf("%w: invalid hex escape in name", ErrInvalidName)
			}
			buf.WriteByte(byte(val))
		} else {
			buf.WriteByte(b)
		}
	}

	return NameObject(buf.String()), nil
}

// parseBoolean parses a boolean.
func (p *Parser) parseBoolean() (BooleanObject, error) {
	token, err := p.readToken()
	if err != nil {
		return false, err
	}

	switch token {
	case "true":
		return BooleanObject(true), nil
	case "false":
		return BooleanObject(false), nil
	default:
		return false, fmt.Errorf("%w: expected 'true' or 'false', got '%s'", ErrInvalidObject, token)
	}
}

// parseNull parses a null object.
func (p *Parser) parseNull() (NullObject, error) {
	token, err := p.readToken()
	if err != nil {
		return NullObject{}, err
	}

	if token != "null" {
		return NullObject{}, fmt.Errorf("%w: expected 'null', got '%s'", ErrInvalidObject, token)
	}

	return NullObject{}, nil
}

// parseNumber parses a number (integer or real).
func (p *Parser) parseNumber() (PdfObject, error) {
	var buf bytes.Buffer
	hasDecimal := false

	for {
		b, err := p.readByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if b == '.' {
			if hasDecimal {
				p.unreadByte()
				break
			}
			hasDecimal = true
			buf.WriteByte(b)
		} else if b == '-' || b == '+' {
			if buf.Len() > 0 {
				p.unreadByte()
				break
			}
			buf.WriteByte(b)
		} else if b >= '0' && b <= '9' {
			buf.WriteByte(b)
		} else {
			p.unreadByte()
			break
		}
	}

	str := buf.String()
	if str == "" || str == "-" || str == "+" || str == "." {
		return nil, fmt.Errorf("%w: invalid number '%s'", ErrInvalidNumber, str)
	}

	if hasDecimal {
		val, err := strconv.ParseFloat(str, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidNumber, err)
		}
		return RealObject(val), nil
	}

	val, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidNumber, err)
	}
	return IntegerObject(val), nil
}

// ParseObjectOrReference parses an object, potentially as an indirect reference.
func (p *Parser) ParseObjectOrReference() (PdfObject, error) {
	if err := p.skipWhitespace(); err != nil {
		return nil, err
	}

	// Save position for potential backtracking
	startPos := p.pos

	b, err := p.peekByte()
	if err != nil {
		return nil, err
	}

	// Check if this might be a reference (starts with a number)
	if b >= '0' && b <= '9' {
		// Try to parse as reference
		obj, err := p.parseNumber()
		if err != nil {
			return nil, err
		}

		objNum, ok := obj.(IntegerObject)
		if !ok {
			return obj, nil
		}

		if err := p.skipWhitespace(); err != nil {
			return obj, nil
		}

		b, err = p.peekByte()
		if err != nil || b < '0' || b > '9' {
			return obj, nil
		}

		genObj, err := p.parseNumber()
		if err != nil {
			// Reset and return the first number
			p.pos = startPos
			return p.parseNumber()
		}

		genNum, ok := genObj.(IntegerObject)
		if !ok {
			p.pos = startPos
			return p.parseNumber()
		}

		if err := p.skipWhitespace(); err != nil {
			return obj, nil
		}

		b, err = p.readByte()
		if err != nil {
			return obj, nil
		}

		if b == 'R' {
			return Reference{ObjectNumber: int(objNum), GenerationNumber: int(genNum)}, nil
		}

		// Not a reference - backtrack and return first number
		p.pos = startPos
		return p.parseNumber()
	}

	return p.ParseObject()
}

// ParseIndirectObject parses an indirect object definition.
func (p *Parser) ParseIndirectObject() (*IndirectObject, error) {
	// Parse object number
	objNumObj, err := p.parseNumber()
	if err != nil {
		return nil, fmt.Errorf("%w: invalid object number: %v", ErrInvalidObject, err)
	}
	objNum, ok := objNumObj.(IntegerObject)
	if !ok {
		return nil, fmt.Errorf("%w: object number must be integer", ErrInvalidObject)
	}

	if err := p.skipWhitespace(); err != nil {
		return nil, err
	}

	// Parse generation number
	genNumObj, err := p.parseNumber()
	if err != nil {
		return nil, fmt.Errorf("%w: invalid generation number: %v", ErrInvalidObject, err)
	}
	genNum, ok := genNumObj.(IntegerObject)
	if !ok {
		return nil, fmt.Errorf("%w: generation number must be integer", ErrInvalidObject)
	}

	if err := p.skipWhitespace(); err != nil {
		return nil, err
	}

	// Expect "obj"
	token, err := p.readToken()
	if err != nil {
		return nil, err
	}
	if token != "obj" {
		return nil, fmt.Errorf("%w: expected 'obj', got '%s'", ErrInvalidObject, token)
	}

	// Parse the object value
	obj, err := p.ParseObjectOrReference()
	if err != nil {
		return nil, err
	}

	if err := p.skipWhitespace(); err != nil {
		return nil, err
	}

	// Check for stream
	if dict, ok := obj.(*DictionaryObject); ok {
		b, err := p.peekByte()
		if err == nil && b == 's' {
			token, _ := p.readToken()
			if token == "stream" {
				// Skip stream keyword and newline
				b, _ := p.readByte()
				if b == '\r' {
					next, _ := p.peekByte()
					if next == '\n' {
						p.readByte()
					}
				}

				// Get length
				length := int64(0)
				if l, ok := dict.GetInt("Length"); ok {
					length = l
				}

				// Read stream data
				data := make([]byte, length)
				if p.data != nil {
					copy(data, p.data[p.pos:p.pos+length])
					p.pos += length
				} else {
					io.ReadFull(p.reader, data)
				}

				// Skip endstream
				p.skipWhitespace()
				p.readToken() // "endstream"

				stream := NewStream(dict, data)
				obj = stream
			}
		}
	}

	if err := p.skipWhitespace(); err != nil {
		return nil, err
	}

	// Expect "endobj"
	token, err = p.readToken()
	if err != nil && err != io.EOF {
		return nil, err
	}
	if token != "endobj" && token != "" {
		// Some PDFs omit endobj
	}

	return NewIndirectObject(int(objNum), int(genNum), obj), nil
}

// Utility functions for parsing PDF structures

// ParseRectangle parses a rectangle from an array.
func ParseRectangle(obj PdfObject) (*Rectangle, error) {
	arr, ok := obj.(ArrayObject)
	if !ok {
		return nil, fmt.Errorf("expected array for rectangle")
	}
	return NewRectangle(arr)
}

// ParseDate parses a PDF date string.
func ParseDate(s string) (string, error) {
	// PDF date format: D:YYYYMMDDHHmmSSOHH'mm'
	s = strings.TrimPrefix(s, "D:")
	// For now, just return the raw string
	return s, nil
}
