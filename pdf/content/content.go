// Package content provides PDF content stream handling.
package content

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// Operator represents a PDF content stream operator.
type Operator string

// Common PDF operators
const (
	// Graphics state operators
	OpSaveState     Operator = "q"
	OpRestoreState  Operator = "Q"
	OpSetCTM        Operator = "cm"
	OpSetLineWidth  Operator = "w"
	OpSetLineCap    Operator = "J"
	OpSetLineJoin   Operator = "j"
	OpSetMiterLimit Operator = "M"
	OpSetDash       Operator = "d"
	OpSetIntent     Operator = "ri"
	OpSetFlatness   Operator = "i"
	OpSetGState     Operator = "gs"

	// Path construction operators
	OpMoveTo    Operator = "m"
	OpLineTo    Operator = "l"
	OpCurveTo   Operator = "c"
	OpCurveToV  Operator = "v"
	OpCurveToY  Operator = "y"
	OpClosePath Operator = "h"
	OpRectangle Operator = "re"

	// Path painting operators
	OpStroke               Operator = "S"
	OpCloseAndStroke       Operator = "s"
	OpFill                 Operator = "f"
	OpFillEvenOdd          Operator = "f*"
	OpFillAndStroke        Operator = "B"
	OpFillAndStrokeEvenOdd Operator = "B*"
	OpCloseFillAndStroke   Operator = "b"
	OpEndPath              Operator = "n"

	// Clipping operators
	OpClip        Operator = "W"
	OpClipEvenOdd Operator = "W*"

	// Text object operators
	OpBeginText Operator = "BT"
	OpEndText   Operator = "ET"

	// Text state operators
	OpSetCharSpacing Operator = "Tc"
	OpSetWordSpacing Operator = "Tw"
	OpSetHScale      Operator = "Tz"
	OpSetLeading     Operator = "TL"
	OpSetFont        Operator = "Tf"
	OpSetRenderMode  Operator = "Tr"
	OpSetTextRise    Operator = "Ts"

	// Text positioning operators
	OpTextMove      Operator = "Td"
	OpTextMoveSet   Operator = "TD"
	OpSetTextMatrix Operator = "Tm"
	OpTextNextLine  Operator = "T*"

	// Text showing operators
	OpShowText      Operator = "Tj"
	OpShowTextArray Operator = "TJ"
	OpMoveShowText  Operator = "'"
	OpMoveSetShow   Operator = "\""

	// Color operators
	OpSetStrokeColorSpace Operator = "CS"
	OpSetFillColorSpace   Operator = "cs"
	OpSetStrokeColor      Operator = "SC"
	OpSetStrokeColorN     Operator = "SCN"
	OpSetFillColor        Operator = "sc"
	OpSetFillColorN       Operator = "scn"
	OpSetStrokeGray       Operator = "G"
	OpSetFillGray         Operator = "g"
	OpSetStrokeRGB        Operator = "RG"
	OpSetFillRGB          Operator = "rg"
	OpSetStrokeCMYK       Operator = "K"
	OpSetFillCMYK         Operator = "k"

	// XObject operators
	OpPaintXObject Operator = "Do"

	// Marked content operators
	OpBeginMarkedContent     Operator = "BMC"
	OpBeginMarkedContentDict Operator = "BDC"
	OpEndMarkedContent       Operator = "EMC"

	// Inline image operators
	OpBeginInlineImage Operator = "BI"
	OpBeginImageData   Operator = "ID"
	OpEndInlineImage   Operator = "EI"
)

// ContentStream represents a parsed PDF content stream.
type ContentStream struct {
	Operations []Operation
}

// Operation represents a single operation in a content stream.
type Operation struct {
	Operator Operator
	Operands []interface{}
}

// NewContentStream creates a new empty content stream.
func NewContentStream() *ContentStream {
	return &ContentStream{
		Operations: make([]Operation, 0),
	}
}

// AddOperation adds an operation to the content stream.
func (cs *ContentStream) AddOperation(op Operator, operands ...interface{}) {
	cs.Operations = append(cs.Operations, Operation{
		Operator: op,
		Operands: operands,
	})
}

// Render renders the content stream to bytes.
func (cs *ContentStream) Render() []byte {
	var buf bytes.Buffer

	for _, op := range cs.Operations {
		for i, operand := range op.Operands {
			if i > 0 {
				buf.WriteByte(' ')
			}
			buf.WriteString(formatOperand(operand))
		}
		if len(op.Operands) > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(string(op.Operator))
		buf.WriteByte('\n')
	}

	return buf.Bytes()
}

// formatOperand formats an operand for output.
func formatOperand(v interface{}) string {
	switch val := v.(type) {
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case string:
		return val
	case generic.NameObject:
		return "/" + string(val)
	case *generic.StringObject:
		var buf bytes.Buffer
		val.Write(&buf)
		return buf.String()
	case generic.ArrayObject:
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(' ')
			}
			buf.WriteString(formatOperand(item))
		}
		buf.WriteByte(']')
		return buf.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}

// Parser parses PDF content streams.
type Parser struct {
	data []byte
	pos  int
}

// NewParser creates a new content stream parser.
func NewParser(data []byte) *Parser {
	return &Parser{data: data}
}

// Parse parses the content stream.
func (p *Parser) Parse() (*ContentStream, error) {
	cs := NewContentStream()

	var operands []interface{}

	for {
		token, err := p.nextToken()
		if err != nil {
			break
		}
		if token == "" {
			break
		}

		// Check if this is an operator
		if isOperator(token) {
			cs.AddOperation(Operator(token), operands...)
			operands = nil
		} else {
			// Parse as operand
			operand := p.parseOperand(token)
			operands = append(operands, operand)
		}
	}

	return cs, nil
}

// nextToken reads the next token from the content stream.
func (p *Parser) nextToken() (string, error) {
	// Skip whitespace
	for p.pos < len(p.data) && isWhitespace(p.data[p.pos]) {
		p.pos++
	}

	if p.pos >= len(p.data) {
		return "", nil
	}

	start := p.pos

	// Handle special characters
	switch p.data[p.pos] {
	case '[', ']', '{', '}':
		p.pos++
		return string(p.data[start:p.pos]), nil

	case '(':
		// String
		return p.readString()

	case '<':
		if p.pos+1 < len(p.data) && p.data[p.pos+1] == '<' {
			// Dictionary
			p.pos += 2
			return "<<", nil
		}
		// Hex string
		return p.readHexString()

	case '>':
		if p.pos+1 < len(p.data) && p.data[p.pos+1] == '>' {
			p.pos += 2
			return ">>", nil
		}
		p.pos++
		return ">", nil

	case '/':
		// Name
		return p.readName()

	case '%':
		// Comment - skip to end of line
		for p.pos < len(p.data) && p.data[p.pos] != '\n' && p.data[p.pos] != '\r' {
			p.pos++
		}
		return p.nextToken()
	}

	// Regular token
	for p.pos < len(p.data) && !isWhitespace(p.data[p.pos]) && !isDelimiter(p.data[p.pos]) {
		p.pos++
	}

	return string(p.data[start:p.pos]), nil
}

// readString reads a literal string.
func (p *Parser) readString() (string, error) {
	start := p.pos
	p.pos++ // Skip opening (

	depth := 1
	var buf bytes.Buffer
	buf.WriteByte('(')

	for p.pos < len(p.data) && depth > 0 {
		b := p.data[p.pos]
		switch b {
		case '(':
			depth++
			buf.WriteByte(b)
		case ')':
			depth--
			buf.WriteByte(b)
		case '\\':
			buf.WriteByte(b)
			p.pos++
			if p.pos < len(p.data) {
				buf.WriteByte(p.data[p.pos])
			}
		default:
			buf.WriteByte(b)
		}
		p.pos++
	}

	_ = start
	return buf.String(), nil
}

// readHexString reads a hex string.
func (p *Parser) readHexString() (string, error) {
	start := p.pos
	p.pos++ // Skip <

	for p.pos < len(p.data) && p.data[p.pos] != '>' {
		p.pos++
	}

	if p.pos < len(p.data) {
		p.pos++ // Skip >
	}

	return string(p.data[start:p.pos]), nil
}

// readName reads a name object.
func (p *Parser) readName() (string, error) {
	start := p.pos
	p.pos++ // Skip /

	for p.pos < len(p.data) && !isWhitespace(p.data[p.pos]) && !isDelimiter(p.data[p.pos]) {
		p.pos++
	}

	return string(p.data[start:p.pos]), nil
}

// parseOperand parses a token as an operand.
func (p *Parser) parseOperand(token string) interface{} {
	// Try as number
	if i, err := strconv.ParseInt(token, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(token, 64); err == nil {
		return f
	}

	// Name
	if strings.HasPrefix(token, "/") {
		return generic.NameObject(token[1:])
	}

	// String
	if strings.HasPrefix(token, "(") {
		return token
	}

	// Hex string
	if strings.HasPrefix(token, "<") && !strings.HasPrefix(token, "<<") {
		return token
	}

	// Boolean
	if token == "true" {
		return true
	}
	if token == "false" {
		return false
	}

	return token
}

func isWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\x00' || b == '\x0c'
}

func isDelimiter(b byte) bool {
	return b == '(' || b == ')' || b == '<' || b == '>' ||
		b == '[' || b == ']' || b == '{' || b == '}' ||
		b == '/' || b == '%'
}

// Operator patterns
var operatorPattern = regexp.MustCompile(`^[A-Za-z*'"]+$`)

func isOperator(token string) bool {
	operators := map[string]bool{
		"q": true, "Q": true, "cm": true, "w": true, "J": true, "j": true,
		"M": true, "d": true, "ri": true, "i": true, "gs": true,
		"m": true, "l": true, "c": true, "v": true, "y": true, "h": true, "re": true,
		"S": true, "s": true, "f": true, "F": true, "f*": true, "B": true, "B*": true,
		"b": true, "b*": true, "n": true,
		"W": true, "W*": true,
		"BT": true, "ET": true,
		"Tc": true, "Tw": true, "Tz": true, "TL": true, "Tf": true, "Tr": true, "Ts": true,
		"Td": true, "TD": true, "Tm": true, "T*": true,
		"Tj": true, "TJ": true, "'": true, "\"": true,
		"CS": true, "cs": true, "SC": true, "SCN": true, "sc": true, "scn": true,
		"G": true, "g": true, "RG": true, "rg": true, "K": true, "k": true,
		"Do":  true,
		"BMC": true, "BDC": true, "EMC": true,
		"BI": true, "ID": true, "EI": true,
		"sh": true, "MP": true, "DP": true,
	}
	return operators[token]
}

// ContentBuilder provides a fluent interface for building content streams.
type ContentBuilder struct {
	stream *ContentStream
}

// NewContentBuilder creates a new content builder.
func NewContentBuilder() *ContentBuilder {
	return &ContentBuilder{
		stream: NewContentStream(),
	}
}

// SaveState saves the graphics state.
func (cb *ContentBuilder) SaveState() *ContentBuilder {
	cb.stream.AddOperation(OpSaveState)
	return cb
}

// RestoreState restores the graphics state.
func (cb *ContentBuilder) RestoreState() *ContentBuilder {
	cb.stream.AddOperation(OpRestoreState)
	return cb
}

// Transform applies a transformation matrix.
func (cb *ContentBuilder) Transform(a, b, c, d, e, f float64) *ContentBuilder {
	cb.stream.AddOperation(OpSetCTM, a, b, c, d, e, f)
	return cb
}

// Translate moves the origin.
func (cb *ContentBuilder) Translate(tx, ty float64) *ContentBuilder {
	return cb.Transform(1, 0, 0, 1, tx, ty)
}

// Scale scales the coordinate system.
func (cb *ContentBuilder) Scale(sx, sy float64) *ContentBuilder {
	return cb.Transform(sx, 0, 0, sy, 0, 0)
}

// Rotate rotates the coordinate system.
func (cb *ContentBuilder) Rotate(angle float64) *ContentBuilder {
	// Angle in radians
	cos := cosine(angle)
	sin := sine(angle)
	return cb.Transform(cos, sin, -sin, cos, 0, 0)
}

// MoveTo moves to a point.
func (cb *ContentBuilder) MoveTo(x, y float64) *ContentBuilder {
	cb.stream.AddOperation(OpMoveTo, x, y)
	return cb
}

// LineTo draws a line to a point.
func (cb *ContentBuilder) LineTo(x, y float64) *ContentBuilder {
	cb.stream.AddOperation(OpLineTo, x, y)
	return cb
}

// Rectangle draws a rectangle.
func (cb *ContentBuilder) Rectangle(x, y, width, height float64) *ContentBuilder {
	cb.stream.AddOperation(OpRectangle, x, y, width, height)
	return cb
}

// ClosePath closes the current path.
func (cb *ContentBuilder) ClosePath() *ContentBuilder {
	cb.stream.AddOperation(OpClosePath)
	return cb
}

// Stroke strokes the path.
func (cb *ContentBuilder) Stroke() *ContentBuilder {
	cb.stream.AddOperation(OpStroke)
	return cb
}

// Fill fills the path.
func (cb *ContentBuilder) Fill() *ContentBuilder {
	cb.stream.AddOperation(OpFill)
	return cb
}

// FillAndStroke fills and strokes the path.
func (cb *ContentBuilder) FillAndStroke() *ContentBuilder {
	cb.stream.AddOperation(OpFillAndStroke)
	return cb
}

// Clip sets the clipping path.
func (cb *ContentBuilder) Clip() *ContentBuilder {
	cb.stream.AddOperation(OpClip)
	return cb
}

// BeginText begins a text object.
func (cb *ContentBuilder) BeginText() *ContentBuilder {
	cb.stream.AddOperation(OpBeginText)
	return cb
}

// EndText ends a text object.
func (cb *ContentBuilder) EndText() *ContentBuilder {
	cb.stream.AddOperation(OpEndText)
	return cb
}

// SetFont sets the font and size.
func (cb *ContentBuilder) SetFont(font string, size float64) *ContentBuilder {
	cb.stream.AddOperation(OpSetFont, generic.NameObject(font), size)
	return cb
}

// TextPosition sets the text position.
func (cb *ContentBuilder) TextPosition(x, y float64) *ContentBuilder {
	cb.stream.AddOperation(OpTextMove, x, y)
	return cb
}

// ShowText shows text.
func (cb *ContentBuilder) ShowText(text string) *ContentBuilder {
	cb.stream.AddOperation(OpShowText, "("+escapeString(text)+")")
	return cb
}

// SetStrokeColor sets the stroke color (RGB).
func (cb *ContentBuilder) SetStrokeColor(r, g, b float64) *ContentBuilder {
	cb.stream.AddOperation(OpSetStrokeRGB, r, g, b)
	return cb
}

// SetFillColor sets the fill color (RGB).
func (cb *ContentBuilder) SetFillColor(r, g, b float64) *ContentBuilder {
	cb.stream.AddOperation(OpSetFillRGB, r, g, b)
	return cb
}

// SetStrokeGray sets the stroke color (grayscale).
func (cb *ContentBuilder) SetStrokeGray(gray float64) *ContentBuilder {
	cb.stream.AddOperation(OpSetStrokeGray, gray)
	return cb
}

// SetFillGray sets the fill color (grayscale).
func (cb *ContentBuilder) SetFillGray(gray float64) *ContentBuilder {
	cb.stream.AddOperation(OpSetFillGray, gray)
	return cb
}

// SetLineWidth sets the line width.
func (cb *ContentBuilder) SetLineWidth(width float64) *ContentBuilder {
	cb.stream.AddOperation(OpSetLineWidth, width)
	return cb
}

// PaintXObject paints an XObject.
func (cb *ContentBuilder) PaintXObject(name string) *ContentBuilder {
	cb.stream.AddOperation(OpPaintXObject, generic.NameObject(name))
	return cb
}

// Build returns the content stream.
func (cb *ContentBuilder) Build() *ContentStream {
	return cb.stream
}

// Render renders the content stream to bytes.
func (cb *ContentBuilder) Render() []byte {
	return cb.stream.Render()
}

// Helper functions

func escapeString(s string) string {
	var buf bytes.Buffer
	for _, c := range s {
		switch c {
		case '(':
			buf.WriteString("\\(")
		case ')':
			buf.WriteString("\\)")
		case '\\':
			buf.WriteString("\\\\")
		default:
			buf.WriteRune(c)
		}
	}
	return buf.String()
}

func cosine(x float64) float64 {
	// Taylor series approximation
	x = mod(x, 2*3.14159265358979323846)
	result := 1.0
	term := 1.0
	for i := 1; i < 10; i++ {
		term *= -x * x / float64(2*i*(2*i-1))
		result += term
	}
	return result
}

func sine(x float64) float64 {
	// Taylor series approximation
	x = mod(x, 2*3.14159265358979323846)
	result := x
	term := x
	for i := 1; i < 10; i++ {
		term *= -x * x / float64((2*i+1)*(2*i))
		result += term
	}
	return result
}

func mod(x, y float64) float64 {
	for x >= y {
		x -= y
	}
	for x < 0 {
		x += y
	}
	return x
}
