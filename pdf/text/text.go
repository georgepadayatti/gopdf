// Package text provides PDF text rendering and layout.
package text

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"unicode"

	"github.com/georgepadayatti/gopdf/pdf/fonts"
)

// TextAlign represents text alignment.
type TextAlign int

const (
	AlignLeft TextAlign = iota
	AlignCenter
	AlignRight
	AlignJustify
)

// String returns the string representation.
func (a TextAlign) String() string {
	switch a {
	case AlignLeft:
		return "left"
	case AlignCenter:
		return "center"
	case AlignRight:
		return "right"
	case AlignJustify:
		return "justify"
	default:
		return "left"
	}
}

// ParseTextAlign parses a text alignment string.
func ParseTextAlign(s string) TextAlign {
	switch strings.ToLower(s) {
	case "center", "centre":
		return AlignCenter
	case "right":
		return AlignRight
	case "justify", "justified":
		return AlignJustify
	default:
		return AlignLeft
	}
}

// VerticalAlign represents vertical alignment.
type VerticalAlign int

const (
	VAlignTop VerticalAlign = iota
	VAlignMiddle
	VAlignBottom
)

// String returns the string representation.
func (v VerticalAlign) String() string {
	switch v {
	case VAlignTop:
		return "top"
	case VAlignMiddle:
		return "middle"
	case VAlignBottom:
		return "bottom"
	default:
		return "top"
	}
}

// Color represents an RGB color.
type Color struct {
	R, G, B float64 // 0.0 to 1.0
}

// Black returns black color.
func Black() Color {
	return Color{0, 0, 0}
}

// White returns white color.
func White() Color {
	return Color{1, 1, 1}
}

// Red returns red color.
func Red() Color {
	return Color{1, 0, 0}
}

// Green returns green color.
func Green() Color {
	return Color{0, 1, 0}
}

// Blue returns blue color.
func Blue() Color {
	return Color{0, 0, 1}
}

// Gray returns a gray color.
func Gray(level float64) Color {
	return Color{level, level, level}
}

// RGB creates a color from RGB values (0-255).
func RGB(r, g, b int) Color {
	return Color{
		R: float64(r) / 255.0,
		G: float64(g) / 255.0,
		B: float64(b) / 255.0,
	}
}

// Hex creates a color from a hex string (e.g., "#FF0000" or "FF0000").
func Hex(s string) Color {
	s = strings.TrimPrefix(s, "#")
	if len(s) != 6 {
		return Black()
	}
	var r, g, b int
	fmt.Sscanf(s, "%02x%02x%02x", &r, &g, &b)
	return RGB(r, g, b)
}

// TextStyle defines styling for text.
type TextStyle struct {
	Font      fonts.Font
	FontSize  float64
	Color     Color
	Bold      bool
	Italic    bool
	Underline bool
	Strikeout bool
}

// NewTextStyle creates a new text style.
func NewTextStyle(font fonts.Font, fontSize float64) *TextStyle {
	return &TextStyle{
		Font:     font,
		FontSize: fontSize,
		Color:    Black(),
	}
}

// WithColor returns a copy with the specified color.
func (s *TextStyle) WithColor(c Color) *TextStyle {
	copy := *s
	copy.Color = c
	return &copy
}

// WithBold returns a copy with bold enabled.
func (s *TextStyle) WithBold(bold bool) *TextStyle {
	copy := *s
	copy.Bold = bold
	return &copy
}

// WithItalic returns a copy with italic enabled.
func (s *TextStyle) WithItalic(italic bool) *TextStyle {
	copy := *s
	copy.Italic = italic
	return &copy
}

// WithUnderline returns a copy with underline enabled.
func (s *TextStyle) WithUnderline(underline bool) *TextStyle {
	copy := *s
	copy.Underline = underline
	return &copy
}

// LineHeight returns the line height.
func (s *TextStyle) LineHeight() float64 {
	return s.Font.Metrics().GetLineHeight(s.FontSize)
}

// StringWidth returns the width of a string.
func (s *TextStyle) StringWidth(text string) float64 {
	return s.Font.Metrics().GetStringWidth(text, s.FontSize)
}

// Ascender returns the ascender height.
func (s *TextStyle) Ascender() float64 {
	m := s.Font.Metrics()
	return m.Ascender * s.FontSize / m.UnitsPerEm
}

// Descender returns the descender depth (negative).
func (s *TextStyle) Descender() float64 {
	m := s.Font.Metrics()
	return m.Descender * s.FontSize / m.UnitsPerEm
}

// TextSpan represents a segment of text with a style.
type TextSpan struct {
	Text  string
	Style *TextStyle
}

// NewTextSpan creates a new text span.
func NewTextSpan(text string, style *TextStyle) *TextSpan {
	return &TextSpan{
		Text:  text,
		Style: style,
	}
}

// Width returns the width of the span.
func (s *TextSpan) Width() float64 {
	return s.Style.StringWidth(s.Text)
}

// TextLine represents a line of text with potentially multiple spans.
type TextLine struct {
	Spans      []*TextSpan
	Width      float64
	Height     float64
	Baseline   float64
	WordSpaces int // Number of word spaces for justification
}

// NewTextLine creates a new text line.
func NewTextLine() *TextLine {
	return &TextLine{
		Spans: make([]*TextSpan, 0),
	}
}

// AddSpan adds a span to the line.
func (l *TextLine) AddSpan(span *TextSpan) {
	l.Spans = append(l.Spans, span)
	l.Width += span.Width()

	// Update height and baseline
	if span.Style != nil {
		height := span.Style.LineHeight()
		if height > l.Height {
			l.Height = height
		}
		baseline := span.Style.Ascender()
		if baseline > l.Baseline {
			l.Baseline = baseline
		}
	}

	// Count word spaces
	l.WordSpaces += strings.Count(span.Text, " ")
}

// IsEmpty returns true if the line has no spans.
func (l *TextLine) IsEmpty() bool {
	return len(l.Spans) == 0
}

// Text returns the combined text of all spans.
func (l *TextLine) Text() string {
	var sb strings.Builder
	for _, span := range l.Spans {
		sb.WriteString(span.Text)
	}
	return sb.String()
}

// TextBlock represents a block of formatted text.
type TextBlock struct {
	Lines          []*TextLine
	Width          float64
	Height         float64
	MaxWidth       float64
	Align          TextAlign
	VerticalAlign  VerticalAlign
	LineSpacing    float64 // Additional spacing between lines
	ParagraphSpace float64 // Space between paragraphs
}

// NewTextBlock creates a new text block.
func NewTextBlock(maxWidth float64) *TextBlock {
	return &TextBlock{
		Lines:          make([]*TextLine, 0),
		MaxWidth:       maxWidth,
		Align:          AlignLeft,
		VerticalAlign:  VAlignTop,
		LineSpacing:    0,
		ParagraphSpace: 0,
	}
}

// AddLine adds a line to the block.
func (b *TextBlock) AddLine(line *TextLine) {
	b.Lines = append(b.Lines, line)

	if line.Width > b.Width {
		b.Width = line.Width
	}

	if len(b.Lines) == 1 {
		b.Height = line.Height
	} else {
		b.Height += b.LineSpacing + line.Height
	}
}

// SetAlignment sets the text alignment.
func (b *TextBlock) SetAlignment(align TextAlign) {
	b.Align = align
}

// SetVerticalAlignment sets the vertical alignment.
func (b *TextBlock) SetVerticalAlignment(valign VerticalAlign) {
	b.VerticalAlign = valign
}

// TextFormatter formats text into blocks.
type TextFormatter struct {
	DefaultStyle *TextStyle
	MaxWidth     float64
	Align        TextAlign
	LineSpacing  float64
}

// NewTextFormatter creates a new text formatter.
func NewTextFormatter(style *TextStyle, maxWidth float64) *TextFormatter {
	return &TextFormatter{
		DefaultStyle: style,
		MaxWidth:     maxWidth,
		Align:        AlignLeft,
		LineSpacing:  0,
	}
}

// FormatText formats plain text into a text block.
func (f *TextFormatter) FormatText(text string) *TextBlock {
	block := NewTextBlock(f.MaxWidth)
	block.Align = f.Align
	block.LineSpacing = f.LineSpacing

	paragraphs := strings.Split(text, "\n")

	for _, paragraph := range paragraphs {
		if paragraph == "" {
			// Empty line
			line := NewTextLine()
			line.Height = f.DefaultStyle.LineHeight()
			block.AddLine(line)
			continue
		}

		lines := f.wrapText(paragraph, f.DefaultStyle)
		for _, line := range lines {
			block.AddLine(line)
		}
	}

	return block
}

// FormatSpans formats styled text spans into a text block.
func (f *TextFormatter) FormatSpans(spans []*TextSpan) *TextBlock {
	block := NewTextBlock(f.MaxWidth)
	block.Align = f.Align
	block.LineSpacing = f.LineSpacing

	currentLine := NewTextLine()
	currentLineWidth := 0.0

	for _, span := range spans {
		words := splitIntoWords(span.Text)

		for _, word := range words {
			wordSpan := NewTextSpan(word, span.Style)
			wordWidth := wordSpan.Width()

			// Check if word fits on current line
			if currentLineWidth+wordWidth <= f.MaxWidth || currentLine.IsEmpty() {
				currentLine.AddSpan(wordSpan)
				currentLineWidth += wordWidth
			} else {
				// Start new line
				block.AddLine(currentLine)
				currentLine = NewTextLine()
				currentLine.AddSpan(NewTextSpan(strings.TrimLeft(word, " "), span.Style))
				currentLineWidth = span.Style.StringWidth(strings.TrimLeft(word, " "))
			}
		}
	}

	if !currentLine.IsEmpty() {
		block.AddLine(currentLine)
	}

	return block
}

// wrapText wraps text to fit within the max width.
func (f *TextFormatter) wrapText(text string, style *TextStyle) []*TextLine {
	var lines []*TextLine
	words := strings.Fields(text)

	if len(words) == 0 {
		return lines
	}

	currentLine := NewTextLine()
	currentText := ""

	for i, word := range words {
		testText := currentText
		if testText != "" {
			testText += " "
		}
		testText += word

		testWidth := style.StringWidth(testText)

		if testWidth <= f.MaxWidth || currentText == "" {
			currentText = testText
		} else {
			// Finish current line
			currentLine.AddSpan(NewTextSpan(currentText, style))
			lines = append(lines, currentLine)

			// Start new line
			currentLine = NewTextLine()
			currentText = word

			// Handle last word
			if i == len(words)-1 {
				currentLine.AddSpan(NewTextSpan(currentText, style))
				lines = append(lines, currentLine)
			}
			continue
		}

		// Handle last word
		if i == len(words)-1 {
			currentLine.AddSpan(NewTextSpan(currentText, style))
			lines = append(lines, currentLine)
		}
	}

	return lines
}

// splitIntoWords splits text into words while preserving spaces.
func splitIntoWords(text string) []string {
	var words []string
	var current strings.Builder

	for i, r := range text {
		if unicode.IsSpace(r) {
			if current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
			// Include the space with the next word
			if i+1 < len(text) {
				current.WriteRune(r)
			} else {
				words = append(words, string(r))
			}
		} else {
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		words = append(words, current.String())
	}

	return words
}

// TextRenderer renders text to PDF content streams.
type TextRenderer struct {
	fontRegistry *fonts.FontRegistry
}

// NewTextRenderer creates a new text renderer.
func NewTextRenderer(registry *fonts.FontRegistry) *TextRenderer {
	return &TextRenderer{
		fontRegistry: registry,
	}
}

// RenderText renders a simple text string at a position.
func (r *TextRenderer) RenderText(text string, x, y float64, style *TextStyle) []byte {
	var buf bytes.Buffer

	fontRef := r.fontRegistry.Register(style.Font)

	buf.WriteString("BT\n")

	// Set color
	buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f rg\n", style.Color.R, style.Color.G, style.Color.B))

	// Set font
	buf.WriteString(fmt.Sprintf("/%s %.2f Tf\n", fontRef, style.FontSize))

	// Position
	buf.WriteString(fmt.Sprintf("%.2f %.2f Td\n", x, y))

	// Show text
	encoded := style.Font.Encode(text)
	buf.WriteString("(")
	buf.Write(escapeStringBytes(encoded))
	buf.WriteString(") Tj\n")

	buf.WriteString("ET\n")

	// Draw underline if needed
	if style.Underline {
		underlineY := y - style.FontSize*0.1
		underlineWidth := style.StringWidth(text)
		buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f RG\n", style.Color.R, style.Color.G, style.Color.B))
		buf.WriteString(fmt.Sprintf("%.2f w\n", style.FontSize*0.05))
		buf.WriteString(fmt.Sprintf("%.2f %.2f m\n", x, underlineY))
		buf.WriteString(fmt.Sprintf("%.2f %.2f l\n", x+underlineWidth, underlineY))
		buf.WriteString("S\n")
	}

	// Draw strikeout if needed
	if style.Strikeout {
		strikeY := y + style.FontSize*0.3
		strikeWidth := style.StringWidth(text)
		buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f RG\n", style.Color.R, style.Color.G, style.Color.B))
		buf.WriteString(fmt.Sprintf("%.2f w\n", style.FontSize*0.05))
		buf.WriteString(fmt.Sprintf("%.2f %.2f m\n", x, strikeY))
		buf.WriteString(fmt.Sprintf("%.2f %.2f l\n", x+strikeWidth, strikeY))
		buf.WriteString("S\n")
	}

	return buf.Bytes()
}

// RenderLine renders a text line at a position.
func (r *TextRenderer) RenderLine(line *TextLine, x, y float64, align TextAlign, maxWidth float64) []byte {
	var buf bytes.Buffer

	// Calculate starting X based on alignment
	startX := x
	switch align {
	case AlignCenter:
		startX = x + (maxWidth-line.Width)/2
	case AlignRight:
		startX = x + maxWidth - line.Width
	case AlignJustify:
		// For justified text, we'll use word spacing
		startX = x
	}

	currentX := startX

	buf.WriteString("BT\n")

	for _, span := range line.Spans {
		fontRef := r.fontRegistry.Register(span.Style.Font)

		// Set color
		buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f rg\n", span.Style.Color.R, span.Style.Color.G, span.Style.Color.B))

		// Set font
		buf.WriteString(fmt.Sprintf("/%s %.2f Tf\n", fontRef, span.Style.FontSize))

		// Position
		buf.WriteString(fmt.Sprintf("%.2f %.2f Td\n", currentX, y))

		// For justified text, adjust word spacing
		if align == AlignJustify && line.WordSpaces > 0 {
			extraSpace := (maxWidth - line.Width) / float64(line.WordSpaces)
			buf.WriteString(fmt.Sprintf("%.4f Tw\n", extraSpace))
		}

		// Show text
		encoded := span.Style.Font.Encode(span.Text)
		buf.WriteString("(")
		buf.Write(escapeStringBytes(encoded))
		buf.WriteString(") Tj\n")

		currentX += span.Width()
	}

	buf.WriteString("ET\n")

	// Reset word spacing
	if align == AlignJustify {
		buf.WriteString("0 Tw\n")
	}

	// Draw decorations
	currentX = startX
	for _, span := range line.Spans {
		if span.Style.Underline {
			underlineY := y - span.Style.FontSize*0.1
			buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f RG\n", span.Style.Color.R, span.Style.Color.G, span.Style.Color.B))
			buf.WriteString(fmt.Sprintf("%.2f w\n", span.Style.FontSize*0.05))
			buf.WriteString(fmt.Sprintf("%.2f %.2f m\n", currentX, underlineY))
			buf.WriteString(fmt.Sprintf("%.2f %.2f l\n", currentX+span.Width(), underlineY))
			buf.WriteString("S\n")
		}

		if span.Style.Strikeout {
			strikeY := y + span.Style.FontSize*0.3
			buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f RG\n", span.Style.Color.R, span.Style.Color.G, span.Style.Color.B))
			buf.WriteString(fmt.Sprintf("%.2f w\n", span.Style.FontSize*0.05))
			buf.WriteString(fmt.Sprintf("%.2f %.2f m\n", currentX, strikeY))
			buf.WriteString(fmt.Sprintf("%.2f %.2f l\n", currentX+span.Width(), strikeY))
			buf.WriteString("S\n")
		}

		currentX += span.Width()
	}

	return buf.Bytes()
}

// RenderBlock renders a text block at a position.
func (r *TextRenderer) RenderBlock(block *TextBlock, x, y, boxHeight float64) []byte {
	var buf bytes.Buffer

	// Calculate starting Y based on vertical alignment
	startY := y
	switch block.VerticalAlign {
	case VAlignMiddle:
		startY = y + (boxHeight-block.Height)/2
	case VAlignBottom:
		startY = y + boxHeight - block.Height
	}

	currentY := startY

	for i, line := range block.Lines {
		// Don't justify the last line
		align := block.Align
		if align == AlignJustify && i == len(block.Lines)-1 {
			align = AlignLeft
		}

		lineY := currentY - line.Baseline
		buf.Write(r.RenderLine(line, x, lineY, align, block.MaxWidth))

		currentY -= line.Height + block.LineSpacing
	}

	return buf.Bytes()
}

// escapeStringBytes escapes bytes for use in a PDF string.
func escapeStringBytes(data []byte) []byte {
	var buf bytes.Buffer
	for _, b := range data {
		switch b {
		case '\\':
			buf.WriteString("\\\\")
		case '(':
			buf.WriteString("\\(")
		case ')':
			buf.WriteString("\\)")
		case '\r':
			buf.WriteString("\\r")
		case '\n':
			buf.WriteString("\\n")
		case '\t':
			buf.WriteString("\\t")
		default:
			if b < 32 || b > 126 {
				buf.WriteString(fmt.Sprintf("\\%03o", b))
			} else {
				buf.WriteByte(b)
			}
		}
	}
	return buf.Bytes()
}

// TextBox represents a rectangular text area.
type TextBox struct {
	X, Y            float64
	Width, Height   float64
	Padding         float64
	Border          bool
	BorderColor     Color
	BorderWidth     float64
	Background      bool
	BackgroundColor Color
}

// NewTextBox creates a new text box.
func NewTextBox(x, y, width, height float64) *TextBox {
	return &TextBox{
		X:               x,
		Y:               y,
		Width:           width,
		Height:          height,
		Padding:         0,
		Border:          false,
		BorderColor:     Black(),
		BorderWidth:     1,
		Background:      false,
		BackgroundColor: White(),
	}
}

// WithPadding sets the padding.
func (b *TextBox) WithPadding(padding float64) *TextBox {
	b.Padding = padding
	return b
}

// WithBorder enables a border.
func (b *TextBox) WithBorder(color Color, width float64) *TextBox {
	b.Border = true
	b.BorderColor = color
	b.BorderWidth = width
	return b
}

// WithBackground enables a background.
func (b *TextBox) WithBackground(color Color) *TextBox {
	b.Background = true
	b.BackgroundColor = color
	return b
}

// InnerWidth returns the usable width after padding.
func (b *TextBox) InnerWidth() float64 {
	return b.Width - 2*b.Padding
}

// InnerHeight returns the usable height after padding.
func (b *TextBox) InnerHeight() float64 {
	return b.Height - 2*b.Padding
}

// RenderBox renders the text box background and border.
func (b *TextBox) RenderBox() []byte {
	var buf bytes.Buffer

	// Background
	if b.Background {
		buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f rg\n", b.BackgroundColor.R, b.BackgroundColor.G, b.BackgroundColor.B))
		buf.WriteString(fmt.Sprintf("%.2f %.2f %.2f %.2f re\n", b.X, b.Y, b.Width, b.Height))
		buf.WriteString("f\n")
	}

	// Border
	if b.Border {
		buf.WriteString(fmt.Sprintf("%.3f %.3f %.3f RG\n", b.BorderColor.R, b.BorderColor.G, b.BorderColor.B))
		buf.WriteString(fmt.Sprintf("%.2f w\n", b.BorderWidth))
		buf.WriteString(fmt.Sprintf("%.2f %.2f %.2f %.2f re\n", b.X, b.Y, b.Width, b.Height))
		buf.WriteString("S\n")
	}

	return buf.Bytes()
}

// TextBoxRenderer renders text within a text box.
type TextBoxRenderer struct {
	renderer *TextRenderer
}

// NewTextBoxRenderer creates a new text box renderer.
func NewTextBoxRenderer(registry *fonts.FontRegistry) *TextBoxRenderer {
	return &TextBoxRenderer{
		renderer: NewTextRenderer(registry),
	}
}

// RenderTextInBox renders text inside a text box.
func (r *TextBoxRenderer) RenderTextInBox(text string, box *TextBox, style *TextStyle, align TextAlign, valign VerticalAlign) []byte {
	var buf bytes.Buffer

	// Render box first
	buf.Write(box.RenderBox())

	// Format text to fit
	formatter := NewTextFormatter(style, box.InnerWidth())
	formatter.Align = align
	block := formatter.FormatText(text)
	block.VerticalAlign = valign

	// Calculate content position
	contentX := box.X + box.Padding
	contentY := box.Y + box.Height - box.Padding // PDF coordinates start at bottom

	// Render text block
	buf.Write(r.renderer.RenderBlock(block, contentX, contentY, box.InnerHeight()))

	return buf.Bytes()
}

// RenderSpansInBox renders styled spans inside a text box.
func (r *TextBoxRenderer) RenderSpansInBox(spans []*TextSpan, box *TextBox, align TextAlign, valign VerticalAlign) []byte {
	var buf bytes.Buffer

	// Render box first
	buf.Write(box.RenderBox())

	// Format spans to fit
	formatter := NewTextFormatter(spans[0].Style, box.InnerWidth())
	formatter.Align = align
	block := formatter.FormatSpans(spans)
	block.VerticalAlign = valign

	// Calculate content position
	contentX := box.X + box.Padding
	contentY := box.Y + box.Height - box.Padding

	// Render text block
	buf.Write(r.renderer.RenderBlock(block, contentX, contentY, box.InnerHeight()))

	return buf.Bytes()
}

// Paragraph represents a paragraph with specific formatting.
type Paragraph struct {
	Spans           []*TextSpan
	Align           TextAlign
	FirstLineIndent float64
	LeftMargin      float64
	RightMargin     float64
	SpaceBefore     float64
	SpaceAfter      float64
}

// NewParagraph creates a new paragraph.
func NewParagraph(text string, style *TextStyle) *Paragraph {
	return &Paragraph{
		Spans: []*TextSpan{NewTextSpan(text, style)},
		Align: AlignLeft,
	}
}

// AddSpan adds a span to the paragraph.
func (p *Paragraph) AddSpan(span *TextSpan) {
	p.Spans = append(p.Spans, span)
}

// SetIndent sets the first line indent.
func (p *Paragraph) SetIndent(indent float64) {
	p.FirstLineIndent = indent
}

// SetMargins sets the left and right margins.
func (p *Paragraph) SetMargins(left, right float64) {
	p.LeftMargin = left
	p.RightMargin = right
}

// SetSpacing sets the space before and after.
func (p *Paragraph) SetSpacing(before, after float64) {
	p.SpaceBefore = before
	p.SpaceAfter = after
}

// Document represents a simple text document layout.
type Document struct {
	Paragraphs   []*Paragraph
	Width        float64
	Height       float64
	MarginTop    float64
	MarginBottom float64
	MarginLeft   float64
	MarginRight  float64
}

// NewDocument creates a new document.
func NewDocument(width, height float64) *Document {
	return &Document{
		Paragraphs:   make([]*Paragraph, 0),
		Width:        width,
		Height:       height,
		MarginTop:    72,
		MarginBottom: 72,
		MarginLeft:   72,
		MarginRight:  72,
	}
}

// SetMargins sets all margins.
func (d *Document) SetMargins(top, right, bottom, left float64) {
	d.MarginTop = top
	d.MarginRight = right
	d.MarginBottom = bottom
	d.MarginLeft = left
}

// AddParagraph adds a paragraph to the document.
func (d *Document) AddParagraph(p *Paragraph) {
	d.Paragraphs = append(d.Paragraphs, p)
}

// ContentWidth returns the usable content width.
func (d *Document) ContentWidth() float64 {
	return d.Width - d.MarginLeft - d.MarginRight
}

// ContentHeight returns the usable content height.
func (d *Document) ContentHeight() float64 {
	return d.Height - d.MarginTop - d.MarginBottom
}

// CharacterSpacing adjusts character spacing in a content stream.
func CharacterSpacing(spacing float64) string {
	return fmt.Sprintf("%.4f Tc\n", spacing)
}

// WordSpacing adjusts word spacing in a content stream.
func WordSpacing(spacing float64) string {
	return fmt.Sprintf("%.4f Tw\n", spacing)
}

// TextRise sets the text rise (superscript/subscript) in a content stream.
func TextRise(rise float64) string {
	return fmt.Sprintf("%.4f Ts\n", rise)
}

// TextMatrix sets the text matrix in a content stream.
func TextMatrix(a, b, c, d, e, f float64) string {
	return fmt.Sprintf("%.4f %.4f %.4f %.4f %.4f %.4f Tm\n", a, b, c, d, e, f)
}

// RotatedText creates a text matrix for rotated text.
func RotatedText(x, y, angleDeg float64) string {
	angleRad := angleDeg * math.Pi / 180
	cos := math.Cos(angleRad)
	sin := math.Sin(angleRad)
	return TextMatrix(cos, sin, -sin, cos, x, y)
}

// ScaledText creates a text matrix for scaled text.
func ScaledText(x, y, scaleX, scaleY float64) string {
	return TextMatrix(scaleX, 0, 0, scaleY, x, y)
}

// TextMeasurer provides text measurement utilities.
type TextMeasurer struct {
	Font     fonts.Font
	FontSize float64
}

// NewTextMeasurer creates a new text measurer.
func NewTextMeasurer(font fonts.Font, fontSize float64) *TextMeasurer {
	return &TextMeasurer{
		Font:     font,
		FontSize: fontSize,
	}
}

// StringWidth returns the width of a string.
func (m *TextMeasurer) StringWidth(s string) float64 {
	return m.Font.Metrics().GetStringWidth(s, m.FontSize)
}

// CharWidth returns the width of a character.
func (m *TextMeasurer) CharWidth(r rune) float64 {
	return m.Font.Metrics().GetWidth(r) * m.FontSize / m.Font.Metrics().UnitsPerEm
}

// LineHeight returns the line height.
func (m *TextMeasurer) LineHeight() float64 {
	return m.Font.Metrics().GetLineHeight(m.FontSize)
}

// Ascender returns the ascender height.
func (m *TextMeasurer) Ascender() float64 {
	metrics := m.Font.Metrics()
	return metrics.Ascender * m.FontSize / metrics.UnitsPerEm
}

// Descender returns the descender depth (negative).
func (m *TextMeasurer) Descender() float64 {
	metrics := m.Font.Metrics()
	return metrics.Descender * m.FontSize / metrics.UnitsPerEm
}

// FitWidth returns the number of characters that fit within a width.
func (m *TextMeasurer) FitWidth(s string, maxWidth float64) int {
	width := 0.0
	count := 0
	for _, r := range s {
		charWidth := m.CharWidth(r)
		if width+charWidth > maxWidth {
			break
		}
		width += charWidth
		count++
	}
	return count
}

// TruncateToFit truncates a string to fit within a width, adding ellipsis if needed.
func (m *TextMeasurer) TruncateToFit(s string, maxWidth float64, ellipsis string) string {
	fullWidth := m.StringWidth(s)
	if fullWidth <= maxWidth {
		return s
	}

	ellipsisWidth := m.StringWidth(ellipsis)
	targetWidth := maxWidth - ellipsisWidth

	if targetWidth <= 0 {
		return ellipsis
	}

	count := m.FitWidth(s, targetWidth)
	if count == 0 {
		return ellipsis
	}

	runes := []rune(s)
	return string(runes[:count]) + ellipsis
}

// WrapLines wraps text into lines that fit within a width.
func (m *TextMeasurer) WrapLines(text string, maxWidth float64) []string {
	layout := fonts.NewTextLayout(m.Font, m.FontSize)
	return layout.WrapText(text, maxWidth)
}

// CenterText calculates the X position to center text.
func (m *TextMeasurer) CenterText(text string, boxWidth float64) float64 {
	textWidth := m.StringWidth(text)
	return (boxWidth - textWidth) / 2
}

// RightAlignText calculates the X position to right-align text.
func (m *TextMeasurer) RightAlignText(text string, boxWidth float64) float64 {
	textWidth := m.StringWidth(text)
	return boxWidth - textWidth
}
