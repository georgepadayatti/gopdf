package text

import (
	"strings"
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/fonts"
)

func getTestFont() fonts.Font {
	return fonts.NewStandardFont(fonts.Helvetica)
}

func getTestStyle() *TextStyle {
	return NewTextStyle(getTestFont(), 12)
}

// TextAlign tests

func TestTextAlignString(t *testing.T) {
	tests := []struct {
		align    TextAlign
		expected string
	}{
		{AlignLeft, "left"},
		{AlignCenter, "center"},
		{AlignRight, "right"},
		{AlignJustify, "justify"},
		{TextAlign(99), "left"},
	}

	for _, tt := range tests {
		if got := tt.align.String(); got != tt.expected {
			t.Errorf("TextAlign(%d).String() = %q, want %q", tt.align, got, tt.expected)
		}
	}
}

func TestParseTextAlign(t *testing.T) {
	tests := []struct {
		input    string
		expected TextAlign
	}{
		{"left", AlignLeft},
		{"LEFT", AlignLeft},
		{"center", AlignCenter},
		{"centre", AlignCenter},
		{"right", AlignRight},
		{"justify", AlignJustify},
		{"justified", AlignJustify},
		{"unknown", AlignLeft},
	}

	for _, tt := range tests {
		if got := ParseTextAlign(tt.input); got != tt.expected {
			t.Errorf("ParseTextAlign(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

// VerticalAlign tests

func TestVerticalAlignString(t *testing.T) {
	tests := []struct {
		valign   VerticalAlign
		expected string
	}{
		{VAlignTop, "top"},
		{VAlignMiddle, "middle"},
		{VAlignBottom, "bottom"},
		{VerticalAlign(99), "top"},
	}

	for _, tt := range tests {
		if got := tt.valign.String(); got != tt.expected {
			t.Errorf("VerticalAlign(%d).String() = %q, want %q", tt.valign, got, tt.expected)
		}
	}
}

// Color tests

func TestColorFunctions(t *testing.T) {
	black := Black()
	if black.R != 0 || black.G != 0 || black.B != 0 {
		t.Error("Black should be (0, 0, 0)")
	}

	white := White()
	if white.R != 1 || white.G != 1 || white.B != 1 {
		t.Error("White should be (1, 1, 1)")
	}

	red := Red()
	if red.R != 1 || red.G != 0 || red.B != 0 {
		t.Error("Red should be (1, 0, 0)")
	}

	green := Green()
	if green.R != 0 || green.G != 1 || green.B != 0 {
		t.Error("Green should be (0, 1, 0)")
	}

	blue := Blue()
	if blue.R != 0 || blue.G != 0 || blue.B != 1 {
		t.Error("Blue should be (0, 0, 1)")
	}
}

func TestGray(t *testing.T) {
	gray := Gray(0.5)
	if gray.R != 0.5 || gray.G != 0.5 || gray.B != 0.5 {
		t.Errorf("Gray(0.5) = (%v, %v, %v), want (0.5, 0.5, 0.5)", gray.R, gray.G, gray.B)
	}
}

func TestRGB(t *testing.T) {
	color := RGB(255, 128, 0)
	if color.R != 1.0 || color.G < 0.5 || color.G > 0.51 || color.B != 0 {
		t.Errorf("RGB(255, 128, 0) = (%v, %v, %v)", color.R, color.G, color.B)
	}
}

func TestHex(t *testing.T) {
	tests := []struct {
		hex string
		r, g, b float64
	}{
		{"#FF0000", 1.0, 0, 0},
		{"FF0000", 1.0, 0, 0},
		{"#00FF00", 0, 1.0, 0},
		{"#0000FF", 0, 0, 1.0},
		{"invalid", 0, 0, 0},
	}

	for _, tt := range tests {
		color := Hex(tt.hex)
		if color.R != tt.r || color.G != tt.g || color.B != tt.b {
			t.Errorf("Hex(%q) = (%v, %v, %v), want (%v, %v, %v)",
				tt.hex, color.R, color.G, color.B, tt.r, tt.g, tt.b)
		}
	}
}

// TextStyle tests

func TestNewTextStyle(t *testing.T) {
	font := getTestFont()
	style := NewTextStyle(font, 14)

	if style.Font != font {
		t.Error("Font not set")
	}
	if style.FontSize != 14 {
		t.Errorf("FontSize = %v, want 14", style.FontSize)
	}
	if style.Color != Black() {
		t.Error("Default color should be black")
	}
}

func TestTextStyleWithColor(t *testing.T) {
	style := getTestStyle()
	red := Red()
	newStyle := style.WithColor(red)

	if newStyle.Color != red {
		t.Error("WithColor should set color")
	}
	if style.Color == red {
		t.Error("Original style should not be modified")
	}
}

func TestTextStyleWithBold(t *testing.T) {
	style := getTestStyle()
	boldStyle := style.WithBold(true)

	if !boldStyle.Bold {
		t.Error("WithBold(true) should set Bold to true")
	}
	if style.Bold {
		t.Error("Original style should not be modified")
	}
}

func TestTextStyleWithItalic(t *testing.T) {
	style := getTestStyle()
	italicStyle := style.WithItalic(true)

	if !italicStyle.Italic {
		t.Error("WithItalic(true) should set Italic to true")
	}
}

func TestTextStyleWithUnderline(t *testing.T) {
	style := getTestStyle()
	underlineStyle := style.WithUnderline(true)

	if !underlineStyle.Underline {
		t.Error("WithUnderline(true) should set Underline to true")
	}
}

func TestTextStyleLineHeight(t *testing.T) {
	style := getTestStyle()
	height := style.LineHeight()

	if height <= 0 {
		t.Errorf("LineHeight = %v, should be positive", height)
	}
}

func TestTextStyleStringWidth(t *testing.T) {
	style := getTestStyle()
	width := style.StringWidth("Hello")

	if width <= 0 {
		t.Errorf("StringWidth = %v, should be positive", width)
	}

	// Longer string should be wider
	longerWidth := style.StringWidth("Hello World")
	if longerWidth <= width {
		t.Error("Longer string should have greater width")
	}
}

func TestTextStyleAscenderDescender(t *testing.T) {
	style := getTestStyle()

	ascender := style.Ascender()
	if ascender <= 0 {
		t.Errorf("Ascender = %v, should be positive", ascender)
	}

	descender := style.Descender()
	if descender >= 0 {
		t.Errorf("Descender = %v, should be negative", descender)
	}
}

// TextSpan tests

func TestNewTextSpan(t *testing.T) {
	style := getTestStyle()
	span := NewTextSpan("Hello", style)

	if span.Text != "Hello" {
		t.Errorf("Text = %q, want 'Hello'", span.Text)
	}
	if span.Style != style {
		t.Error("Style not set")
	}
}

func TestTextSpanWidth(t *testing.T) {
	style := getTestStyle()
	span := NewTextSpan("Hello", style)

	width := span.Width()
	if width <= 0 {
		t.Errorf("Width = %v, should be positive", width)
	}
}

// TextLine tests

func TestNewTextLine(t *testing.T) {
	line := NewTextLine()

	if len(line.Spans) != 0 {
		t.Error("New line should have no spans")
	}
	if !line.IsEmpty() {
		t.Error("New line should be empty")
	}
}

func TestTextLineAddSpan(t *testing.T) {
	line := NewTextLine()
	style := getTestStyle()
	span := NewTextSpan("Hello", style)

	line.AddSpan(span)

	if len(line.Spans) != 1 {
		t.Errorf("Spans count = %d, want 1", len(line.Spans))
	}
	if line.IsEmpty() {
		t.Error("Line should not be empty after adding span")
	}
	if line.Width <= 0 {
		t.Error("Line width should be positive")
	}
	if line.Height <= 0 {
		t.Error("Line height should be positive")
	}
}

func TestTextLineText(t *testing.T) {
	line := NewTextLine()
	style := getTestStyle()

	line.AddSpan(NewTextSpan("Hello", style))
	line.AddSpan(NewTextSpan(" World", style))

	if line.Text() != "Hello World" {
		t.Errorf("Text() = %q, want 'Hello World'", line.Text())
	}
}

func TestTextLineWordSpaces(t *testing.T) {
	line := NewTextLine()
	style := getTestStyle()

	line.AddSpan(NewTextSpan("Hello World", style))

	if line.WordSpaces != 1 {
		t.Errorf("WordSpaces = %d, want 1", line.WordSpaces)
	}
}

// TextBlock tests

func TestNewTextBlock(t *testing.T) {
	block := NewTextBlock(200)

	if block.MaxWidth != 200 {
		t.Errorf("MaxWidth = %v, want 200", block.MaxWidth)
	}
	if len(block.Lines) != 0 {
		t.Error("New block should have no lines")
	}
}

func TestTextBlockAddLine(t *testing.T) {
	block := NewTextBlock(200)
	line := NewTextLine()
	style := getTestStyle()
	line.AddSpan(NewTextSpan("Hello", style))

	block.AddLine(line)

	if len(block.Lines) != 1 {
		t.Errorf("Lines count = %d, want 1", len(block.Lines))
	}
	if block.Height <= 0 {
		t.Error("Block height should be positive")
	}
}

func TestTextBlockSetAlignment(t *testing.T) {
	block := NewTextBlock(200)
	block.SetAlignment(AlignCenter)

	if block.Align != AlignCenter {
		t.Errorf("Align = %v, want AlignCenter", block.Align)
	}
}

// TextFormatter tests

func TestNewTextFormatter(t *testing.T) {
	style := getTestStyle()
	formatter := NewTextFormatter(style, 200)

	if formatter.DefaultStyle != style {
		t.Error("DefaultStyle not set")
	}
	if formatter.MaxWidth != 200 {
		t.Errorf("MaxWidth = %v, want 200", formatter.MaxWidth)
	}
}

func TestTextFormatterFormatText(t *testing.T) {
	style := getTestStyle()
	formatter := NewTextFormatter(style, 200)

	block := formatter.FormatText("Hello World")

	if len(block.Lines) == 0 {
		t.Error("Block should have at least one line")
	}
}

func TestTextFormatterFormatTextMultiLine(t *testing.T) {
	style := getTestStyle()
	formatter := NewTextFormatter(style, 200)

	block := formatter.FormatText("Line 1\nLine 2\nLine 3")

	if len(block.Lines) != 3 {
		t.Errorf("Lines count = %d, want 3", len(block.Lines))
	}
}

func TestTextFormatterFormatTextWrapping(t *testing.T) {
	style := getTestStyle()
	formatter := NewTextFormatter(style, 50) // Narrow width

	block := formatter.FormatText("This is a long text that should wrap to multiple lines")

	if len(block.Lines) < 2 {
		t.Error("Text should wrap to multiple lines")
	}
}

func TestTextFormatterFormatSpans(t *testing.T) {
	style := getTestStyle()
	formatter := NewTextFormatter(style, 200)

	spans := []*TextSpan{
		NewTextSpan("Hello ", style),
		NewTextSpan("World", style.WithBold(true)),
	}

	block := formatter.FormatSpans(spans)

	if len(block.Lines) == 0 {
		t.Error("Block should have at least one line")
	}
}

// TextRenderer tests

func TestNewTextRenderer(t *testing.T) {
	registry := fonts.NewFontRegistry()
	renderer := NewTextRenderer(registry)

	if renderer.fontRegistry != registry {
		t.Error("Font registry not set")
	}
}

func TestTextRendererRenderText(t *testing.T) {
	registry := fonts.NewFontRegistry()
	renderer := NewTextRenderer(registry)
	style := getTestStyle()

	output := renderer.RenderText("Hello", 100, 700, style)

	if len(output) == 0 {
		t.Error("RenderText should produce output")
	}
	if !strings.Contains(string(output), "BT") {
		t.Error("Output should contain BT (begin text)")
	}
	if !strings.Contains(string(output), "ET") {
		t.Error("Output should contain ET (end text)")
	}
	if !strings.Contains(string(output), "Tf") {
		t.Error("Output should contain Tf (set font)")
	}
	if !strings.Contains(string(output), "Tj") {
		t.Error("Output should contain Tj (show text)")
	}
}

func TestTextRendererRenderTextWithUnderline(t *testing.T) {
	registry := fonts.NewFontRegistry()
	renderer := NewTextRenderer(registry)
	style := getTestStyle().WithUnderline(true)

	output := renderer.RenderText("Hello", 100, 700, style)

	if !strings.Contains(string(output), "S") {
		t.Error("Output should contain S (stroke) for underline")
	}
}

func TestTextRendererRenderTextWithStrikeout(t *testing.T) {
	registry := fonts.NewFontRegistry()
	renderer := NewTextRenderer(registry)
	style := getTestStyle()
	style.Strikeout = true

	output := renderer.RenderText("Hello", 100, 700, style)

	if !strings.Contains(string(output), "S") {
		t.Error("Output should contain S (stroke) for strikeout")
	}
}

func TestTextRendererRenderLine(t *testing.T) {
	registry := fonts.NewFontRegistry()
	renderer := NewTextRenderer(registry)
	style := getTestStyle()

	line := NewTextLine()
	line.AddSpan(NewTextSpan("Hello World", style))

	output := renderer.RenderLine(line, 100, 700, AlignLeft, 200)

	if len(output) == 0 {
		t.Error("RenderLine should produce output")
	}
}

func TestTextRendererRenderLineJustified(t *testing.T) {
	registry := fonts.NewFontRegistry()
	renderer := NewTextRenderer(registry)
	style := getTestStyle()

	line := NewTextLine()
	line.AddSpan(NewTextSpan("Hello World", style))

	output := renderer.RenderLine(line, 100, 700, AlignJustify, 200)

	if !strings.Contains(string(output), "Tw") {
		t.Error("Justified text should set word spacing")
	}
}

func TestTextRendererRenderBlock(t *testing.T) {
	registry := fonts.NewFontRegistry()
	renderer := NewTextRenderer(registry)
	style := getTestStyle()

	block := NewTextBlock(200)
	line := NewTextLine()
	line.AddSpan(NewTextSpan("Hello World", style))
	block.AddLine(line)

	output := renderer.RenderBlock(block, 100, 700, 100)

	if len(output) == 0 {
		t.Error("RenderBlock should produce output")
	}
}

// TextBox tests

func TestNewTextBox(t *testing.T) {
	box := NewTextBox(100, 600, 200, 100)

	if box.X != 100 || box.Y != 600 || box.Width != 200 || box.Height != 100 {
		t.Error("TextBox dimensions not set correctly")
	}
	if box.Border {
		t.Error("Border should be false by default")
	}
	if box.Background {
		t.Error("Background should be false by default")
	}
}

func TestTextBoxWithPadding(t *testing.T) {
	box := NewTextBox(100, 600, 200, 100).WithPadding(10)

	if box.Padding != 10 {
		t.Errorf("Padding = %v, want 10", box.Padding)
	}
	if box.InnerWidth() != 180 {
		t.Errorf("InnerWidth = %v, want 180", box.InnerWidth())
	}
	if box.InnerHeight() != 80 {
		t.Errorf("InnerHeight = %v, want 80", box.InnerHeight())
	}
}

func TestTextBoxWithBorder(t *testing.T) {
	box := NewTextBox(100, 600, 200, 100).WithBorder(Red(), 2)

	if !box.Border {
		t.Error("Border should be enabled")
	}
	if box.BorderColor != Red() {
		t.Error("BorderColor not set")
	}
	if box.BorderWidth != 2 {
		t.Errorf("BorderWidth = %v, want 2", box.BorderWidth)
	}
}

func TestTextBoxWithBackground(t *testing.T) {
	box := NewTextBox(100, 600, 200, 100).WithBackground(Gray(0.9))

	if !box.Background {
		t.Error("Background should be enabled")
	}
}

func TestTextBoxRenderBox(t *testing.T) {
	box := NewTextBox(100, 600, 200, 100).
		WithBorder(Black(), 1).
		WithBackground(White())

	output := box.RenderBox()

	if !strings.Contains(string(output), "re") {
		t.Error("Output should contain re (rectangle)")
	}
	if !strings.Contains(string(output), "f") {
		t.Error("Output should contain f (fill) for background")
	}
	if !strings.Contains(string(output), "S") {
		t.Error("Output should contain S (stroke) for border")
	}
}

// TextBoxRenderer tests

func TestNewTextBoxRenderer(t *testing.T) {
	registry := fonts.NewFontRegistry()
	renderer := NewTextBoxRenderer(registry)

	if renderer.renderer == nil {
		t.Error("Internal renderer not created")
	}
}

func TestTextBoxRendererRenderTextInBox(t *testing.T) {
	registry := fonts.NewFontRegistry()
	renderer := NewTextBoxRenderer(registry)
	style := getTestStyle()
	box := NewTextBox(100, 600, 200, 100).WithPadding(5)

	output := renderer.RenderTextInBox("Hello World", box, style, AlignLeft, VAlignTop)

	if len(output) == 0 {
		t.Error("RenderTextInBox should produce output")
	}
}

// Paragraph tests

func TestNewParagraph(t *testing.T) {
	style := getTestStyle()
	para := NewParagraph("Hello World", style)

	if len(para.Spans) != 1 {
		t.Errorf("Spans count = %d, want 1", len(para.Spans))
	}
	if para.Align != AlignLeft {
		t.Error("Default alignment should be left")
	}
}

func TestParagraphAddSpan(t *testing.T) {
	style := getTestStyle()
	para := NewParagraph("Hello", style)
	para.AddSpan(NewTextSpan(" World", style.WithBold(true)))

	if len(para.Spans) != 2 {
		t.Errorf("Spans count = %d, want 2", len(para.Spans))
	}
}

func TestParagraphSetIndent(t *testing.T) {
	style := getTestStyle()
	para := NewParagraph("Hello", style)
	para.SetIndent(20)

	if para.FirstLineIndent != 20 {
		t.Errorf("FirstLineIndent = %v, want 20", para.FirstLineIndent)
	}
}

func TestParagraphSetMargins(t *testing.T) {
	style := getTestStyle()
	para := NewParagraph("Hello", style)
	para.SetMargins(10, 20)

	if para.LeftMargin != 10 {
		t.Errorf("LeftMargin = %v, want 10", para.LeftMargin)
	}
	if para.RightMargin != 20 {
		t.Errorf("RightMargin = %v, want 20", para.RightMargin)
	}
}

func TestParagraphSetSpacing(t *testing.T) {
	style := getTestStyle()
	para := NewParagraph("Hello", style)
	para.SetSpacing(5, 10)

	if para.SpaceBefore != 5 {
		t.Errorf("SpaceBefore = %v, want 5", para.SpaceBefore)
	}
	if para.SpaceAfter != 10 {
		t.Errorf("SpaceAfter = %v, want 10", para.SpaceAfter)
	}
}

// Document tests

func TestNewDocument(t *testing.T) {
	doc := NewDocument(612, 792)

	if doc.Width != 612 || doc.Height != 792 {
		t.Error("Document dimensions not set correctly")
	}
	if len(doc.Paragraphs) != 0 {
		t.Error("New document should have no paragraphs")
	}
}

func TestDocumentSetMargins(t *testing.T) {
	doc := NewDocument(612, 792)
	doc.SetMargins(36, 36, 36, 36)

	if doc.MarginTop != 36 || doc.MarginRight != 36 ||
		doc.MarginBottom != 36 || doc.MarginLeft != 36 {
		t.Error("Margins not set correctly")
	}
}

func TestDocumentAddParagraph(t *testing.T) {
	doc := NewDocument(612, 792)
	style := getTestStyle()
	para := NewParagraph("Hello", style)

	doc.AddParagraph(para)

	if len(doc.Paragraphs) != 1 {
		t.Errorf("Paragraphs count = %d, want 1", len(doc.Paragraphs))
	}
}

func TestDocumentContentDimensions(t *testing.T) {
	doc := NewDocument(612, 792)
	doc.SetMargins(72, 72, 72, 72)

	if doc.ContentWidth() != 468 {
		t.Errorf("ContentWidth = %v, want 468", doc.ContentWidth())
	}
	if doc.ContentHeight() != 648 {
		t.Errorf("ContentHeight = %v, want 648", doc.ContentHeight())
	}
}

// Helper functions tests

func TestCharacterSpacing(t *testing.T) {
	output := CharacterSpacing(0.5)
	if !strings.Contains(output, "Tc") {
		t.Error("Output should contain Tc operator")
	}
}

func TestWordSpacing(t *testing.T) {
	output := WordSpacing(2.0)
	if !strings.Contains(output, "Tw") {
		t.Error("Output should contain Tw operator")
	}
}

func TestTextRise(t *testing.T) {
	output := TextRise(5.0)
	if !strings.Contains(output, "Ts") {
		t.Error("Output should contain Ts operator")
	}
}

func TestTextMatrix(t *testing.T) {
	output := TextMatrix(1, 0, 0, 1, 100, 700)
	if !strings.Contains(output, "Tm") {
		t.Error("Output should contain Tm operator")
	}
}

func TestRotatedText(t *testing.T) {
	output := RotatedText(100, 700, 45)
	if !strings.Contains(output, "Tm") {
		t.Error("Output should contain Tm operator")
	}
}

func TestScaledText(t *testing.T) {
	output := ScaledText(100, 700, 2, 1.5)
	if !strings.Contains(output, "Tm") {
		t.Error("Output should contain Tm operator")
	}
}

// TextMeasurer tests

func TestNewTextMeasurer(t *testing.T) {
	font := getTestFont()
	measurer := NewTextMeasurer(font, 12)

	if measurer.Font != font {
		t.Error("Font not set")
	}
	if measurer.FontSize != 12 {
		t.Errorf("FontSize = %v, want 12", measurer.FontSize)
	}
}

func TestTextMeasurerStringWidth(t *testing.T) {
	measurer := NewTextMeasurer(getTestFont(), 12)
	width := measurer.StringWidth("Hello")

	if width <= 0 {
		t.Errorf("StringWidth = %v, should be positive", width)
	}
}

func TestTextMeasurerCharWidth(t *testing.T) {
	measurer := NewTextMeasurer(getTestFont(), 12)
	width := measurer.CharWidth('A')

	if width <= 0 {
		t.Errorf("CharWidth = %v, should be positive", width)
	}
}

func TestTextMeasurerLineHeight(t *testing.T) {
	measurer := NewTextMeasurer(getTestFont(), 12)
	height := measurer.LineHeight()

	if height <= 0 {
		t.Errorf("LineHeight = %v, should be positive", height)
	}
}

func TestTextMeasurerAscenderDescender(t *testing.T) {
	measurer := NewTextMeasurer(getTestFont(), 12)

	ascender := measurer.Ascender()
	if ascender <= 0 {
		t.Errorf("Ascender = %v, should be positive", ascender)
	}

	descender := measurer.Descender()
	if descender >= 0 {
		t.Errorf("Descender = %v, should be negative", descender)
	}
}

func TestTextMeasurerFitWidth(t *testing.T) {
	measurer := NewTextMeasurer(getTestFont(), 12)

	count := measurer.FitWidth("Hello World", 30)
	if count <= 0 {
		t.Errorf("FitWidth = %d, should be positive", count)
	}
	if count > len("Hello World") {
		t.Error("FitWidth should not exceed string length")
	}
}

func TestTextMeasurerTruncateToFit(t *testing.T) {
	measurer := NewTextMeasurer(getTestFont(), 12)

	// Short string that fits
	result := measurer.TruncateToFit("Hi", 100, "...")
	if result != "Hi" {
		t.Errorf("TruncateToFit = %q, want 'Hi' (no truncation needed)", result)
	}

	// Long string that needs truncation
	result = measurer.TruncateToFit("Hello World This Is A Long String", 50, "...")
	if !strings.HasSuffix(result, "...") {
		t.Error("Truncated string should end with ellipsis")
	}
	if len(result) >= len("Hello World This Is A Long String") {
		t.Error("Truncated string should be shorter")
	}
}

func TestTextMeasurerWrapLines(t *testing.T) {
	measurer := NewTextMeasurer(getTestFont(), 12)

	lines := measurer.WrapLines("This is a long text that should wrap", 50)
	if len(lines) < 2 {
		t.Error("Text should wrap to multiple lines")
	}
}

func TestTextMeasurerCenterText(t *testing.T) {
	measurer := NewTextMeasurer(getTestFont(), 12)

	x := measurer.CenterText("Hello", 100)
	if x < 0 || x > 100 {
		t.Errorf("CenterText x = %v, should be between 0 and 100", x)
	}
}

func TestTextMeasurerRightAlignText(t *testing.T) {
	measurer := NewTextMeasurer(getTestFont(), 12)

	x := measurer.RightAlignText("Hello", 100)
	if x < 0 || x > 100 {
		t.Errorf("RightAlignText x = %v, should be between 0 and 100", x)
	}
}

// escapeStringBytes tests

func TestEscapeStringBytes(t *testing.T) {
	tests := []struct {
		input    []byte
		contains string
	}{
		{[]byte("Hello"), "Hello"},
		{[]byte("Hello\\World"), "\\\\"},
		{[]byte("Hello(World)"), "\\("},
		{[]byte("Hello\nWorld"), "\\n"},
		{[]byte("Hello\rWorld"), "\\r"},
		{[]byte("Hello\tWorld"), "\\t"},
	}

	for _, tt := range tests {
		result := escapeStringBytes(tt.input)
		if !strings.Contains(string(result), tt.contains) {
			t.Errorf("escapeStringBytes(%q) should contain %q", tt.input, tt.contains)
		}
	}
}

// Integration tests

func TestCompleteTextRendering(t *testing.T) {
	registry := fonts.NewFontRegistry()
	renderer := NewTextRenderer(registry)
	style := getTestStyle()

	// Create a text block
	formatter := NewTextFormatter(style, 200)
	formatter.Align = AlignJustify
	block := formatter.FormatText("This is a paragraph of text that should be formatted and rendered properly. It contains multiple sentences to test wrapping.")

	// Render it
	output := renderer.RenderBlock(block, 100, 700, 100)

	if len(output) == 0 {
		t.Error("Complete rendering should produce output")
	}
	if !strings.Contains(string(output), "BT") {
		t.Error("Output should contain text begin")
	}
}

func TestTextBoxWithFormattedContent(t *testing.T) {
	registry := fonts.NewFontRegistry()
	renderer := NewTextBoxRenderer(registry)
	style := getTestStyle()

	box := NewTextBox(50, 650, 200, 100).
		WithPadding(10).
		WithBorder(Black(), 1).
		WithBackground(Gray(0.95))

	output := renderer.RenderTextInBox(
		"This is some text in a box with padding, border, and background.",
		box, style, AlignCenter, VAlignMiddle)

	if len(output) == 0 {
		t.Error("Text box rendering should produce output")
	}

	// Should have box rendering
	if !strings.Contains(string(output), "re") {
		t.Error("Output should contain rectangle")
	}

	// Should have text rendering
	if !strings.Contains(string(output), "Tj") {
		t.Error("Output should contain text show")
	}
}

func TestMultiStyleSpans(t *testing.T) {
	registry := fonts.NewFontRegistry()
	renderer := NewTextRenderer(registry)
	normalStyle := getTestStyle()
	boldStyle := NewTextStyle(fonts.NewStandardFont(fonts.HelveticaBold), 12)
	italicStyle := NewTextStyle(fonts.NewStandardFont(fonts.HelveticaOblique), 12)

	spans := []*TextSpan{
		NewTextSpan("Normal ", normalStyle),
		NewTextSpan("Bold ", boldStyle),
		NewTextSpan("Italic", italicStyle),
	}

	formatter := NewTextFormatter(normalStyle, 300)
	block := formatter.FormatSpans(spans)

	output := renderer.RenderBlock(block, 100, 700, 50)

	if len(output) == 0 {
		t.Error("Multi-style rendering should produce output")
	}

	// Should switch fonts
	outputStr := string(output)
	if strings.Count(outputStr, "Tf") < 3 {
		t.Error("Should have multiple font switches")
	}
}
