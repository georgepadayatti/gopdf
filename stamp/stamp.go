// Package stamp provides PDF stamping and signature appearance functionality.
package stamp

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// StampStyle configures the appearance of a stamp.
type StampStyle struct {
	// Background color (RGBA)
	BackgroundColor color.RGBA
	// Border color
	BorderColor color.RGBA
	// Border width in points
	BorderWidth float64
	// Text color
	TextColor color.RGBA
	// Font size in points
	FontSize float64
	// Font name (standard PDF fonts)
	FontName string
	// Padding inside the stamp
	Padding float64
}

// DefaultStampStyle returns the default stamp style.
func DefaultStampStyle() *StampStyle {
	return &StampStyle{
		BackgroundColor: color.RGBA{255, 255, 255, 255},
		BorderColor:     color.RGBA{0, 0, 0, 255},
		BorderWidth:     1.0,
		TextColor:       color.RGBA{0, 0, 0, 255},
		FontSize:        10.0,
		FontName:        "Helvetica",
		Padding:         5.0,
	}
}

// TextStamp creates a text-based stamp.
type TextStamp struct {
	Style  *StampStyle
	Lines  []string
	Width  float64
	Height float64
}

// NewTextStamp creates a new text stamp.
func NewTextStamp(lines []string, style *StampStyle) *TextStamp {
	if style == nil {
		style = DefaultStampStyle()
	}

	// Calculate dimensions
	maxWidth := 0.0
	for _, line := range lines {
		lineWidth := float64(len(line)) * style.FontSize * 0.5
		if lineWidth > maxWidth {
			maxWidth = lineWidth
		}
	}

	width := maxWidth + style.Padding*2
	height := float64(len(lines))*style.FontSize*1.2 + style.Padding*2

	return &TextStamp{
		Style:  style,
		Lines:  lines,
		Width:  width,
		Height: height,
	}
}

// Render renders the stamp to a PDF content stream.
func (s *TextStamp) Render() []byte {
	var buf bytes.Buffer

	// Save graphics state
	buf.WriteString("q\n")

	// Draw background
	if s.Style.BackgroundColor.A > 0 {
		r := float64(s.Style.BackgroundColor.R) / 255.0
		g := float64(s.Style.BackgroundColor.G) / 255.0
		b := float64(s.Style.BackgroundColor.B) / 255.0
		fmt.Fprintf(&buf, "%f %f %f rg\n", r, g, b)
		fmt.Fprintf(&buf, "0 0 %f %f re f\n", s.Width, s.Height)
	}

	// Draw border
	if s.Style.BorderWidth > 0 {
		r := float64(s.Style.BorderColor.R) / 255.0
		g := float64(s.Style.BorderColor.G) / 255.0
		b := float64(s.Style.BorderColor.B) / 255.0
		fmt.Fprintf(&buf, "%f %f %f RG\n", r, g, b)
		fmt.Fprintf(&buf, "%f w\n", s.Style.BorderWidth)
		fmt.Fprintf(&buf, "0 0 %f %f re S\n", s.Width, s.Height)
	}

	// Draw text
	r := float64(s.Style.TextColor.R) / 255.0
	g := float64(s.Style.TextColor.G) / 255.0
	b := float64(s.Style.TextColor.B) / 255.0
	fmt.Fprintf(&buf, "%f %f %f rg\n", r, g, b)
	buf.WriteString("BT\n")
	fmt.Fprintf(&buf, "/F1 %f Tf\n", s.Style.FontSize)

	y := s.Height - s.Style.Padding - s.Style.FontSize
	for _, line := range s.Lines {
		fmt.Fprintf(&buf, "%f %f Td\n", s.Style.Padding, y)
		fmt.Fprintf(&buf, "(%s) Tj\n", escapeString(line))
		y -= s.Style.FontSize * 1.2
	}

	buf.WriteString("ET\n")

	// Restore graphics state
	buf.WriteString("Q\n")

	return buf.Bytes()
}

// CreateAppearanceStream creates a PDF appearance stream for the stamp.
func (s *TextStamp) CreateAppearanceStream() *generic.StreamObject {
	content := s.Render()

	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XObject"))
	dict.Set("Subtype", generic.NameObject("Form"))
	dict.Set("BBox", generic.ArrayObject{
		generic.RealObject(0),
		generic.RealObject(0),
		generic.RealObject(s.Width),
		generic.RealObject(s.Height),
	})

	// Resources
	resources := generic.NewDictionary()
	fonts := generic.NewDictionary()
	font := generic.NewDictionary()
	font.Set("Type", generic.NameObject("Font"))
	font.Set("Subtype", generic.NameObject("Type1"))
	font.Set("BaseFont", generic.NameObject(s.Style.FontName))
	fonts.Set("F1", font)
	resources.Set("Font", fonts)
	dict.Set("Resources", resources)

	return generic.NewStream(dict, content)
}

// GetDimensions returns the stamp dimensions.
func (s *TextStamp) GetDimensions() (width, height float64) {
	return s.Width, s.Height
}

// SignatureAppearance creates signature appearance stamps.
type SignatureAppearance struct {
	Style        *StampStyle
	SignerName   string
	Reason       string
	Location     string
	SigningTime  time.Time
	ShowDate     bool
	ShowReason   bool
	ShowLocation bool
	LogoImage    image.Image
}

// NewSignatureAppearance creates a new signature appearance.
func NewSignatureAppearance(signerName string) *SignatureAppearance {
	return &SignatureAppearance{
		Style:        DefaultStampStyle(),
		SignerName:   signerName,
		SigningTime:  time.Now(),
		ShowDate:     true,
		ShowReason:   true,
		ShowLocation: true,
	}
}

// SetReason sets the signing reason.
func (s *SignatureAppearance) SetReason(reason string) {
	s.Reason = reason
}

// SetLocation sets the signing location.
func (s *SignatureAppearance) SetLocation(location string) {
	s.Location = location
}

// Render renders the signature appearance to a PDF content stream.
func (s *SignatureAppearance) Render(width, height float64) []byte {
	var lines []string

	// Add signer name
	lines = append(lines, fmt.Sprintf("Digitally signed by %s", s.SignerName))

	// Add date if requested
	if s.ShowDate {
		lines = append(lines, fmt.Sprintf("Date: %s", s.SigningTime.Format("2006-01-02 15:04:05")))
	}

	// Add reason if present and requested
	if s.ShowReason && s.Reason != "" {
		lines = append(lines, fmt.Sprintf("Reason: %s", s.Reason))
	}

	// Add location if present and requested
	if s.ShowLocation && s.Location != "" {
		lines = append(lines, fmt.Sprintf("Location: %s", s.Location))
	}

	// Create text stamp with the lines
	stamp := &TextStamp{
		Style:  s.Style,
		Lines:  lines,
		Width:  width,
		Height: height,
	}

	return stamp.Render()
}

// CreateAppearanceStream creates a PDF appearance stream.
func (s *SignatureAppearance) CreateAppearanceStream(width, height float64) *generic.StreamObject {
	content := s.Render(width, height)

	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XObject"))
	dict.Set("Subtype", generic.NameObject("Form"))
	dict.Set("BBox", generic.ArrayObject{
		generic.RealObject(0),
		generic.RealObject(0),
		generic.RealObject(width),
		generic.RealObject(height),
	})

	// Resources
	resources := generic.NewDictionary()
	fonts := generic.NewDictionary()
	font := generic.NewDictionary()
	font.Set("Type", generic.NameObject("Font"))
	font.Set("Subtype", generic.NameObject("Type1"))
	font.Set("BaseFont", generic.NameObject(s.Style.FontName))
	fonts.Set("F1", font)
	resources.Set("Font", fonts)
	dict.Set("Resources", resources)

	return generic.NewStream(dict, content)
}

// QRStamp creates a QR code stamp.
type QRStamp struct {
	Style   *StampStyle
	Data    string
	Size    float64
	Modules [][]bool
}

// NewQRStamp creates a new QR code stamp.
func NewQRStamp(data string, size float64) *QRStamp {
	stamp := &QRStamp{
		Style: DefaultStampStyle(),
		Data:  data,
		Size:  size,
	}

	// Generate QR code modules (simplified - real implementation would use a QR library)
	stamp.Modules = generateQRCode(data)

	return stamp
}

// generateQRCode generates a simplified QR code pattern.
// This is a placeholder - real implementation would use a proper QR library.
func generateQRCode(data string) [][]bool {
	// Create a simple pattern based on data
	size := 21 // Minimum QR code size
	modules := make([][]bool, size)
	for i := range modules {
		modules[i] = make([]bool, size)
	}

	// Add finder patterns (corners)
	addFinderPattern(modules, 0, 0)
	addFinderPattern(modules, 0, size-7)
	addFinderPattern(modules, size-7, 0)

	// Add timing patterns
	for i := 8; i < size-8; i++ {
		modules[6][i] = i%2 == 0
		modules[i][6] = i%2 == 0
	}

	// Add data pattern (simplified)
	dataIdx := 0
	for y := 9; y < size-1; y++ {
		for x := 9; x < size-1; x++ {
			if dataIdx < len(data) {
				modules[y][x] = data[dataIdx]%2 == 1
				dataIdx++
			}
		}
	}

	return modules
}

// addFinderPattern adds a QR finder pattern at the specified position.
func addFinderPattern(modules [][]bool, y, x int) {
	// 7x7 finder pattern
	for dy := 0; dy < 7; dy++ {
		for dx := 0; dx < 7; dx++ {
			// Outer border
			if dy == 0 || dy == 6 || dx == 0 || dx == 6 {
				modules[y+dy][x+dx] = true
			} else if dy >= 2 && dy <= 4 && dx >= 2 && dx <= 4 {
				// Inner square
				modules[y+dy][x+dx] = true
			}
		}
	}
}

// Render renders the QR code to a PDF content stream.
func (s *QRStamp) Render() []byte {
	var buf bytes.Buffer

	if len(s.Modules) == 0 {
		return buf.Bytes()
	}

	moduleCount := len(s.Modules)
	moduleSize := s.Size / float64(moduleCount)

	// Save graphics state
	buf.WriteString("q\n")

	// Set black fill
	buf.WriteString("0 0 0 rg\n")

	// Draw modules
	for y, row := range s.Modules {
		for x, filled := range row {
			if filled {
				xPos := float64(x) * moduleSize
				yPos := s.Size - float64(y+1)*moduleSize
				fmt.Fprintf(&buf, "%f %f %f %f re f\n", xPos, yPos, moduleSize, moduleSize)
			}
		}
	}

	// Restore graphics state
	buf.WriteString("Q\n")

	return buf.Bytes()
}

// CreateAppearanceStream creates a PDF appearance stream for the QR code.
func (s *QRStamp) CreateAppearanceStream() *generic.StreamObject {
	content := s.Render()

	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XObject"))
	dict.Set("Subtype", generic.NameObject("Form"))
	dict.Set("BBox", generic.ArrayObject{
		generic.RealObject(0),
		generic.RealObject(0),
		generic.RealObject(s.Size),
		generic.RealObject(s.Size),
	})

	return generic.NewStream(dict, content)
}

// GetDimensions returns the QR stamp dimensions.
func (s *QRStamp) GetDimensions() (width, height float64) {
	return s.Size, s.Size
}

// QRPosition specifies where the QR code should be positioned relative to text.
type QRPosition int

const (
	// QRPositionLeftOfText places the QR code to the left of the text.
	QRPositionLeftOfText QRPosition = iota
	// QRPositionRightOfText places the QR code to the right of the text.
	QRPositionRightOfText
	// QRPositionAboveText places the QR code above the text.
	QRPositionAboveText
	// QRPositionBelowText places the QR code below the text.
	QRPositionBelowText
)

// String returns the string representation of QRPosition.
func (p QRPosition) String() string {
	switch p {
	case QRPositionLeftOfText:
		return "left"
	case QRPositionRightOfText:
		return "right"
	case QRPositionAboveText:
		return "top"
	case QRPositionBelowText:
		return "bottom"
	default:
		return "unknown"
	}
}

// ParseQRPosition parses a string to QRPosition.
func ParseQRPosition(s string) (QRPosition, error) {
	switch s {
	case "left":
		return QRPositionLeftOfText, nil
	case "right":
		return QRPositionRightOfText, nil
	case "top", "above":
		return QRPositionAboveText, nil
	case "bottom", "below":
		return QRPositionBelowText, nil
	default:
		return QRPositionLeftOfText, fmt.Errorf("invalid QR position: %s (valid: left, right, top, bottom)", s)
	}
}

// IsHorizontalFlow returns true if QR and text are arranged horizontally.
func (p QRPosition) IsHorizontalFlow() bool {
	return p == QRPositionLeftOfText || p == QRPositionRightOfText
}

// QRStampStyle configures the appearance of a QR code stamp with text.
type QRStampStyle struct {
	// TextStyle is the style for the text portion.
	TextStyle *StampStyle

	// QRPosition specifies where the QR code is relative to text.
	QRPosition QRPosition

	// QRSize is the size of the QR code in points. If 0, auto-calculated.
	QRSize float64

	// InnerSeparation is the space between QR code and text in points.
	InnerSeparation float64

	// BorderWidth is the border width around the entire stamp.
	BorderWidth float64

	// BorderColor is the border color (RGB, 0-1 range).
	BorderColor [3]float64

	// BackgroundOpacity is the opacity of the background (0-1).
	BackgroundOpacity float64

	// DefaultQRScale is the scale factor for QR code when size is auto-calculated.
	DefaultQRScale float64
}

// DefaultQRStampStyle returns the default QR stamp style.
func DefaultQRStampStyle() *QRStampStyle {
	return &QRStampStyle{
		TextStyle:         DefaultStampStyle(),
		QRPosition:        QRPositionLeftOfText,
		QRSize:            0, // Auto-calculate
		InnerSeparation:   3,
		BorderWidth:       3,
		BorderColor:       [3]float64{0, 0, 0},
		BackgroundOpacity: 0.6,
		DefaultQRScale:    0.2,
	}
}

// QRTextStamp creates a stamp with both QR code and text.
type QRTextStamp struct {
	Style   *QRStampStyle
	URL     string
	Lines   []string
	Width   float64
	Height  float64
	Modules [][]bool

	// Calculated layout values
	qrSize     float64
	qrX        float64
	qrY        float64
	textX      float64
	textY      float64
	textWidth  float64
	textHeight float64
}

// NewQRTextStamp creates a new QR code stamp with text.
func NewQRTextStamp(url string, lines []string, style *QRStampStyle) *QRTextStamp {
	if style == nil {
		style = DefaultQRStampStyle()
	}

	stamp := &QRTextStamp{
		Style:   style,
		URL:     url,
		Lines:   lines,
		Modules: generateQRCode(url),
	}

	stamp.calculateLayout()
	return stamp
}

// calculateLayout calculates the positions of QR code and text.
func (s *QRTextStamp) calculateLayout() {
	style := s.Style
	innsep := style.InnerSeparation

	// Calculate text dimensions
	textStyle := style.TextStyle
	if textStyle == nil {
		textStyle = DefaultStampStyle()
	}

	maxTextWidth := 0.0
	for _, line := range s.Lines {
		lineWidth := float64(len(line)) * textStyle.FontSize * 0.5
		if lineWidth > maxTextWidth {
			maxTextWidth = lineWidth
		}
	}
	s.textWidth = maxTextWidth + textStyle.Padding*2
	s.textHeight = float64(len(s.Lines))*textStyle.FontSize*1.2 + textStyle.Padding*2

	// Calculate QR size
	naturalQRSize := float64(len(s.Modules))
	if style.QRSize > 0 {
		s.qrSize = style.QRSize
	} else {
		// Auto-calculate based on text size and default scale
		s.qrSize = naturalQRSize * style.DefaultQRScale
		if s.qrSize < 20 {
			s.qrSize = 20 // Minimum QR size
		}
	}

	qrPadded := s.qrSize + 2*innsep

	// Calculate total dimensions and positions based on QR position
	switch style.QRPosition {
	case QRPositionLeftOfText:
		s.Width = qrPadded + s.textWidth
		s.Height = max(qrPadded, s.textHeight)
		s.qrX = innsep
		s.qrY = (s.Height - s.qrSize) / 2
		s.textX = qrPadded
		s.textY = (s.Height - s.textHeight) / 2

	case QRPositionRightOfText:
		s.Width = s.textWidth + qrPadded
		s.Height = max(qrPadded, s.textHeight)
		s.textX = 0
		s.textY = (s.Height - s.textHeight) / 2
		s.qrX = s.textWidth + innsep
		s.qrY = (s.Height - s.qrSize) / 2

	case QRPositionAboveText:
		s.Width = max(qrPadded, s.textWidth)
		s.Height = qrPadded + s.textHeight
		s.qrX = (s.Width - s.qrSize) / 2
		s.qrY = s.textHeight + innsep
		s.textX = (s.Width - s.textWidth) / 2
		s.textY = 0

	case QRPositionBelowText:
		s.Width = max(qrPadded, s.textWidth)
		s.Height = s.textHeight + qrPadded
		s.textX = (s.Width - s.textWidth) / 2
		s.textY = qrPadded
		s.qrX = (s.Width - s.qrSize) / 2
		s.qrY = innsep
	}
}

// Render renders the QR text stamp to a PDF content stream.
func (s *QRTextStamp) Render() []byte {
	var buf bytes.Buffer

	// Save graphics state
	buf.WriteString("q\n")

	// Draw QR code
	s.renderQRCode(&buf)

	// Draw text
	s.renderText(&buf)

	// Draw border
	if s.Style.BorderWidth > 0 {
		bc := s.Style.BorderColor
		fmt.Fprintf(&buf, "%f %f %f RG\n", bc[0], bc[1], bc[2])
		fmt.Fprintf(&buf, "%f w\n", s.Style.BorderWidth)
		fmt.Fprintf(&buf, "0 0 %f %f re S\n", s.Width, s.Height)
	}

	// Restore graphics state
	buf.WriteString("Q\n")

	return buf.Bytes()
}

// renderQRCode renders just the QR code portion.
func (s *QRTextStamp) renderQRCode(buf *bytes.Buffer) {
	if len(s.Modules) == 0 {
		return
	}

	moduleCount := len(s.Modules)
	moduleSize := s.qrSize / float64(moduleCount)

	// Save state for QR code
	buf.WriteString("q\n")

	// Translate to QR position
	fmt.Fprintf(buf, "1 0 0 1 %f %f cm\n", s.qrX, s.qrY)

	// Set black fill
	buf.WriteString("0 0 0 rg\n")

	// Draw modules
	for y, row := range s.Modules {
		for x, filled := range row {
			if filled {
				xPos := float64(x) * moduleSize
				yPos := s.qrSize - float64(y+1)*moduleSize
				fmt.Fprintf(buf, "%f %f %f %f re f\n", xPos, yPos, moduleSize, moduleSize)
			}
		}
	}

	buf.WriteString("Q\n")
}

// renderText renders just the text portion.
func (s *QRTextStamp) renderText(buf *bytes.Buffer) {
	textStyle := s.Style.TextStyle
	if textStyle == nil {
		textStyle = DefaultStampStyle()
	}

	// Save state for text
	buf.WriteString("q\n")

	// Translate to text position
	fmt.Fprintf(buf, "1 0 0 1 %f %f cm\n", s.textX, s.textY)

	// Draw text background if specified
	if textStyle.BackgroundColor.A > 0 {
		r := float64(textStyle.BackgroundColor.R) / 255.0
		g := float64(textStyle.BackgroundColor.G) / 255.0
		b := float64(textStyle.BackgroundColor.B) / 255.0
		fmt.Fprintf(buf, "%f %f %f rg\n", r, g, b)
		fmt.Fprintf(buf, "0 0 %f %f re f\n", s.textWidth, s.textHeight)
	}

	// Draw text
	r := float64(textStyle.TextColor.R) / 255.0
	g := float64(textStyle.TextColor.G) / 255.0
	b := float64(textStyle.TextColor.B) / 255.0
	fmt.Fprintf(buf, "%f %f %f rg\n", r, g, b)
	buf.WriteString("BT\n")
	fmt.Fprintf(buf, "/F1 %f Tf\n", textStyle.FontSize)

	y := s.textHeight - textStyle.Padding - textStyle.FontSize
	for i, line := range s.Lines {
		if i == 0 {
			fmt.Fprintf(buf, "%f %f Td\n", textStyle.Padding, y)
		} else {
			fmt.Fprintf(buf, "0 %f Td\n", -textStyle.FontSize*1.2)
		}
		fmt.Fprintf(buf, "(%s) Tj\n", escapeString(line))
	}

	buf.WriteString("ET\n")
	buf.WriteString("Q\n")
}

// GetDimensions returns the stamp dimensions.
func (s *QRTextStamp) GetDimensions() (width, height float64) {
	return s.Width, s.Height
}

// GetQRRect returns the rectangle containing the QR code (for link annotation).
func (s *QRTextStamp) GetQRRect() (x, y, width, height float64) {
	return s.qrX, s.qrY, s.qrSize, s.qrSize
}

// CreateAppearanceStream creates a PDF appearance stream for the QR text stamp.
func (s *QRTextStamp) CreateAppearanceStream() *generic.StreamObject {
	content := s.Render()

	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XObject"))
	dict.Set("Subtype", generic.NameObject("Form"))
	dict.Set("BBox", generic.ArrayObject{
		generic.RealObject(0),
		generic.RealObject(0),
		generic.RealObject(s.Width),
		generic.RealObject(s.Height),
	})

	// Resources
	resources := generic.NewDictionary()
	fonts := generic.NewDictionary()
	font := generic.NewDictionary()
	font.Set("Type", generic.NameObject("Font"))
	font.Set("Subtype", generic.NameObject("Type1"))
	fontName := "Helvetica"
	if s.Style.TextStyle != nil {
		fontName = s.Style.TextStyle.FontName
	}
	font.Set("BaseFont", generic.NameObject(fontName))
	fonts.Set("F1", font)
	resources.Set("Font", fonts)
	dict.Set("Resources", resources)

	return generic.NewStream(dict, content)
}

// CreateLinkAnnotation creates a link annotation for the QR code area.
// The annotation links to the URL encoded in the QR code.
// stampX and stampY are the position of the stamp on the page.
func (s *QRTextStamp) CreateLinkAnnotation(stampX, stampY float64) *generic.DictionaryObject {
	// Calculate absolute QR rectangle on page
	qrRect := generic.ArrayObject{
		generic.RealObject(stampX + s.qrX),
		generic.RealObject(stampY + s.qrY),
		generic.RealObject(stampX + s.qrX + s.qrSize),
		generic.RealObject(stampY + s.qrY + s.qrSize),
	}

	// Create URI action
	action := generic.NewDictionary()
	action.Set("S", generic.NameObject("URI"))
	action.Set("URI", generic.NewLiteralString(s.URL))

	// Create link annotation
	annot := generic.NewDictionary()
	annot.Set("Type", generic.NameObject("Annot"))
	annot.Set("Subtype", generic.NameObject("Link"))
	annot.Set("Rect", qrRect)
	annot.Set("A", action)
	// No border
	annot.Set("Border", generic.ArrayObject{
		generic.IntegerObject(0),
		generic.IntegerObject(0),
		generic.IntegerObject(0),
	})

	return annot
}

// CreateFullLinkAnnotation creates a link annotation covering the entire stamp.
// stampX and stampY are the position of the stamp on the page.
func (s *QRTextStamp) CreateFullLinkAnnotation(stampX, stampY float64) *generic.DictionaryObject {
	// Calculate full stamp rectangle on page
	rect := generic.ArrayObject{
		generic.RealObject(stampX),
		generic.RealObject(stampY),
		generic.RealObject(stampX + s.Width),
		generic.RealObject(stampY + s.Height),
	}

	// Create URI action
	action := generic.NewDictionary()
	action.Set("S", generic.NameObject("URI"))
	action.Set("URI", generic.NewLiteralString(s.URL))

	// Create link annotation
	annot := generic.NewDictionary()
	annot.Set("Type", generic.NameObject("Annot"))
	annot.Set("Subtype", generic.NameObject("Link"))
	annot.Set("Rect", rect)
	annot.Set("A", action)
	// No border
	annot.Set("Border", generic.ArrayObject{
		generic.IntegerObject(0),
		generic.IntegerObject(0),
		generic.IntegerObject(0),
	})

	return annot
}

// max returns the larger of two float64 values.
func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// Watermark creates a watermark overlay.
type Watermark struct {
	Text     string
	Style    *StampStyle
	Rotation float64 // Degrees
	Opacity  float64 // 0-1
}

// NewWatermark creates a new watermark.
func NewWatermark(text string) *Watermark {
	style := DefaultStampStyle()
	style.FontSize = 48
	style.TextColor = color.RGBA{200, 200, 200, 128}

	return &Watermark{
		Text:     text,
		Style:    style,
		Rotation: -45,
		Opacity:  0.5,
	}
}

// Render renders the watermark for a page of given dimensions.
func (w *Watermark) Render(pageWidth, pageHeight float64) []byte {
	var buf bytes.Buffer

	// Save graphics state
	buf.WriteString("q\n")

	// Set transparency
	fmt.Fprintf(&buf, "/GS1 gs\n")

	// Move to center and rotate
	fmt.Fprintf(&buf, "%f %f %f %f %f %f cm\n",
		cosD(w.Rotation), sinD(w.Rotation),
		-sinD(w.Rotation), cosD(w.Rotation),
		pageWidth/2, pageHeight/2)

	// Draw text
	r := float64(w.Style.TextColor.R) / 255.0
	g := float64(w.Style.TextColor.G) / 255.0
	b := float64(w.Style.TextColor.B) / 255.0
	fmt.Fprintf(&buf, "%f %f %f rg\n", r, g, b)

	buf.WriteString("BT\n")
	fmt.Fprintf(&buf, "/F1 %f Tf\n", w.Style.FontSize)

	// Center text
	textWidth := float64(len(w.Text)) * w.Style.FontSize * 0.5
	fmt.Fprintf(&buf, "%f %f Td\n", -textWidth/2, -w.Style.FontSize/2)
	fmt.Fprintf(&buf, "(%s) Tj\n", escapeString(w.Text))

	buf.WriteString("ET\n")

	// Restore graphics state
	buf.WriteString("Q\n")

	return buf.Bytes()
}

// CreateExtGState creates the external graphics state for transparency.
func (w *Watermark) CreateExtGState() *generic.DictionaryObject {
	gs := generic.NewDictionary()
	gs.Set("Type", generic.NameObject("ExtGState"))
	gs.Set("CA", generic.RealObject(w.Opacity))
	gs.Set("ca", generic.RealObject(w.Opacity))
	return gs
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

func cosD(degrees float64) float64 {
	return cos(degrees * 3.14159265358979323846 / 180.0)
}

func sinD(degrees float64) float64 {
	return sin(degrees * 3.14159265358979323846 / 180.0)
}

func cos(x float64) float64 {
	// Taylor series approximation
	x = mod(x, 2*3.14159265358979323846)
	if x > 3.14159265358979323846 {
		x -= 2 * 3.14159265358979323846
	}
	result := 1.0
	term := 1.0
	for i := 1; i < 10; i++ {
		term *= -x * x / float64(2*i*(2*i-1))
		result += term
	}
	return result
}

func sin(x float64) float64 {
	// Taylor series approximation
	x = mod(x, 2*3.14159265358979323846)
	if x > 3.14159265358979323846 {
		x -= 2 * 3.14159265358979323846
	}
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
