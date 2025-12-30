// Package stamp provides PDF stamping and signature appearance functionality.
package stamp

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"io"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/pdf/images"
)

// VisualSignatureConfig configures a visual signature appearance.
type VisualSignatureConfig struct {
	// Signer information
	SignerName  string
	Reason      string
	Location    string
	ContactInfo string
	SigningTime time.Time

	// Display options
	ShowSignerName bool
	ShowDate       bool
	ShowReason     bool
	ShowLocation   bool
	ShowContact    bool

	// Image configuration
	Image            []byte      // Raw image data (JPEG or PNG)
	ImageAsWatermark bool        // If true, text is drawn over the image
	ImagePosition    ImageTextPosition
	ImageRatio       float64     // Ratio of image area to total (0.0 to 1.0)
	ImageOpacity     float64     // Image opacity (0.0 to 1.0)

	// Text styling
	TextStyle *StampStyle

	// Layout
	Padding    float64
	Separation float64 // Space between image and text

	// Border
	BorderWidth float64
	BorderColor color.RGBA
}

// DefaultVisualSignatureConfig returns the default visual signature configuration.
func DefaultVisualSignatureConfig() *VisualSignatureConfig {
	return &VisualSignatureConfig{
		SigningTime:      time.Now(),
		ShowSignerName:   true,
		ShowDate:         true,
		ShowReason:       true,
		ShowLocation:     true,
		ShowContact:      false,
		ImagePosition:    ImageTextPositionLeft,
		ImageRatio:       0.3,
		ImageOpacity:     1.0,
		TextStyle:        DefaultStampStyle(),
		Padding:          5,
		Separation:       5,
		BorderWidth:      0,
		BorderColor:      color.RGBA{0, 0, 0, 255},
	}
}

// VisualSignature creates a visual signature appearance with optional image.
type VisualSignature struct {
	Config *VisualSignatureConfig

	// Dimensions
	Width  float64
	Height float64

	// Image data
	pdfImage   *images.PDFImage
	alphaImage *images.PDFImage
	hasImage   bool
	hasAlpha   bool

	// Layout calculations
	imageAreaWidth  float64
	imageAreaHeight float64
	imageAreaX      float64
	imageAreaY      float64
	textAreaWidth   float64
	textAreaHeight  float64
	textAreaX       float64
	textAreaY       float64

	// Calculated image dimensions
	imageWidth  float64
	imageHeight float64
	imageX      float64
	imageY      float64
}

// NewVisualSignature creates a new visual signature.
func NewVisualSignature(width, height float64, config *VisualSignatureConfig) (*VisualSignature, error) {
	if config == nil {
		config = DefaultVisualSignatureConfig()
	}

	vs := &VisualSignature{
		Config: config,
		Width:  width,
		Height: height,
	}

	// Process image if provided
	if len(config.Image) > 0 {
		pdfImg, err := images.NewPDFImageFromBytes(config.Image)
		if err != nil {
			return nil, fmt.Errorf("failed to decode image: %w", err)
		}
		vs.pdfImage = pdfImg
		vs.hasImage = true
		vs.hasAlpha = pdfImg.HasAlpha()
		if vs.hasAlpha {
			vs.alphaImage = pdfImg.GetAlphaMask()
		}
	}

	vs.calculateLayout()
	return vs, nil
}

// NewVisualSignatureFromReader creates a visual signature with image from a reader.
func NewVisualSignatureFromReader(width, height float64, imageReader io.Reader, config *VisualSignatureConfig) (*VisualSignature, error) {
	if config == nil {
		config = DefaultVisualSignatureConfig()
	}

	if imageReader != nil {
		data, err := io.ReadAll(imageReader)
		if err != nil {
			return nil, err
		}
		config.Image = data
	}

	return NewVisualSignature(width, height, config)
}

// NewVisualSignatureFromImage creates a visual signature with a Go image.
func NewVisualSignatureFromImage(width, height float64, img image.Image, config *VisualSignatureConfig) (*VisualSignature, error) {
	if config == nil {
		config = DefaultVisualSignatureConfig()
	}

	vs := &VisualSignature{
		Config: config,
		Width:  width,
		Height: height,
	}

	if img != nil {
		pdfImg, err := images.NewPDFImageFromImage(img)
		if err != nil {
			return nil, fmt.Errorf("failed to convert image: %w", err)
		}
		vs.pdfImage = pdfImg
		vs.hasImage = true
		vs.hasAlpha = pdfImg.HasAlpha()
		if vs.hasAlpha {
			vs.alphaImage = pdfImg.GetAlphaMask()
		}
	}

	vs.calculateLayout()
	return vs, nil
}

// calculateLayout calculates the positions of image and text areas.
func (vs *VisualSignature) calculateLayout() {
	config := vs.Config
	padding := config.Padding
	sep := config.Separation

	// Available area
	availWidth := vs.Width - 2*padding
	availHeight := vs.Height - 2*padding

	if !vs.hasImage {
		// Text only - use full area
		vs.textAreaWidth = availWidth
		vs.textAreaHeight = availHeight
		vs.textAreaX = padding
		vs.textAreaY = padding
		return
	}

	switch config.ImagePosition {
	case ImageTextPositionLeft:
		vs.imageAreaWidth = availWidth * config.ImageRatio
		vs.imageAreaHeight = availHeight
		vs.imageAreaX = padding
		vs.imageAreaY = padding
		vs.textAreaWidth = availWidth - vs.imageAreaWidth - sep
		vs.textAreaHeight = availHeight
		vs.textAreaX = padding + vs.imageAreaWidth + sep
		vs.textAreaY = padding

	case ImageTextPositionRight:
		vs.textAreaWidth = availWidth*(1-config.ImageRatio) - sep
		vs.textAreaHeight = availHeight
		vs.textAreaX = padding
		vs.textAreaY = padding
		vs.imageAreaWidth = availWidth * config.ImageRatio
		vs.imageAreaHeight = availHeight
		vs.imageAreaX = padding + vs.textAreaWidth + sep
		vs.imageAreaY = padding

	case ImageTextPositionAbove:
		vs.imageAreaWidth = availWidth
		vs.imageAreaHeight = availHeight * config.ImageRatio
		vs.imageAreaX = padding
		vs.imageAreaY = padding + availHeight - vs.imageAreaHeight
		vs.textAreaWidth = availWidth
		vs.textAreaHeight = availHeight - vs.imageAreaHeight - sep
		vs.textAreaX = padding
		vs.textAreaY = padding

	case ImageTextPositionBelow:
		vs.textAreaWidth = availWidth
		vs.textAreaHeight = availHeight*(1-config.ImageRatio) - sep
		vs.textAreaX = padding
		vs.textAreaY = padding + availHeight - vs.textAreaHeight
		vs.imageAreaWidth = availWidth
		vs.imageAreaHeight = availHeight * config.ImageRatio
		vs.imageAreaX = padding
		vs.imageAreaY = padding

	case ImageTextPositionBackground:
		// Image fills entire area, text overlays
		vs.imageAreaWidth = availWidth
		vs.imageAreaHeight = availHeight
		vs.imageAreaX = padding
		vs.imageAreaY = padding
		vs.textAreaWidth = availWidth
		vs.textAreaHeight = availHeight
		vs.textAreaX = padding
		vs.textAreaY = padding
	}

	// Calculate image scaling within its area
	vs.calculateImageScale()
}

// calculateImageScale calculates how the image should be scaled within its area.
func (vs *VisualSignature) calculateImageScale() {
	if !vs.hasImage {
		return
	}

	imgWidth := float64(vs.pdfImage.Width)
	imgHeight := float64(vs.pdfImage.Height)

	// Scale to fit while maintaining aspect ratio
	scaleX := vs.imageAreaWidth / imgWidth
	scaleY := vs.imageAreaHeight / imgHeight
	scale := scaleX
	if scaleY < scale {
		scale = scaleY
	}

	vs.imageWidth = imgWidth * scale
	vs.imageHeight = imgHeight * scale

	// Center image in its area
	vs.imageX = vs.imageAreaX + (vs.imageAreaWidth-vs.imageWidth)/2
	vs.imageY = vs.imageAreaY + (vs.imageAreaHeight-vs.imageHeight)/2
}

// getTextLines returns the text lines to display.
func (vs *VisualSignature) getTextLines() []string {
	config := vs.Config
	var lines []string

	if config.ShowSignerName && config.SignerName != "" {
		lines = append(lines, fmt.Sprintf("Digitally signed by %s", config.SignerName))
	}

	if config.ShowDate {
		lines = append(lines, fmt.Sprintf("Date: %s", config.SigningTime.Format("2006-01-02 15:04:05")))
	}

	if config.ShowReason && config.Reason != "" {
		lines = append(lines, fmt.Sprintf("Reason: %s", config.Reason))
	}

	if config.ShowLocation && config.Location != "" {
		lines = append(lines, fmt.Sprintf("Location: %s", config.Location))
	}

	if config.ShowContact && config.ContactInfo != "" {
		lines = append(lines, fmt.Sprintf("Contact: %s", config.ContactInfo))
	}

	return lines
}

// Render renders the visual signature to a PDF content stream.
func (vs *VisualSignature) Render() []byte {
	var buf bytes.Buffer

	// Save graphics state
	buf.WriteString("q\n")

	// Draw border
	if vs.Config.BorderWidth > 0 {
		r := float64(vs.Config.BorderColor.R) / 255.0
		g := float64(vs.Config.BorderColor.G) / 255.0
		b := float64(vs.Config.BorderColor.B) / 255.0
		fmt.Fprintf(&buf, "%f %f %f RG\n", r, g, b)
		fmt.Fprintf(&buf, "%f w\n", vs.Config.BorderWidth)
		fmt.Fprintf(&buf, "0 0 %f %f re S\n", vs.Width, vs.Height)
	}

	// Draw image first (if background mode, it goes under text)
	if vs.hasImage {
		vs.renderImage(&buf)
	}

	// Draw text
	vs.renderText(&buf)

	// Restore graphics state
	buf.WriteString("Q\n")

	return buf.Bytes()
}

// renderImage renders the image portion.
func (vs *VisualSignature) renderImage(buf *bytes.Buffer) {
	// Save state for image
	buf.WriteString("q\n")

	// Apply opacity if needed
	if vs.Config.ImageOpacity < 1.0 {
		buf.WriteString("/GS1 gs\n")
	}

	// Draw image with transformation
	buf.WriteString("q\n")
	fmt.Fprintf(buf, "%f 0 0 %f %f %f cm\n", vs.imageWidth, vs.imageHeight, vs.imageX, vs.imageY)
	buf.WriteString("/Im1 Do\n")
	buf.WriteString("Q\n")

	buf.WriteString("Q\n")
}

// renderText renders the text portion.
func (vs *VisualSignature) renderText(buf *bytes.Buffer) {
	textStyle := vs.Config.TextStyle
	if textStyle == nil {
		textStyle = DefaultStampStyle()
	}

	lines := vs.getTextLines()
	if len(lines) == 0 {
		return
	}

	// Save state for text
	buf.WriteString("q\n")

	// Draw text background if specified (only if not background mode)
	if vs.Config.ImagePosition != ImageTextPositionBackground && textStyle.BackgroundColor.A > 0 {
		r := float64(textStyle.BackgroundColor.R) / 255.0
		g := float64(textStyle.BackgroundColor.G) / 255.0
		b := float64(textStyle.BackgroundColor.B) / 255.0
		fmt.Fprintf(buf, "%f %f %f rg\n", r, g, b)
		fmt.Fprintf(buf, "%f %f %f %f re f\n",
			vs.textAreaX, vs.textAreaY, vs.textAreaWidth, vs.textAreaHeight)
	}

	// Draw text
	r := float64(textStyle.TextColor.R) / 255.0
	g := float64(textStyle.TextColor.G) / 255.0
	b := float64(textStyle.TextColor.B) / 255.0
	fmt.Fprintf(buf, "%f %f %f rg\n", r, g, b)
	buf.WriteString("BT\n")
	fmt.Fprintf(buf, "/F1 %f Tf\n", textStyle.FontSize)

	// Calculate starting position
	textPadding := textStyle.Padding
	y := vs.textAreaY + vs.textAreaHeight - textPadding - textStyle.FontSize

	for i, line := range lines {
		if i == 0 {
			fmt.Fprintf(buf, "%f %f Td\n", vs.textAreaX+textPadding, y)
		} else {
			fmt.Fprintf(buf, "0 %f Td\n", -textStyle.FontSize*1.2)
		}
		fmt.Fprintf(buf, "(%s) Tj\n", escapeString(line))
	}

	buf.WriteString("ET\n")
	buf.WriteString("Q\n")
}

// CreateAppearanceStream creates a PDF appearance stream for the visual signature.
func (vs *VisualSignature) CreateAppearanceStream() (*generic.StreamObject, []*generic.StreamObject, error) {
	content := vs.Render()

	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XObject"))
	dict.Set("Subtype", generic.NameObject("Form"))
	dict.Set("BBox", generic.ArrayObject{
		generic.RealObject(0),
		generic.RealObject(0),
		generic.RealObject(vs.Width),
		generic.RealObject(vs.Height),
	})
	dict.Set("FormType", generic.IntegerObject(1))

	// Resources dictionary
	resources := generic.NewDictionary()

	// Font resources
	textStyle := vs.Config.TextStyle
	if textStyle == nil {
		textStyle = DefaultStampStyle()
	}
	fonts := generic.NewDictionary()
	font := generic.NewDictionary()
	font.Set("Type", generic.NameObject("Font"))
	font.Set("Subtype", generic.NameObject("Type1"))
	font.Set("BaseFont", generic.NameObject(textStyle.FontName))
	fonts.Set("F1", font)
	resources.Set("Font", fonts)

	// Add opacity graphics state if needed
	if vs.hasImage && vs.Config.ImageOpacity < 1.0 {
		extGState := generic.NewDictionary()
		gs1 := generic.NewDictionary()
		gs1.Set("Type", generic.NameObject("ExtGState"))
		gs1.Set("CA", generic.RealObject(vs.Config.ImageOpacity))
		gs1.Set("ca", generic.RealObject(vs.Config.ImageOpacity))
		extGState.Set("GS1", gs1)
		resources.Set("ExtGState", extGState)
	}

	// XObject resources placeholder - actual references added when embedding
	if vs.hasImage {
		xobjects := generic.NewDictionary()
		resources.Set("XObject", xobjects)
	}

	dict.Set("Resources", resources)

	// Create the form stream
	formStream := generic.NewStream(dict, content)

	// Create image XObject streams
	var additionalStreams []*generic.StreamObject

	if vs.hasImage {
		imgStream, err := vs.createImageXObject()
		if err != nil {
			return nil, nil, err
		}
		additionalStreams = append(additionalStreams, imgStream)

		if vs.hasAlpha && vs.alphaImage != nil {
			alphaStream := vs.createAlphaMaskXObject()
			additionalStreams = append(additionalStreams, alphaStream)
		}
	}

	return formStream, additionalStreams, nil
}

// createImageXObject creates the PDF image XObject.
func (vs *VisualSignature) createImageXObject() (*generic.StreamObject, error) {
	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XObject"))
	dict.Set("Subtype", generic.NameObject("Image"))
	dict.Set("Width", generic.IntegerObject(vs.pdfImage.Width))
	dict.Set("Height", generic.IntegerObject(vs.pdfImage.Height))
	dict.Set("ColorSpace", generic.NameObject(string(vs.pdfImage.ColorSpace)))
	dict.Set("BitsPerComponent", generic.IntegerObject(vs.pdfImage.BitsPerComponent))

	if vs.pdfImage.Filter != "" {
		dict.Set("Filter", generic.NameObject(vs.pdfImage.Filter))
	}

	return generic.NewStream(dict, vs.pdfImage.Data), nil
}

// createAlphaMaskXObject creates the PDF soft mask XObject.
func (vs *VisualSignature) createAlphaMaskXObject() *generic.StreamObject {
	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XObject"))
	dict.Set("Subtype", generic.NameObject("Image"))
	dict.Set("Width", generic.IntegerObject(vs.alphaImage.Width))
	dict.Set("Height", generic.IntegerObject(vs.alphaImage.Height))
	dict.Set("ColorSpace", generic.NameObject("DeviceGray"))
	dict.Set("BitsPerComponent", generic.IntegerObject(8))

	if vs.alphaImage.Filter != "" {
		dict.Set("Filter", generic.NameObject(vs.alphaImage.Filter))
	}

	return generic.NewStream(dict, vs.alphaImage.Data)
}

// GetDimensions returns the signature dimensions.
func (vs *VisualSignature) GetDimensions() (width, height float64) {
	return vs.Width, vs.Height
}

// HasImage returns true if the signature has an image.
func (vs *VisualSignature) HasImage() bool {
	return vs.hasImage
}

// HasAlpha returns true if the image has an alpha channel.
func (vs *VisualSignature) HasAlpha() bool {
	return vs.hasAlpha
}

// GetPDFImage returns the underlying PDFImage.
func (vs *VisualSignature) GetPDFImage() *images.PDFImage {
	return vs.pdfImage
}

// SignatureAppearanceBuilder helps build visual signature appearances.
type SignatureAppearanceBuilder struct {
	config *VisualSignatureConfig
	width  float64
	height float64
}

// NewSignatureAppearanceBuilder creates a new signature appearance builder.
func NewSignatureAppearanceBuilder(signerName string, width, height float64) *SignatureAppearanceBuilder {
	config := DefaultVisualSignatureConfig()
	config.SignerName = signerName
	return &SignatureAppearanceBuilder{
		config: config,
		width:  width,
		height: height,
	}
}

// WithReason sets the signing reason.
func (b *SignatureAppearanceBuilder) WithReason(reason string) *SignatureAppearanceBuilder {
	b.config.Reason = reason
	return b
}

// WithLocation sets the signing location.
func (b *SignatureAppearanceBuilder) WithLocation(location string) *SignatureAppearanceBuilder {
	b.config.Location = location
	return b
}

// WithContact sets the contact info.
func (b *SignatureAppearanceBuilder) WithContact(contact string) *SignatureAppearanceBuilder {
	b.config.ContactInfo = contact
	b.config.ShowContact = true
	return b
}

// WithSigningTime sets the signing time.
func (b *SignatureAppearanceBuilder) WithSigningTime(t time.Time) *SignatureAppearanceBuilder {
	b.config.SigningTime = t
	return b
}

// WithImage sets the image data.
func (b *SignatureAppearanceBuilder) WithImage(imageData []byte) *SignatureAppearanceBuilder {
	b.config.Image = imageData
	return b
}

// WithImageAsWatermark sets the image as a watermark (text over image).
func (b *SignatureAppearanceBuilder) WithImageAsWatermark(opacity float64) *SignatureAppearanceBuilder {
	b.config.ImageAsWatermark = true
	b.config.ImagePosition = ImageTextPositionBackground
	b.config.ImageOpacity = opacity
	return b
}

// WithImagePosition sets the image position.
func (b *SignatureAppearanceBuilder) WithImagePosition(pos ImageTextPosition) *SignatureAppearanceBuilder {
	b.config.ImagePosition = pos
	return b
}

// WithImageRatio sets the image ratio.
func (b *SignatureAppearanceBuilder) WithImageRatio(ratio float64) *SignatureAppearanceBuilder {
	b.config.ImageRatio = ratio
	return b
}

// WithTextStyle sets the text style.
func (b *SignatureAppearanceBuilder) WithTextStyle(style *StampStyle) *SignatureAppearanceBuilder {
	b.config.TextStyle = style
	return b
}

// WithBorder sets the border.
func (b *SignatureAppearanceBuilder) WithBorder(width float64, c color.RGBA) *SignatureAppearanceBuilder {
	b.config.BorderWidth = width
	b.config.BorderColor = c
	return b
}

// HideDate hides the date.
func (b *SignatureAppearanceBuilder) HideDate() *SignatureAppearanceBuilder {
	b.config.ShowDate = false
	return b
}

// HideReason hides the reason.
func (b *SignatureAppearanceBuilder) HideReason() *SignatureAppearanceBuilder {
	b.config.ShowReason = false
	return b
}

// HideLocation hides the location.
func (b *SignatureAppearanceBuilder) HideLocation() *SignatureAppearanceBuilder {
	b.config.ShowLocation = false
	return b
}

// Build creates the visual signature.
func (b *SignatureAppearanceBuilder) Build() (*VisualSignature, error) {
	return NewVisualSignature(b.width, b.height, b.config)
}

// SignatureRect defines the rectangle for a signature appearance.
type SignatureRect struct {
	// LowerLeftX is the X coordinate of the lower-left corner.
	LowerLeftX float64
	// LowerLeftY is the Y coordinate of the lower-left corner.
	LowerLeftY float64
	// UpperRightX is the X coordinate of the upper-right corner.
	UpperRightX float64
	// UpperRightY is the Y coordinate of the upper-right corner.
	UpperRightY float64
}

// NewSignatureRect creates a new signature rectangle.
func NewSignatureRect(llx, lly, urx, ury float64) *SignatureRect {
	return &SignatureRect{
		LowerLeftX:  llx,
		LowerLeftY:  lly,
		UpperRightX: urx,
		UpperRightY: ury,
	}
}

// Width returns the rectangle width.
func (r *SignatureRect) Width() float64 {
	return r.UpperRightX - r.LowerLeftX
}

// Height returns the rectangle height.
func (r *SignatureRect) Height() float64 {
	return r.UpperRightY - r.LowerLeftY
}

// ToArray returns the rectangle as a PDF array.
func (r *SignatureRect) ToArray() generic.ArrayObject {
	return generic.ArrayObject{
		generic.RealObject(r.LowerLeftX),
		generic.RealObject(r.LowerLeftY),
		generic.RealObject(r.UpperRightX),
		generic.RealObject(r.UpperRightY),
	}
}

// ToGenericRectangle converts to generic.Rectangle.
func (r *SignatureRect) ToGenericRectangle() *generic.Rectangle {
	return &generic.Rectangle{
		LLX: r.LowerLeftX,
		LLY: r.LowerLeftY,
		URX: r.UpperRightX,
		URY: r.UpperRightY,
	}
}
