// Package stamp provides PDF stamping and signature appearance functionality.
package stamp

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg" // register JPEG format
	_ "image/png"  // register PNG format
	"io"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/pdf/images"
)

// ImageScaleMode specifies how an image should be scaled within the stamp.
type ImageScaleMode int

const (
	// ImageScaleFit scales the image to fit within the bounds while maintaining aspect ratio.
	ImageScaleFit ImageScaleMode = iota
	// ImageScaleFill scales the image to fill the bounds while maintaining aspect ratio (may crop).
	ImageScaleFill
	// ImageScaleStretch stretches the image to exactly fill the bounds (may distort).
	ImageScaleStretch
	// ImageScaleNone uses the image's natural size (may exceed bounds).
	ImageScaleNone
)

// String returns a string representation of the scale mode.
func (m ImageScaleMode) String() string {
	switch m {
	case ImageScaleFit:
		return "fit"
	case ImageScaleFill:
		return "fill"
	case ImageScaleStretch:
		return "stretch"
	case ImageScaleNone:
		return "none"
	default:
		return "unknown"
	}
}

// ParseImageScaleMode parses a string to ImageScaleMode.
func ParseImageScaleMode(s string) (ImageScaleMode, error) {
	switch s {
	case "fit":
		return ImageScaleFit, nil
	case "fill":
		return ImageScaleFill, nil
	case "stretch":
		return ImageScaleStretch, nil
	case "none":
		return ImageScaleNone, nil
	default:
		return ImageScaleFit, fmt.Errorf("invalid scale mode: %s (valid: fit, fill, stretch, none)", s)
	}
}

// ImagePosition specifies where an image should be positioned within a stamp.
type ImagePosition int

const (
	// ImagePositionCenter centers the image.
	ImagePositionCenter ImagePosition = iota
	// ImagePositionTopLeft positions at top-left.
	ImagePositionTopLeft
	// ImagePositionTopRight positions at top-right.
	ImagePositionTopRight
	// ImagePositionBottomLeft positions at bottom-left.
	ImagePositionBottomLeft
	// ImagePositionBottomRight positions at bottom-right.
	ImagePositionBottomRight
	// ImagePositionLeft positions at left center.
	ImagePositionLeft
	// ImagePositionRight positions at right center.
	ImagePositionRight
	// ImagePositionTop positions at top center.
	ImagePositionTop
	// ImagePositionBottom positions at bottom center.
	ImagePositionBottom
)

// ImageStampStyle configures the appearance of an image stamp.
type ImageStampStyle struct {
	// ScaleMode determines how the image is scaled.
	ScaleMode ImageScaleMode

	// Position determines where the image is positioned within the bounds.
	Position ImagePosition

	// Opacity sets the image opacity (0.0 to 1.0).
	Opacity float64

	// BorderWidth is the border width around the image in points.
	BorderWidth float64

	// BorderColor is the border color.
	BorderColor color.RGBA

	// BackgroundColor is the background color behind the image.
	BackgroundColor color.RGBA

	// Padding is the padding inside the stamp bounds.
	Padding float64
}

// DefaultImageStampStyle returns the default image stamp style.
func DefaultImageStampStyle() *ImageStampStyle {
	return &ImageStampStyle{
		ScaleMode:       ImageScaleFit,
		Position:        ImagePositionCenter,
		Opacity:         1.0,
		BorderWidth:     0,
		BorderColor:     color.RGBA{0, 0, 0, 255},
		BackgroundColor: color.RGBA{255, 255, 255, 0}, // Transparent
		Padding:         0,
	}
}

// ImageStamp creates an image-based stamp.
type ImageStamp struct {
	Style *ImageStampStyle

	// Image data
	imageData    []byte
	pdfImage     *images.PDFImage
	hasAlpha     bool
	alphaImage   *images.PDFImage

	// Dimensions
	Width  float64 // Stamp width in points
	Height float64 // Stamp height in points

	// Calculated image dimensions
	imageWidth  float64
	imageHeight float64
	imageX      float64
	imageY      float64
}

// NewImageStamp creates a new image stamp from raw image data.
func NewImageStamp(imageData []byte, width, height float64, style *ImageStampStyle) (*ImageStamp, error) {
	if style == nil {
		style = DefaultImageStampStyle()
	}

	// Decode the image
	pdfImage, err := images.NewPDFImageFromBytes(imageData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	stamp := &ImageStamp{
		Style:     style,
		imageData: imageData,
		pdfImage:  pdfImage,
		hasAlpha:  pdfImage.HasAlpha(),
		Width:     width,
		Height:    height,
	}

	if stamp.hasAlpha {
		stamp.alphaImage = pdfImage.GetAlphaMask()
	}

	stamp.calculateLayout()
	return stamp, nil
}

// NewImageStampFromReader creates a new image stamp from an io.Reader.
func NewImageStampFromReader(r io.Reader, width, height float64, style *ImageStampStyle) (*ImageStamp, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return NewImageStamp(data, width, height, style)
}

// NewImageStampFromImage creates a new image stamp from a Go image.Image.
func NewImageStampFromImage(img image.Image, width, height float64, style *ImageStampStyle) (*ImageStamp, error) {
	pdfImage, err := images.NewPDFImageFromImage(img)
	if err != nil {
		return nil, fmt.Errorf("failed to convert image: %w", err)
	}

	if style == nil {
		style = DefaultImageStampStyle()
	}

	stamp := &ImageStamp{
		Style:    style,
		pdfImage: pdfImage,
		hasAlpha: pdfImage.HasAlpha(),
		Width:    width,
		Height:   height,
	}

	if stamp.hasAlpha {
		stamp.alphaImage = pdfImage.GetAlphaMask()
	}

	stamp.calculateLayout()
	return stamp, nil
}

// calculateLayout calculates the image position and size within the stamp.
func (s *ImageStamp) calculateLayout() {
	style := s.Style
	padding := style.Padding

	// Available area for image
	availWidth := s.Width - 2*padding
	availHeight := s.Height - 2*padding

	// Original image dimensions
	imgWidth := float64(s.pdfImage.Width)
	imgHeight := float64(s.pdfImage.Height)

	// Calculate scaled dimensions based on scale mode
	switch style.ScaleMode {
	case ImageScaleFit:
		// Scale to fit while maintaining aspect ratio
		scaleX := availWidth / imgWidth
		scaleY := availHeight / imgHeight
		scale := scaleX
		if scaleY < scale {
			scale = scaleY
		}
		s.imageWidth = imgWidth * scale
		s.imageHeight = imgHeight * scale

	case ImageScaleFill:
		// Scale to fill while maintaining aspect ratio
		scaleX := availWidth / imgWidth
		scaleY := availHeight / imgHeight
		scale := scaleX
		if scaleY > scale {
			scale = scaleY
		}
		s.imageWidth = imgWidth * scale
		s.imageHeight = imgHeight * scale

	case ImageScaleStretch:
		// Stretch to fill exactly
		s.imageWidth = availWidth
		s.imageHeight = availHeight

	case ImageScaleNone:
		// Use natural size
		s.imageWidth = imgWidth
		s.imageHeight = imgHeight
	}

	// Calculate position based on position setting
	switch style.Position {
	case ImagePositionCenter:
		s.imageX = padding + (availWidth-s.imageWidth)/2
		s.imageY = padding + (availHeight-s.imageHeight)/2

	case ImagePositionTopLeft:
		s.imageX = padding
		s.imageY = s.Height - padding - s.imageHeight

	case ImagePositionTopRight:
		s.imageX = s.Width - padding - s.imageWidth
		s.imageY = s.Height - padding - s.imageHeight

	case ImagePositionBottomLeft:
		s.imageX = padding
		s.imageY = padding

	case ImagePositionBottomRight:
		s.imageX = s.Width - padding - s.imageWidth
		s.imageY = padding

	case ImagePositionLeft:
		s.imageX = padding
		s.imageY = padding + (availHeight-s.imageHeight)/2

	case ImagePositionRight:
		s.imageX = s.Width - padding - s.imageWidth
		s.imageY = padding + (availHeight-s.imageHeight)/2

	case ImagePositionTop:
		s.imageX = padding + (availWidth-s.imageWidth)/2
		s.imageY = s.Height - padding - s.imageHeight

	case ImagePositionBottom:
		s.imageX = padding + (availWidth-s.imageWidth)/2
		s.imageY = padding
	}
}

// Render renders the image stamp to a PDF content stream.
func (s *ImageStamp) Render() []byte {
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

	// Apply opacity if needed
	if s.Style.Opacity < 1.0 {
		buf.WriteString("/GS1 gs\n")
	}

	// Draw image
	buf.WriteString("q\n") // Save for image transformation
	fmt.Fprintf(&buf, "%f 0 0 %f %f %f cm\n", s.imageWidth, s.imageHeight, s.imageX, s.imageY)
	buf.WriteString("/Im1 Do\n")
	buf.WriteString("Q\n") // Restore after image

	// Restore graphics state
	buf.WriteString("Q\n")

	return buf.Bytes()
}

// CreateAppearanceStream creates a PDF appearance stream for the image stamp.
func (s *ImageStamp) CreateAppearanceStream() (*generic.StreamObject, []*generic.StreamObject, error) {
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
	dict.Set("FormType", generic.IntegerObject(1))

	// Resources dictionary
	resources := generic.NewDictionary()

	// Add opacity graphics state if needed
	if s.Style.Opacity < 1.0 {
		extGState := generic.NewDictionary()
		gs1 := generic.NewDictionary()
		gs1.Set("Type", generic.NameObject("ExtGState"))
		gs1.Set("CA", generic.RealObject(s.Style.Opacity))
		gs1.Set("ca", generic.RealObject(s.Style.Opacity))
		extGState.Set("GS1", gs1)
		resources.Set("ExtGState", extGState)
	}

	// XObject resources - image reference will be added by caller
	xobjects := generic.NewDictionary()
	// The actual image reference will be set when embedding
	resources.Set("XObject", xobjects)

	dict.Set("Resources", resources)

	// Create the form stream
	formStream := generic.NewStream(dict, content)

	// Create image XObject streams
	var additionalStreams []*generic.StreamObject

	// Create main image XObject
	imgStream, err := s.createImageXObject()
	if err != nil {
		return nil, nil, err
	}
	additionalStreams = append(additionalStreams, imgStream)

	// Create alpha mask XObject if needed
	if s.hasAlpha && s.alphaImage != nil {
		alphaStream := s.createAlphaMaskXObject()
		additionalStreams = append(additionalStreams, alphaStream)
	}

	return formStream, additionalStreams, nil
}

// createImageXObject creates the PDF image XObject.
func (s *ImageStamp) createImageXObject() (*generic.StreamObject, error) {
	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XObject"))
	dict.Set("Subtype", generic.NameObject("Image"))
	dict.Set("Width", generic.IntegerObject(s.pdfImage.Width))
	dict.Set("Height", generic.IntegerObject(s.pdfImage.Height))
	dict.Set("ColorSpace", generic.NameObject(string(s.pdfImage.ColorSpace)))
	dict.Set("BitsPerComponent", generic.IntegerObject(s.pdfImage.BitsPerComponent))

	if s.pdfImage.Filter != "" {
		dict.Set("Filter", generic.NameObject(s.pdfImage.Filter))
	}

	// Note: SMask reference will be set by the caller when embedding

	return generic.NewStream(dict, s.pdfImage.Data), nil
}

// createAlphaMaskXObject creates the PDF soft mask XObject.
func (s *ImageStamp) createAlphaMaskXObject() *generic.StreamObject {
	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XObject"))
	dict.Set("Subtype", generic.NameObject("Image"))
	dict.Set("Width", generic.IntegerObject(s.alphaImage.Width))
	dict.Set("Height", generic.IntegerObject(s.alphaImage.Height))
	dict.Set("ColorSpace", generic.NameObject("DeviceGray"))
	dict.Set("BitsPerComponent", generic.IntegerObject(8))

	if s.alphaImage.Filter != "" {
		dict.Set("Filter", generic.NameObject(s.alphaImage.Filter))
	}

	return generic.NewStream(dict, s.alphaImage.Data)
}

// GetDimensions returns the stamp dimensions.
func (s *ImageStamp) GetDimensions() (width, height float64) {
	return s.Width, s.Height
}

// GetImageDimensions returns the calculated image dimensions within the stamp.
func (s *ImageStamp) GetImageDimensions() (width, height, x, y float64) {
	return s.imageWidth, s.imageHeight, s.imageX, s.imageY
}

// HasAlpha returns true if the image has an alpha channel.
func (s *ImageStamp) HasAlpha() bool {
	return s.hasAlpha
}

// GetPDFImage returns the underlying PDFImage.
func (s *ImageStamp) GetPDFImage() *images.PDFImage {
	return s.pdfImage
}

// ImageTextStamp creates a stamp with both image and text.
type ImageTextStamp struct {
	Style *ImageTextStampStyle

	// Image
	imageStamp *ImageStamp

	// Text lines
	Lines []string

	// Dimensions
	Width  float64
	Height float64

	// Layout calculations
	imageAreaWidth  float64
	imageAreaHeight float64
	imageAreaX      float64
	imageAreaY      float64
	textAreaWidth   float64
	textAreaHeight  float64
	textAreaX       float64
	textAreaY       float64
}

// ImageTextPosition specifies where the image is relative to text.
type ImageTextPosition int

const (
	// ImageTextPositionLeft places image on the left of text.
	ImageTextPositionLeft ImageTextPosition = iota
	// ImageTextPositionRight places image on the right of text.
	ImageTextPositionRight
	// ImageTextPositionAbove places image above text.
	ImageTextPositionAbove
	// ImageTextPositionBelow places image below text.
	ImageTextPositionBelow
	// ImageTextPositionBackground places image behind text (watermark mode).
	ImageTextPositionBackground
)

// ImageTextStampStyle configures the appearance of an image+text stamp.
type ImageTextStampStyle struct {
	// ImageStyle is the style for the image portion.
	ImageStyle *ImageStampStyle

	// TextStyle is the style for the text portion.
	TextStyle *StampStyle

	// ImagePosition specifies where the image is relative to text.
	ImagePosition ImageTextPosition

	// ImageRatio is the ratio of image area to total area (0.0 to 1.0).
	// For ImageTextPositionBackground, this is ignored.
	ImageRatio float64

	// Separation is the space between image and text in points.
	Separation float64

	// BorderWidth is the border width around the entire stamp.
	BorderWidth float64

	// BorderColor is the border color.
	BorderColor color.RGBA
}

// DefaultImageTextStampStyle returns the default image+text stamp style.
func DefaultImageTextStampStyle() *ImageTextStampStyle {
	return &ImageTextStampStyle{
		ImageStyle:    DefaultImageStampStyle(),
		TextStyle:     DefaultStampStyle(),
		ImagePosition: ImageTextPositionLeft,
		ImageRatio:    0.4,
		Separation:    5,
		BorderWidth:   0,
		BorderColor:   color.RGBA{0, 0, 0, 255},
	}
}

// NewImageTextStamp creates a new image+text stamp.
func NewImageTextStamp(imageData []byte, lines []string, width, height float64, style *ImageTextStampStyle) (*ImageTextStamp, error) {
	if style == nil {
		style = DefaultImageTextStampStyle()
	}

	stamp := &ImageTextStamp{
		Style:  style,
		Lines:  lines,
		Width:  width,
		Height: height,
	}

	// Calculate layout first to determine image area
	stamp.calculateLayout()

	// Create image stamp for the image area
	imgStamp, err := NewImageStamp(imageData, stamp.imageAreaWidth, stamp.imageAreaHeight, style.ImageStyle)
	if err != nil {
		return nil, err
	}
	stamp.imageStamp = imgStamp

	return stamp, nil
}

// calculateLayout calculates the positions of image and text areas.
func (s *ImageTextStamp) calculateLayout() {
	style := s.Style
	sep := style.Separation

	switch style.ImagePosition {
	case ImageTextPositionLeft:
		s.imageAreaWidth = s.Width * style.ImageRatio
		s.imageAreaHeight = s.Height
		s.imageAreaX = 0
		s.imageAreaY = 0
		s.textAreaWidth = s.Width - s.imageAreaWidth - sep
		s.textAreaHeight = s.Height
		s.textAreaX = s.imageAreaWidth + sep
		s.textAreaY = 0

	case ImageTextPositionRight:
		s.textAreaWidth = s.Width * (1 - style.ImageRatio) - sep
		s.textAreaHeight = s.Height
		s.textAreaX = 0
		s.textAreaY = 0
		s.imageAreaWidth = s.Width * style.ImageRatio
		s.imageAreaHeight = s.Height
		s.imageAreaX = s.textAreaWidth + sep
		s.imageAreaY = 0

	case ImageTextPositionAbove:
		s.imageAreaWidth = s.Width
		s.imageAreaHeight = s.Height * style.ImageRatio
		s.imageAreaX = 0
		s.imageAreaY = s.Height - s.imageAreaHeight
		s.textAreaWidth = s.Width
		s.textAreaHeight = s.Height - s.imageAreaHeight - sep
		s.textAreaX = 0
		s.textAreaY = 0

	case ImageTextPositionBelow:
		s.textAreaWidth = s.Width
		s.textAreaHeight = s.Height * (1 - style.ImageRatio) - sep
		s.textAreaX = 0
		s.textAreaY = s.Height - s.textAreaHeight
		s.imageAreaWidth = s.Width
		s.imageAreaHeight = s.Height * style.ImageRatio
		s.imageAreaX = 0
		s.imageAreaY = 0

	case ImageTextPositionBackground:
		// Image fills entire area, text overlays
		s.imageAreaWidth = s.Width
		s.imageAreaHeight = s.Height
		s.imageAreaX = 0
		s.imageAreaY = 0
		s.textAreaWidth = s.Width
		s.textAreaHeight = s.Height
		s.textAreaX = 0
		s.textAreaY = 0
	}
}

// Render renders the image+text stamp to a PDF content stream.
func (s *ImageTextStamp) Render() []byte {
	var buf bytes.Buffer

	// Save graphics state
	buf.WriteString("q\n")

	// Draw image
	s.renderImage(&buf)

	// Draw text
	s.renderText(&buf)

	// Draw border
	if s.Style.BorderWidth > 0 {
		r := float64(s.Style.BorderColor.R) / 255.0
		g := float64(s.Style.BorderColor.G) / 255.0
		b := float64(s.Style.BorderColor.B) / 255.0
		fmt.Fprintf(&buf, "%f %f %f RG\n", r, g, b)
		fmt.Fprintf(&buf, "%f w\n", s.Style.BorderWidth)
		fmt.Fprintf(&buf, "0 0 %f %f re S\n", s.Width, s.Height)
	}

	// Restore graphics state
	buf.WriteString("Q\n")

	return buf.Bytes()
}

// renderImage renders the image portion.
func (s *ImageTextStamp) renderImage(buf *bytes.Buffer) {
	if s.imageStamp == nil {
		return
	}

	// Save state for image
	buf.WriteString("q\n")

	// Translate to image position
	fmt.Fprintf(buf, "1 0 0 1 %f %f cm\n", s.imageAreaX, s.imageAreaY)

	// Apply opacity if background mode
	if s.Style.ImagePosition == ImageTextPositionBackground {
		imgStyle := s.Style.ImageStyle
		if imgStyle != nil && imgStyle.Opacity < 1.0 {
			buf.WriteString("/GS1 gs\n")
		}
	}

	// Draw image
	imgW, imgH, imgX, imgY := s.imageStamp.GetImageDimensions()
	buf.WriteString("q\n")
	fmt.Fprintf(buf, "%f 0 0 %f %f %f cm\n", imgW, imgH, imgX, imgY)
	buf.WriteString("/Im1 Do\n")
	buf.WriteString("Q\n")

	buf.WriteString("Q\n")
}

// renderText renders the text portion.
func (s *ImageTextStamp) renderText(buf *bytes.Buffer) {
	textStyle := s.Style.TextStyle
	if textStyle == nil {
		textStyle = DefaultStampStyle()
	}

	// Save state for text
	buf.WriteString("q\n")

	// Translate to text position
	fmt.Fprintf(buf, "1 0 0 1 %f %f cm\n", s.textAreaX, s.textAreaY)

	// Draw text background if specified (only if not background mode)
	if s.Style.ImagePosition != ImageTextPositionBackground && textStyle.BackgroundColor.A > 0 {
		r := float64(textStyle.BackgroundColor.R) / 255.0
		g := float64(textStyle.BackgroundColor.G) / 255.0
		b := float64(textStyle.BackgroundColor.B) / 255.0
		fmt.Fprintf(buf, "%f %f %f rg\n", r, g, b)
		fmt.Fprintf(buf, "0 0 %f %f re f\n", s.textAreaWidth, s.textAreaHeight)
	}

	// Draw text
	r := float64(textStyle.TextColor.R) / 255.0
	g := float64(textStyle.TextColor.G) / 255.0
	b := float64(textStyle.TextColor.B) / 255.0
	fmt.Fprintf(buf, "%f %f %f rg\n", r, g, b)
	buf.WriteString("BT\n")
	fmt.Fprintf(buf, "/F1 %f Tf\n", textStyle.FontSize)

	y := s.textAreaHeight - textStyle.Padding - textStyle.FontSize
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

// CreateAppearanceStream creates a PDF appearance stream for the image+text stamp.
func (s *ImageTextStamp) CreateAppearanceStream() (*generic.StreamObject, []*generic.StreamObject, error) {
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
	dict.Set("FormType", generic.IntegerObject(1))

	// Resources dictionary
	resources := generic.NewDictionary()

	// Font resources
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

	// Add opacity graphics state if needed
	if s.Style.ImagePosition == ImageTextPositionBackground &&
		s.Style.ImageStyle != nil && s.Style.ImageStyle.Opacity < 1.0 {
		extGState := generic.NewDictionary()
		gs1 := generic.NewDictionary()
		gs1.Set("Type", generic.NameObject("ExtGState"))
		gs1.Set("CA", generic.RealObject(s.Style.ImageStyle.Opacity))
		gs1.Set("ca", generic.RealObject(s.Style.ImageStyle.Opacity))
		extGState.Set("GS1", gs1)
		resources.Set("ExtGState", extGState)
	}

	// XObject resources - image reference will be added by caller
	xobjects := generic.NewDictionary()
	resources.Set("XObject", xobjects)

	dict.Set("Resources", resources)

	// Create the form stream
	formStream := generic.NewStream(dict, content)

	// Create image XObject streams
	var additionalStreams []*generic.StreamObject

	if s.imageStamp != nil {
		imgStream, err := s.imageStamp.createImageXObject()
		if err != nil {
			return nil, nil, err
		}
		additionalStreams = append(additionalStreams, imgStream)

		if s.imageStamp.hasAlpha && s.imageStamp.alphaImage != nil {
			alphaStream := s.imageStamp.createAlphaMaskXObject()
			additionalStreams = append(additionalStreams, alphaStream)
		}
	}

	return formStream, additionalStreams, nil
}

// GetDimensions returns the stamp dimensions.
func (s *ImageTextStamp) GetDimensions() (width, height float64) {
	return s.Width, s.Height
}

// HasAlpha returns true if the image has an alpha channel.
func (s *ImageTextStamp) HasAlpha() bool {
	return s.imageStamp != nil && s.imageStamp.HasAlpha()
}

// compressZlib compresses data using zlib.
func compressZlib(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, err := w.Write(data)
	if err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
