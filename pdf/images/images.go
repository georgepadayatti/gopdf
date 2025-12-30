// Package images provides PDF image handling.
package images

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
)

// Common errors
var (
	ErrInvalidImage      = errors.New("invalid image data")
	ErrUnsupportedFormat = errors.New("unsupported image format")
	ErrDecodeFailed      = errors.New("image decode failed")
	ErrInvalidDimensions = errors.New("invalid image dimensions")
)

// ColorSpace represents a PDF color space.
type ColorSpace string

const (
	ColorSpaceGray ColorSpace = "DeviceGray"
	ColorSpaceRGB  ColorSpace = "DeviceRGB"
	ColorSpaceCMYK ColorSpace = "DeviceCMYK"
)

// ImageFormat represents an image format.
type ImageFormat string

const (
	FormatPNG  ImageFormat = "PNG"
	FormatJPEG ImageFormat = "JPEG"
	FormatGIF  ImageFormat = "GIF"
	FormatBMP  ImageFormat = "BMP"
)

// PDFImage represents an image ready for PDF embedding.
type PDFImage struct {
	// Width in pixels
	Width int
	// Height in pixels
	Height int
	// Bits per component (1, 2, 4, 8, 16)
	BitsPerComponent int
	// Color space
	ColorSpace ColorSpace
	// Number of color components (1 for gray, 3 for RGB, 4 for CMYK)
	Components int
	// Raw image data (may be compressed)
	Data []byte
	// Filter applied to data (e.g., "FlateDecode", "DCTDecode")
	Filter string
	// DecodeParms for the filter
	DecodeParms map[string]interface{}
	// Alpha channel data (if separate)
	AlphaData []byte
	// Alpha filter
	AlphaFilter string
	// Original format
	OriginalFormat ImageFormat
	// DPI resolution
	DPIx, DPIy float64
}

// NewPDFImageFromReader creates a PDFImage from an io.Reader.
func NewPDFImageFromReader(r io.Reader) (*PDFImage, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return NewPDFImageFromBytes(data)
}

// NewPDFImageFromBytes creates a PDFImage from raw bytes.
func NewPDFImageFromBytes(data []byte) (*PDFImage, error) {
	format := detectFormat(data)
	switch format {
	case FormatPNG:
		return decodePNG(data)
	case FormatJPEG:
		return decodeJPEG(data)
	default:
		// Try generic image decode
		return decodeGeneric(data)
	}
}

// NewPDFImageFromImage creates a PDFImage from a Go image.Image.
func NewPDFImageFromImage(img image.Image) (*PDFImage, error) {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	if width <= 0 || height <= 0 {
		return nil, ErrInvalidDimensions
	}

	// Determine color model
	var colorSpace ColorSpace
	var components int
	var hasAlpha bool

	switch img.ColorModel() {
	case color.GrayModel, color.Gray16Model:
		colorSpace = ColorSpaceGray
		components = 1
	case color.RGBAModel, color.RGBA64Model:
		colorSpace = ColorSpaceRGB
		components = 3
		hasAlpha = true
	case color.NRGBAModel, color.NRGBA64Model:
		colorSpace = ColorSpaceRGB
		components = 3
		hasAlpha = true
	case color.CMYKModel:
		colorSpace = ColorSpaceCMYK
		components = 4
	default:
		// Default to RGB
		colorSpace = ColorSpaceRGB
		components = 3
	}

	// Extract pixel data
	pixelData := make([]byte, 0, width*height*components)
	var alphaData []byte
	if hasAlpha {
		alphaData = make([]byte, 0, width*height)
	}

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.At(x, y)
			r, g, b, a := c.RGBA()

			switch colorSpace {
			case ColorSpaceGray:
				gray := (r + g + b) / 3
				pixelData = append(pixelData, byte(gray>>8))
			case ColorSpaceRGB:
				pixelData = append(pixelData, byte(r>>8), byte(g>>8), byte(b>>8))
				if hasAlpha {
					alphaData = append(alphaData, byte(a>>8))
				}
			case ColorSpaceCMYK:
				c, m, yk, k := color.CMYKModel.Convert(c).(color.CMYK).C,
					color.CMYKModel.Convert(c).(color.CMYK).M,
					color.CMYKModel.Convert(c).(color.CMYK).Y,
					color.CMYKModel.Convert(c).(color.CMYK).K
				pixelData = append(pixelData, c, m, yk, k)
			}
		}
	}

	// Compress data with zlib
	compressedData, err := compressZlib(pixelData)
	if err != nil {
		return nil, err
	}

	pdfImg := &PDFImage{
		Width:            width,
		Height:           height,
		BitsPerComponent: 8,
		ColorSpace:       colorSpace,
		Components:       components,
		Data:             compressedData,
		Filter:           "FlateDecode",
		DPIx:             72,
		DPIy:             72,
	}

	if hasAlpha && len(alphaData) > 0 {
		compressedAlpha, err := compressZlib(alphaData)
		if err != nil {
			return nil, err
		}
		pdfImg.AlphaData = compressedAlpha
		pdfImg.AlphaFilter = "FlateDecode"
	}

	return pdfImg, nil
}

// detectFormat detects the image format from the file header.
func detectFormat(data []byte) ImageFormat {
	if len(data) < 8 {
		return ""
	}

	// PNG signature
	if bytes.Equal(data[0:8], []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}) {
		return FormatPNG
	}

	// JPEG signature
	if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return FormatJPEG
	}

	// GIF signature
	if bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a")) {
		return FormatGIF
	}

	// BMP signature
	if data[0] == 0x42 && data[1] == 0x4D {
		return FormatBMP
	}

	return ""
}

// decodePNG decodes a PNG image.
func decodePNG(data []byte) (*PDFImage, error) {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}

	pdfImg, err := NewPDFImageFromImage(img)
	if err != nil {
		return nil, err
	}
	pdfImg.OriginalFormat = FormatPNG

	// Try to extract DPI from PNG metadata
	if len(data) > 8 {
		pdfImg.DPIx, pdfImg.DPIy = extractPNGDPI(data)
	}

	return pdfImg, nil
}

// extractPNGDPI extracts DPI from PNG pHYs chunk.
func extractPNGDPI(data []byte) (float64, float64) {
	// Search for pHYs chunk
	offset := 8 // Skip PNG signature
	for offset+12 <= len(data) {
		chunkLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		chunkType := string(data[offset+4 : offset+8])

		if chunkType == "pHYs" && offset+12+chunkLen <= len(data) && chunkLen >= 9 {
			chunkData := data[offset+8 : offset+8+chunkLen]
			ppuX := binary.BigEndian.Uint32(chunkData[0:4])
			ppuY := binary.BigEndian.Uint32(chunkData[4:8])
			unit := chunkData[8]

			if unit == 1 { // Meters
				// Convert pixels per meter to DPI
				return float64(ppuX) / 39.3701, float64(ppuY) / 39.3701
			}
		}

		if chunkType == "IEND" {
			break
		}

		offset += 12 + chunkLen
	}

	return 72, 72 // Default DPI
}

// decodeJPEG decodes a JPEG image.
// For JPEG, we can use DCTDecode directly without re-encoding.
func decodeJPEG(data []byte) (*PDFImage, error) {
	// Decode to get dimensions and color info
	config, err := jpeg.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}

	var colorSpace ColorSpace
	var components int

	switch config.ColorModel {
	case color.GrayModel:
		colorSpace = ColorSpaceGray
		components = 1
	case color.YCbCrModel:
		colorSpace = ColorSpaceRGB
		components = 3
	case color.CMYKModel:
		colorSpace = ColorSpaceCMYK
		components = 4
	default:
		colorSpace = ColorSpaceRGB
		components = 3
	}

	// Extract DPI from JFIF header if present
	dpiX, dpiY := extractJPEGDPI(data)

	return &PDFImage{
		Width:            config.Width,
		Height:           config.Height,
		BitsPerComponent: 8,
		ColorSpace:       colorSpace,
		Components:       components,
		Data:             data, // Use original JPEG data
		Filter:           "DCTDecode",
		OriginalFormat:   FormatJPEG,
		DPIx:             dpiX,
		DPIy:             dpiY,
	}, nil
}

// extractJPEGDPI extracts DPI from JPEG JFIF or EXIF data.
func extractJPEGDPI(data []byte) (float64, float64) {
	if len(data) < 20 {
		return 72, 72
	}

	// Look for JFIF APP0 marker
	offset := 2
	for offset+4 < len(data) {
		if data[offset] != 0xFF {
			break
		}

		marker := data[offset+1]
		if marker == 0xD9 { // EOI
			break
		}

		if marker == 0xE0 { // APP0 (JFIF)
			length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
			if offset+4+length <= len(data) && length >= 14 {
				app0Data := data[offset+4 : offset+4+length]
				if bytes.HasPrefix(app0Data, []byte("JFIF\x00")) && len(app0Data) >= 12 {
					units := app0Data[7]
					xDensity := binary.BigEndian.Uint16(app0Data[8:10])
					yDensity := binary.BigEndian.Uint16(app0Data[10:12])

					switch units {
					case 1: // DPI
						return float64(xDensity), float64(yDensity)
					case 2: // DPCM
						return float64(xDensity) * 2.54, float64(yDensity) * 2.54
					}
				}
			}
		}

		// Skip to next marker
		if marker >= 0xD0 && marker <= 0xD9 {
			offset += 2
		} else {
			length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
			offset += 2 + length
		}
	}

	return 72, 72
}

// decodeGeneric decodes any image format supported by Go's image package.
func decodeGeneric(data []byte) (*PDFImage, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}

	return NewPDFImageFromImage(img)
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

// GetUncompressedData returns the uncompressed image data.
func (img *PDFImage) GetUncompressedData() ([]byte, error) {
	if img.Filter == "" {
		return img.Data, nil
	}

	switch img.Filter {
	case "FlateDecode":
		r, err := zlib.NewReader(bytes.NewReader(img.Data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)

	case "DCTDecode":
		// For JPEG, decode to image and extract raw pixels
		decoded, err := jpeg.Decode(bytes.NewReader(img.Data))
		if err != nil {
			return nil, err
		}

		bounds := decoded.Bounds()
		var pixels []byte
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				r, g, b, _ := decoded.At(x, y).RGBA()
				if img.ColorSpace == ColorSpaceGray {
					pixels = append(pixels, byte(r>>8))
				} else {
					pixels = append(pixels, byte(r>>8), byte(g>>8), byte(b>>8))
				}
			}
		}
		return pixels, nil

	default:
		return nil, fmt.Errorf("unsupported filter: %s", img.Filter)
	}
}

// Resize resizes the image.
func (img *PDFImage) Resize(newWidth, newHeight int) (*PDFImage, error) {
	// Get uncompressed data
	rawData, err := img.GetUncompressedData()
	if err != nil {
		return nil, err
	}

	// Create image from raw data
	var srcImg image.Image
	switch img.ColorSpace {
	case ColorSpaceGray:
		gray := image.NewGray(image.Rect(0, 0, img.Width, img.Height))
		copy(gray.Pix, rawData)
		srcImg = gray
	case ColorSpaceRGB:
		rgba := image.NewRGBA(image.Rect(0, 0, img.Width, img.Height))
		// Convert RGB to RGBA
		for i := 0; i < len(rawData); i += 3 {
			pixIdx := (i / 3) * 4
			if pixIdx+3 < len(rgba.Pix) {
				rgba.Pix[pixIdx] = rawData[i]
				rgba.Pix[pixIdx+1] = rawData[i+1]
				rgba.Pix[pixIdx+2] = rawData[i+2]
				rgba.Pix[pixIdx+3] = 255
			}
		}
		srcImg = rgba
	default:
		return nil, ErrUnsupportedFormat
	}

	// Simple nearest-neighbor resize
	resized := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))
	xRatio := float64(img.Width) / float64(newWidth)
	yRatio := float64(img.Height) / float64(newHeight)

	for y := 0; y < newHeight; y++ {
		for x := 0; x < newWidth; x++ {
			srcX := int(float64(x) * xRatio)
			srcY := int(float64(y) * yRatio)
			resized.Set(x, y, srcImg.At(srcX, srcY))
		}
	}

	return NewPDFImageFromImage(resized)
}

// ToPDFDictionary returns the PDF dictionary entries for this image.
func (img *PDFImage) ToPDFDictionary() map[string]interface{} {
	dict := map[string]interface{}{
		"Type":             "XObject",
		"Subtype":          "Image",
		"Width":            img.Width,
		"Height":           img.Height,
		"ColorSpace":       string(img.ColorSpace),
		"BitsPerComponent": img.BitsPerComponent,
	}

	if img.Filter != "" {
		dict["Filter"] = img.Filter
	}

	if len(img.DecodeParms) > 0 {
		dict["DecodeParms"] = img.DecodeParms
	}

	return dict
}

// HasAlpha returns true if the image has an alpha channel.
func (img *PDFImage) HasAlpha() bool {
	return len(img.AlphaData) > 0
}

// GetAlphaMask returns a PDFImage for the alpha mask.
func (img *PDFImage) GetAlphaMask() *PDFImage {
	if !img.HasAlpha() {
		return nil
	}

	return &PDFImage{
		Width:            img.Width,
		Height:           img.Height,
		BitsPerComponent: 8,
		ColorSpace:       ColorSpaceGray,
		Components:       1,
		Data:             img.AlphaData,
		Filter:           img.AlphaFilter,
	}
}

// ImageXObject represents a PDF image XObject.
type ImageXObject struct {
	PDFImage   *PDFImage
	Name       string
	ObjectNum  int
	Generation int
}

// NewImageXObject creates a new image XObject.
func NewImageXObject(img *PDFImage, name string) *ImageXObject {
	return &ImageXObject{
		PDFImage: img,
		Name:     name,
	}
}

// ImageReader provides utilities for reading images from various sources.
type ImageReader struct {
	MaxWidth  int
	MaxHeight int
	Quality   int // JPEG quality (1-100)
}

// NewImageReader creates a new image reader.
func NewImageReader() *ImageReader {
	return &ImageReader{
		MaxWidth:  0, // No limit
		MaxHeight: 0, // No limit
		Quality:   85,
	}
}

// ReadFromFile reads an image from a file path.
func (r *ImageReader) ReadFromFile(reader io.Reader) (*PDFImage, error) {
	img, err := NewPDFImageFromReader(reader)
	if err != nil {
		return nil, err
	}

	// Apply size limits if set
	if r.MaxWidth > 0 && img.Width > r.MaxWidth {
		ratio := float64(r.MaxWidth) / float64(img.Width)
		newHeight := int(float64(img.Height) * ratio)
		return img.Resize(r.MaxWidth, newHeight)
	}

	if r.MaxHeight > 0 && img.Height > r.MaxHeight {
		ratio := float64(r.MaxHeight) / float64(img.Height)
		newWidth := int(float64(img.Width) * ratio)
		return img.Resize(newWidth, r.MaxHeight)
	}

	return img, nil
}

// EncodeToJPEG re-encodes an image as JPEG.
func EncodeToJPEG(img *PDFImage, quality int) (*PDFImage, error) {
	// Get uncompressed data
	rawData, err := img.GetUncompressedData()
	if err != nil {
		return nil, err
	}

	// Create image
	var srcImg image.Image
	switch img.ColorSpace {
	case ColorSpaceGray:
		gray := image.NewGray(image.Rect(0, 0, img.Width, img.Height))
		copy(gray.Pix, rawData)
		srcImg = gray
	case ColorSpaceRGB:
		rgba := image.NewRGBA(image.Rect(0, 0, img.Width, img.Height))
		for i := 0; i < len(rawData); i += 3 {
			pixIdx := (i / 3) * 4
			if pixIdx+3 < len(rgba.Pix) {
				rgba.Pix[pixIdx] = rawData[i]
				rgba.Pix[pixIdx+1] = rawData[i+1]
				rgba.Pix[pixIdx+2] = rawData[i+2]
				rgba.Pix[pixIdx+3] = 255
			}
		}
		srcImg = rgba
	default:
		return nil, ErrUnsupportedFormat
	}

	// Encode to JPEG
	var buf bytes.Buffer
	opts := &jpeg.Options{Quality: quality}
	if err := jpeg.Encode(&buf, srcImg, opts); err != nil {
		return nil, err
	}

	return &PDFImage{
		Width:            img.Width,
		Height:           img.Height,
		BitsPerComponent: 8,
		ColorSpace:       img.ColorSpace,
		Components:       img.Components,
		Data:             buf.Bytes(),
		Filter:           "DCTDecode",
		OriginalFormat:   FormatJPEG,
		DPIx:             img.DPIx,
		DPIy:             img.DPIy,
	}, nil
}

// GetImageDimensions returns the dimensions of an image without fully decoding it.
func GetImageDimensions(data []byte) (width, height int, err error) {
	format := detectFormat(data)

	switch format {
	case FormatPNG:
		if len(data) < 24 {
			return 0, 0, ErrInvalidImage
		}
		// PNG dimensions are in IHDR chunk
		width = int(binary.BigEndian.Uint32(data[16:20]))
		height = int(binary.BigEndian.Uint32(data[20:24]))
		return width, height, nil

	case FormatJPEG:
		config, err := jpeg.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return 0, 0, err
		}
		return config.Width, config.Height, nil

	default:
		// Generic decode
		config, _, err := image.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return 0, 0, err
		}
		return config.Width, config.Height, nil
	}
}
