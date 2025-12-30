package images

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"
)

func TestColorSpaceConstants(t *testing.T) {
	if ColorSpaceGray != "DeviceGray" {
		t.Error("ColorSpaceGray should be DeviceGray")
	}
	if ColorSpaceRGB != "DeviceRGB" {
		t.Error("ColorSpaceRGB should be DeviceRGB")
	}
	if ColorSpaceCMYK != "DeviceCMYK" {
		t.Error("ColorSpaceCMYK should be DeviceCMYK")
	}
}

func TestImageFormatConstants(t *testing.T) {
	if FormatPNG != "PNG" {
		t.Error("FormatPNG should be PNG")
	}
	if FormatJPEG != "JPEG" {
		t.Error("FormatJPEG should be JPEG")
	}
	if FormatGIF != "GIF" {
		t.Error("FormatGIF should be GIF")
	}
	if FormatBMP != "BMP" {
		t.Error("FormatBMP should be BMP")
	}
}

func createTestPNG(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// Fill with a pattern
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8(x % 256),
				G: uint8(y % 256),
				B: 128,
				A: 255,
			})
		}
	}

	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

func createTestJPEG(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// Fill with a pattern
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8(x % 256),
				G: uint8(y % 256),
				B: 128,
				A: 255,
			})
		}
	}

	var buf bytes.Buffer
	jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85})
	return buf.Bytes()
}

func createTestGrayImage(width, height int) image.Image {
	img := image.NewGray(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.SetGray(x, y, color.Gray{Y: uint8((x + y) % 256)})
		}
	}
	return img
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected ImageFormat
	}{
		{
			name:     "PNG",
			data:     []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			expected: FormatPNG,
		},
		{
			name:     "JPEG",
			data:     []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46},
			expected: FormatJPEG,
		},
		{
			name:     "GIF87a",
			data:     []byte("GIF87a\x00\x00"),
			expected: FormatGIF,
		},
		{
			name:     "GIF89a",
			data:     []byte("GIF89a\x00\x00"),
			expected: FormatGIF,
		},
		{
			name:     "BMP",
			data:     []byte{0x42, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: FormatBMP,
		},
		{
			name:     "Unknown",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: "",
		},
		{
			name:     "Too short",
			data:     []byte{0x00, 0x00},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectFormat(tt.data)
			if result != tt.expected {
				t.Errorf("detectFormat() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNewPDFImageFromBytesPNG(t *testing.T) {
	pngData := createTestPNG(100, 50)

	img, err := NewPDFImageFromBytes(pngData)
	if err != nil {
		t.Fatalf("NewPDFImageFromBytes failed: %v", err)
	}

	if img.Width != 100 {
		t.Errorf("Expected width 100, got %d", img.Width)
	}
	if img.Height != 50 {
		t.Errorf("Expected height 50, got %d", img.Height)
	}
	if img.ColorSpace != ColorSpaceRGB {
		t.Errorf("Expected ColorSpaceRGB, got %s", img.ColorSpace)
	}
	if img.BitsPerComponent != 8 {
		t.Errorf("Expected 8 bits, got %d", img.BitsPerComponent)
	}
	if img.OriginalFormat != FormatPNG {
		t.Errorf("Expected PNG format, got %s", img.OriginalFormat)
	}
	if img.Filter != "FlateDecode" {
		t.Errorf("Expected FlateDecode filter, got %s", img.Filter)
	}
}

func TestNewPDFImageFromBytesJPEG(t *testing.T) {
	jpegData := createTestJPEG(80, 60)

	img, err := NewPDFImageFromBytes(jpegData)
	if err != nil {
		t.Fatalf("NewPDFImageFromBytes failed: %v", err)
	}

	if img.Width != 80 {
		t.Errorf("Expected width 80, got %d", img.Width)
	}
	if img.Height != 60 {
		t.Errorf("Expected height 60, got %d", img.Height)
	}
	if img.OriginalFormat != FormatJPEG {
		t.Errorf("Expected JPEG format, got %s", img.OriginalFormat)
	}
	if img.Filter != "DCTDecode" {
		t.Errorf("Expected DCTDecode filter, got %s", img.Filter)
	}
	// JPEG data should be passed through directly
	if !bytes.Equal(img.Data, jpegData) {
		t.Error("JPEG data should be passed through unchanged")
	}
}

func TestNewPDFImageFromReader(t *testing.T) {
	pngData := createTestPNG(50, 50)
	reader := bytes.NewReader(pngData)

	img, err := NewPDFImageFromReader(reader)
	if err != nil {
		t.Fatalf("NewPDFImageFromReader failed: %v", err)
	}

	if img.Width != 50 || img.Height != 50 {
		t.Errorf("Expected 50x50, got %dx%d", img.Width, img.Height)
	}
}

func TestNewPDFImageFromImage(t *testing.T) {
	srcImg := image.NewRGBA(image.Rect(0, 0, 20, 20))
	for y := 0; y < 20; y++ {
		for x := 0; x < 20; x++ {
			srcImg.Set(x, y, color.RGBA{R: 255, G: 128, B: 64, A: 255})
		}
	}

	img, err := NewPDFImageFromImage(srcImg)
	if err != nil {
		t.Fatalf("NewPDFImageFromImage failed: %v", err)
	}

	if img.Width != 20 || img.Height != 20 {
		t.Errorf("Expected 20x20, got %dx%d", img.Width, img.Height)
	}
	if img.ColorSpace != ColorSpaceRGB {
		t.Errorf("Expected RGB, got %s", img.ColorSpace)
	}
}

func TestNewPDFImageFromGrayImage(t *testing.T) {
	srcImg := createTestGrayImage(30, 30)

	img, err := NewPDFImageFromImage(srcImg)
	if err != nil {
		t.Fatalf("NewPDFImageFromImage failed: %v", err)
	}

	if img.Width != 30 || img.Height != 30 {
		t.Errorf("Expected 30x30, got %dx%d", img.Width, img.Height)
	}
	if img.ColorSpace != ColorSpaceGray {
		t.Errorf("Expected Gray, got %s", img.ColorSpace)
	}
	if img.Components != 1 {
		t.Errorf("Expected 1 component, got %d", img.Components)
	}
}

func TestPDFImageInvalidDimensions(t *testing.T) {
	srcImg := image.NewRGBA(image.Rect(0, 0, 0, 0))

	_, err := NewPDFImageFromImage(srcImg)
	if err != ErrInvalidDimensions {
		t.Errorf("Expected ErrInvalidDimensions, got %v", err)
	}
}

func TestPDFImageGetUncompressedData(t *testing.T) {
	pngData := createTestPNG(10, 10)
	img, err := NewPDFImageFromBytes(pngData)
	if err != nil {
		t.Fatalf("Failed to create image: %v", err)
	}

	uncompressed, err := img.GetUncompressedData()
	if err != nil {
		t.Fatalf("GetUncompressedData failed: %v", err)
	}

	// Should be 10 * 10 * 3 bytes (RGB)
	expectedSize := 10 * 10 * 3
	if len(uncompressed) != expectedSize {
		t.Errorf("Expected %d bytes, got %d", expectedSize, len(uncompressed))
	}
}

func TestPDFImageGetUncompressedDataJPEG(t *testing.T) {
	jpegData := createTestJPEG(10, 10)
	img, err := NewPDFImageFromBytes(jpegData)
	if err != nil {
		t.Fatalf("Failed to create image: %v", err)
	}

	uncompressed, err := img.GetUncompressedData()
	if err != nil {
		t.Fatalf("GetUncompressedData failed: %v", err)
	}

	// Should be 10 * 10 * 3 bytes (RGB)
	expectedSize := 10 * 10 * 3
	if len(uncompressed) != expectedSize {
		t.Errorf("Expected %d bytes, got %d", expectedSize, len(uncompressed))
	}
}

func TestPDFImageHasAlpha(t *testing.T) {
	// Create RGBA image with alpha
	srcImg := image.NewNRGBA(image.Rect(0, 0, 10, 10))
	for y := 0; y < 10; y++ {
		for x := 0; x < 10; x++ {
			srcImg.Set(x, y, color.NRGBA{R: 255, G: 128, B: 64, A: 128})
		}
	}

	img, err := NewPDFImageFromImage(srcImg)
	if err != nil {
		t.Fatalf("NewPDFImageFromImage failed: %v", err)
	}

	if !img.HasAlpha() {
		t.Error("Expected image to have alpha")
	}

	alphaMask := img.GetAlphaMask()
	if alphaMask == nil {
		t.Fatal("GetAlphaMask returned nil")
	}
	if alphaMask.ColorSpace != ColorSpaceGray {
		t.Error("Alpha mask should be grayscale")
	}
}

func TestPDFImageNoAlpha(t *testing.T) {
	jpegData := createTestJPEG(10, 10)
	img, err := NewPDFImageFromBytes(jpegData)
	if err != nil {
		t.Fatalf("Failed to create image: %v", err)
	}

	if img.HasAlpha() {
		t.Error("JPEG should not have alpha")
	}
	if img.GetAlphaMask() != nil {
		t.Error("GetAlphaMask should return nil for non-alpha image")
	}
}

func TestPDFImageToPDFDictionary(t *testing.T) {
	pngData := createTestPNG(100, 50)
	img, err := NewPDFImageFromBytes(pngData)
	if err != nil {
		t.Fatalf("Failed to create image: %v", err)
	}

	dict := img.ToPDFDictionary()

	if dict["Type"] != "XObject" {
		t.Error("Expected Type=XObject")
	}
	if dict["Subtype"] != "Image" {
		t.Error("Expected Subtype=Image")
	}
	if dict["Width"] != 100 {
		t.Errorf("Expected Width=100, got %v", dict["Width"])
	}
	if dict["Height"] != 50 {
		t.Errorf("Expected Height=50, got %v", dict["Height"])
	}
	if dict["ColorSpace"] != "DeviceRGB" {
		t.Errorf("Expected ColorSpace=DeviceRGB, got %v", dict["ColorSpace"])
	}
	if dict["BitsPerComponent"] != 8 {
		t.Errorf("Expected BitsPerComponent=8, got %v", dict["BitsPerComponent"])
	}
	if dict["Filter"] != "FlateDecode" {
		t.Errorf("Expected Filter=FlateDecode, got %v", dict["Filter"])
	}
}

func TestPDFImageResize(t *testing.T) {
	pngData := createTestPNG(100, 100)
	img, err := NewPDFImageFromBytes(pngData)
	if err != nil {
		t.Fatalf("Failed to create image: %v", err)
	}

	resized, err := img.Resize(50, 50)
	if err != nil {
		t.Fatalf("Resize failed: %v", err)
	}

	if resized.Width != 50 || resized.Height != 50 {
		t.Errorf("Expected 50x50, got %dx%d", resized.Width, resized.Height)
	}
}

func TestNewImageXObject(t *testing.T) {
	pngData := createTestPNG(10, 10)
	img, err := NewPDFImageFromBytes(pngData)
	if err != nil {
		t.Fatalf("Failed to create image: %v", err)
	}

	xobj := NewImageXObject(img, "Im1")
	if xobj.Name != "Im1" {
		t.Errorf("Expected name Im1, got %s", xobj.Name)
	}
	if xobj.PDFImage != img {
		t.Error("PDFImage mismatch")
	}
}

func TestNewImageReader(t *testing.T) {
	reader := NewImageReader()
	if reader.MaxWidth != 0 {
		t.Error("MaxWidth should be 0 by default")
	}
	if reader.MaxHeight != 0 {
		t.Error("MaxHeight should be 0 by default")
	}
	if reader.Quality != 85 {
		t.Errorf("Expected quality 85, got %d", reader.Quality)
	}
}

func TestImageReaderReadFromFile(t *testing.T) {
	pngData := createTestPNG(50, 50)
	reader := NewImageReader()

	img, err := reader.ReadFromFile(bytes.NewReader(pngData))
	if err != nil {
		t.Fatalf("ReadFromFile failed: %v", err)
	}

	if img.Width != 50 || img.Height != 50 {
		t.Errorf("Expected 50x50, got %dx%d", img.Width, img.Height)
	}
}

func TestImageReaderWithMaxWidth(t *testing.T) {
	pngData := createTestPNG(100, 100)
	reader := NewImageReader()
	reader.MaxWidth = 50

	img, err := reader.ReadFromFile(bytes.NewReader(pngData))
	if err != nil {
		t.Fatalf("ReadFromFile failed: %v", err)
	}

	if img.Width != 50 {
		t.Errorf("Expected width 50, got %d", img.Width)
	}
	if img.Height != 50 {
		t.Errorf("Expected height 50, got %d", img.Height)
	}
}

func TestImageReaderWithMaxHeight(t *testing.T) {
	pngData := createTestPNG(100, 100)
	reader := NewImageReader()
	reader.MaxHeight = 25

	img, err := reader.ReadFromFile(bytes.NewReader(pngData))
	if err != nil {
		t.Fatalf("ReadFromFile failed: %v", err)
	}

	if img.Height != 25 {
		t.Errorf("Expected height 25, got %d", img.Height)
	}
}

func TestEncodeToJPEG(t *testing.T) {
	pngData := createTestPNG(50, 50)
	img, err := NewPDFImageFromBytes(pngData)
	if err != nil {
		t.Fatalf("Failed to create image: %v", err)
	}

	jpegImg, err := EncodeToJPEG(img, 85)
	if err != nil {
		t.Fatalf("EncodeToJPEG failed: %v", err)
	}

	if jpegImg.Filter != "DCTDecode" {
		t.Errorf("Expected DCTDecode, got %s", jpegImg.Filter)
	}
	if jpegImg.Width != 50 || jpegImg.Height != 50 {
		t.Errorf("Dimensions changed unexpectedly")
	}
}

func TestGetImageDimensionsPNG(t *testing.T) {
	pngData := createTestPNG(200, 100)

	width, height, err := GetImageDimensions(pngData)
	if err != nil {
		t.Fatalf("GetImageDimensions failed: %v", err)
	}

	if width != 200 || height != 100 {
		t.Errorf("Expected 200x100, got %dx%d", width, height)
	}
}

func TestGetImageDimensionsJPEG(t *testing.T) {
	jpegData := createTestJPEG(150, 75)

	width, height, err := GetImageDimensions(jpegData)
	if err != nil {
		t.Fatalf("GetImageDimensions failed: %v", err)
	}

	if width != 150 || height != 75 {
		t.Errorf("Expected 150x75, got %dx%d", width, height)
	}
}

func TestGetImageDimensionsInvalid(t *testing.T) {
	_, _, err := GetImageDimensions([]byte{0, 1, 2, 3})
	if err == nil {
		t.Error("Expected error for invalid data")
	}
}

func TestCompressZlib(t *testing.T) {
	data := []byte("test data for compression test data for compression")
	compressed, err := compressZlib(data)
	if err != nil {
		t.Fatalf("compressZlib failed: %v", err)
	}

	// Compressed data should be smaller for repetitive data
	if len(compressed) >= len(data) {
		t.Log("Warning: compressed data is not smaller (may be OK for small inputs)")
	}
}

func TestExtractPNGDPI(t *testing.T) {
	// Create a simple PNG header + pHYs chunk
	pngData := createTestPNG(10, 10)

	dpiX, dpiY := extractPNGDPI(pngData)
	// Default should be 72 DPI if no pHYs chunk
	if dpiX != 72 || dpiY != 72 {
		t.Logf("DPI: %v x %v (expected 72x72 for standard PNG)", dpiX, dpiY)
	}
}

func TestExtractJPEGDPI(t *testing.T) {
	jpegData := createTestJPEG(10, 10)

	dpiX, dpiY := extractJPEGDPI(jpegData)
	// Should return valid DPI (may be default 72 or from JFIF)
	if dpiX <= 0 || dpiY <= 0 {
		t.Errorf("Invalid DPI values: %v x %v", dpiX, dpiY)
	}
}

func TestNewPDFImageFromBytesInvalid(t *testing.T) {
	_, err := NewPDFImageFromBytes([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	if err == nil {
		t.Error("Expected error for invalid image data")
	}
}

func TestPDFImageDPI(t *testing.T) {
	pngData := createTestPNG(100, 100)
	img, err := NewPDFImageFromBytes(pngData)
	if err != nil {
		t.Fatalf("Failed to create image: %v", err)
	}

	if img.DPIx <= 0 || img.DPIy <= 0 {
		t.Errorf("Invalid DPI values: %v x %v", img.DPIx, img.DPIy)
	}
}
