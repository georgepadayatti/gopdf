package stamp

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
	"time"
)

// createTestImage creates a simple test image.
func createTestImage(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
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

func TestDefaultVisualSignatureConfig(t *testing.T) {
	config := DefaultVisualSignatureConfig()

	if !config.ShowSignerName {
		t.Error("ShowSignerName should be true by default")
	}
	if !config.ShowDate {
		t.Error("ShowDate should be true by default")
	}
	if !config.ShowReason {
		t.Error("ShowReason should be true by default")
	}
	if !config.ShowLocation {
		t.Error("ShowLocation should be true by default")
	}
	if config.ShowContact {
		t.Error("ShowContact should be false by default")
	}
	if config.ImageRatio != 0.3 {
		t.Errorf("ImageRatio = %v, want 0.3", config.ImageRatio)
	}
	if config.ImageOpacity != 1.0 {
		t.Errorf("ImageOpacity = %v, want 1.0", config.ImageOpacity)
	}
	if config.TextStyle == nil {
		t.Error("TextStyle should not be nil")
	}
}

func TestNewVisualSignature_TextOnly(t *testing.T) {
	config := DefaultVisualSignatureConfig()
	config.SignerName = "John Doe"
	config.Reason = "Document approval"
	config.Location = "New York"

	vs, err := NewVisualSignature(200, 100, config)
	if err != nil {
		t.Fatalf("NewVisualSignature() error = %v", err)
	}

	if vs.HasImage() {
		t.Error("HasImage() = true, want false for text-only signature")
	}
	if vs.Width != 200 || vs.Height != 100 {
		t.Errorf("Dimensions = (%v, %v), want (200, 100)", vs.Width, vs.Height)
	}
}

func TestNewVisualSignature_WithImage(t *testing.T) {
	imageData := createTestImage(100, 100)

	config := DefaultVisualSignatureConfig()
	config.SignerName = "John Doe"
	config.Image = imageData

	vs, err := NewVisualSignature(300, 150, config)
	if err != nil {
		t.Fatalf("NewVisualSignature() error = %v", err)
	}

	if !vs.HasImage() {
		t.Error("HasImage() = false, want true")
	}
	if vs.GetPDFImage() == nil {
		t.Error("GetPDFImage() = nil")
	}
}

func TestNewVisualSignature_InvalidImage(t *testing.T) {
	config := DefaultVisualSignatureConfig()
	config.SignerName = "John Doe"
	config.Image = []byte("not an image")

	_, err := NewVisualSignature(200, 100, config)
	if err == nil {
		t.Error("NewVisualSignature() expected error for invalid image")
	}
}

func TestVisualSignature_Render(t *testing.T) {
	config := DefaultVisualSignatureConfig()
	config.SignerName = "John Doe"
	config.Reason = "Approval"
	config.Location = "NYC"

	vs, err := NewVisualSignature(200, 100, config)
	if err != nil {
		t.Fatalf("NewVisualSignature() error = %v", err)
	}

	content := vs.Render()
	if len(content) == 0 {
		t.Error("Render() returned empty content")
	}

	// Check for text content
	if !bytes.Contains(content, []byte("BT\n")) {
		t.Error("Render() missing begin text operator")
	}
	if !bytes.Contains(content, []byte("ET\n")) {
		t.Error("Render() missing end text operator")
	}
	if !bytes.Contains(content, []byte("John Doe")) {
		t.Error("Render() missing signer name")
	}
}

func TestVisualSignature_Render_WithImage(t *testing.T) {
	imageData := createTestImage(100, 100)

	config := DefaultVisualSignatureConfig()
	config.SignerName = "John Doe"
	config.Image = imageData

	vs, err := NewVisualSignature(300, 150, config)
	if err != nil {
		t.Fatalf("NewVisualSignature() error = %v", err)
	}

	content := vs.Render()
	if len(content) == 0 {
		t.Error("Render() returned empty content")
	}

	// Check for image reference
	if !bytes.Contains(content, []byte("/Im1 Do")) {
		t.Error("Render() missing image draw operator")
	}
}

func TestVisualSignature_ImagePositions(t *testing.T) {
	imageData := createTestImage(100, 100)

	positions := []ImageTextPosition{
		ImageTextPositionLeft,
		ImageTextPositionRight,
		ImageTextPositionAbove,
		ImageTextPositionBelow,
		ImageTextPositionBackground,
	}

	for _, pos := range positions {
		t.Run(pos.String(), func(t *testing.T) {
			config := DefaultVisualSignatureConfig()
			config.SignerName = "John Doe"
			config.Image = imageData
			config.ImagePosition = pos

			vs, err := NewVisualSignature(300, 200, config)
			if err != nil {
				t.Fatalf("NewVisualSignature() error = %v", err)
			}

			content := vs.Render()
			if len(content) == 0 {
				t.Error("Render() returned empty content")
			}
		})
	}
}

func TestVisualSignature_CreateAppearanceStream(t *testing.T) {
	config := DefaultVisualSignatureConfig()
	config.SignerName = "John Doe"

	vs, err := NewVisualSignature(200, 100, config)
	if err != nil {
		t.Fatalf("NewVisualSignature() error = %v", err)
	}

	formStream, additionalStreams, err := vs.CreateAppearanceStream()
	if err != nil {
		t.Fatalf("CreateAppearanceStream() error = %v", err)
	}

	if formStream == nil {
		t.Error("CreateAppearanceStream() returned nil form stream")
	}

	// Text-only signature should have no additional streams
	if len(additionalStreams) != 0 {
		t.Errorf("CreateAppearanceStream() returned %d additional streams, want 0 for text-only", len(additionalStreams))
	}
}

func TestVisualSignature_CreateAppearanceStream_WithImage(t *testing.T) {
	imageData := createTestImage(100, 100)

	config := DefaultVisualSignatureConfig()
	config.SignerName = "John Doe"
	config.Image = imageData

	vs, err := NewVisualSignature(300, 150, config)
	if err != nil {
		t.Fatalf("NewVisualSignature() error = %v", err)
	}

	formStream, additionalStreams, err := vs.CreateAppearanceStream()
	if err != nil {
		t.Fatalf("CreateAppearanceStream() error = %v", err)
	}

	if formStream == nil {
		t.Error("CreateAppearanceStream() returned nil form stream")
	}

	// With image should have at least image XObject
	if len(additionalStreams) == 0 {
		t.Error("CreateAppearanceStream() returned no additional streams (expected image XObject)")
	}
}

func TestVisualSignature_WithOpacity(t *testing.T) {
	imageData := createTestImage(100, 100)

	config := DefaultVisualSignatureConfig()
	config.SignerName = "John Doe"
	config.Image = imageData
	config.ImageOpacity = 0.5

	vs, err := NewVisualSignature(300, 150, config)
	if err != nil {
		t.Fatalf("NewVisualSignature() error = %v", err)
	}

	content := vs.Render()
	if !bytes.Contains(content, []byte("/GS1 gs")) {
		t.Error("Render() should include graphics state for opacity")
	}
}

func TestVisualSignature_WithBorder(t *testing.T) {
	config := DefaultVisualSignatureConfig()
	config.SignerName = "John Doe"
	config.BorderWidth = 2
	config.BorderColor = color.RGBA{255, 0, 0, 255}

	vs, err := NewVisualSignature(200, 100, config)
	if err != nil {
		t.Fatalf("NewVisualSignature() error = %v", err)
	}

	content := vs.Render()
	if !bytes.Contains(content, []byte("RG")) {
		t.Error("Render() should include stroke color for border")
	}
}

func TestSignatureAppearanceBuilder(t *testing.T) {
	t.Run("BasicBuild", func(t *testing.T) {
		vs, err := NewSignatureAppearanceBuilder("John Doe", 200, 100).
			Build()

		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}
		if vs == nil {
			t.Fatal("Build() returned nil")
		}
	})

	t.Run("WithAllOptions", func(t *testing.T) {
		imageData := createTestImage(100, 100)

		vs, err := NewSignatureAppearanceBuilder("Jane Smith", 300, 150).
			WithReason("Document approval").
			WithLocation("San Francisco").
			WithContact("jane@example.com").
			WithSigningTime(time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)).
			WithImage(imageData).
			WithImagePosition(ImageTextPositionRight).
			WithImageRatio(0.4).
			WithBorder(1, color.RGBA{0, 0, 0, 255}).
			Build()

		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}
		if !vs.HasImage() {
			t.Error("Built signature should have image")
		}
	})

	t.Run("WithWatermark", func(t *testing.T) {
		imageData := createTestImage(100, 100)

		vs, err := NewSignatureAppearanceBuilder("John Doe", 200, 100).
			WithImage(imageData).
			WithImageAsWatermark(0.5).
			Build()

		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}
		if vs.Config.ImagePosition != ImageTextPositionBackground {
			t.Error("Watermark should set ImagePosition to Background")
		}
		if vs.Config.ImageOpacity != 0.5 {
			t.Errorf("Watermark opacity = %v, want 0.5", vs.Config.ImageOpacity)
		}
	})

	t.Run("HideOptions", func(t *testing.T) {
		vs, err := NewSignatureAppearanceBuilder("John Doe", 200, 100).
			HideDate().
			HideReason().
			HideLocation().
			Build()

		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}
		if vs.Config.ShowDate {
			t.Error("ShowDate should be false")
		}
		if vs.Config.ShowReason {
			t.Error("ShowReason should be false")
		}
		if vs.Config.ShowLocation {
			t.Error("ShowLocation should be false")
		}
	})
}

func TestSignatureRect(t *testing.T) {
	rect := NewSignatureRect(100, 200, 300, 400)

	if rect.LowerLeftX != 100 {
		t.Errorf("LowerLeftX = %v, want 100", rect.LowerLeftX)
	}
	if rect.LowerLeftY != 200 {
		t.Errorf("LowerLeftY = %v, want 200", rect.LowerLeftY)
	}
	if rect.UpperRightX != 300 {
		t.Errorf("UpperRightX = %v, want 300", rect.UpperRightX)
	}
	if rect.UpperRightY != 400 {
		t.Errorf("UpperRightY = %v, want 400", rect.UpperRightY)
	}

	if rect.Width() != 200 {
		t.Errorf("Width() = %v, want 200", rect.Width())
	}
	if rect.Height() != 200 {
		t.Errorf("Height() = %v, want 200", rect.Height())
	}

	arr := rect.ToArray()
	if len(arr) != 4 {
		t.Errorf("ToArray() length = %d, want 4", len(arr))
	}

	genericRect := rect.ToGenericRectangle()
	if genericRect == nil {
		t.Error("ToGenericRectangle() = nil")
	}
}

func TestVisualSignature_GetTextLines(t *testing.T) {
	config := DefaultVisualSignatureConfig()
	config.SignerName = "John Doe"
	config.Reason = "Approval"
	config.Location = "NYC"
	config.ContactInfo = "john@example.com"
	config.ShowContact = true

	vs, err := NewVisualSignature(200, 100, config)
	if err != nil {
		t.Fatalf("NewVisualSignature() error = %v", err)
	}

	lines := vs.getTextLines()

	// Should have at least signer name, date, reason, location, contact
	if len(lines) < 5 {
		t.Errorf("getTextLines() returned %d lines, want >= 5", len(lines))
	}

	// Check content
	found := map[string]bool{
		"signer":   false,
		"date":     false,
		"reason":   false,
		"location": false,
		"contact":  false,
	}

	for _, line := range lines {
		if bytes.Contains([]byte(line), []byte("John Doe")) {
			found["signer"] = true
		}
		if bytes.Contains([]byte(line), []byte("Date:")) {
			found["date"] = true
		}
		if bytes.Contains([]byte(line), []byte("Reason:")) {
			found["reason"] = true
		}
		if bytes.Contains([]byte(line), []byte("Location:")) {
			found["location"] = true
		}
		if bytes.Contains([]byte(line), []byte("Contact:")) {
			found["contact"] = true
		}
	}

	for key, value := range found {
		if !value {
			t.Errorf("getTextLines() missing %s line", key)
		}
	}
}

func TestVisualSignature_GetDimensions(t *testing.T) {
	config := DefaultVisualSignatureConfig()
	config.SignerName = "John Doe"

	vs, err := NewVisualSignature(250, 125, config)
	if err != nil {
		t.Fatalf("NewVisualSignature() error = %v", err)
	}

	w, h := vs.GetDimensions()
	if w != 250 || h != 125 {
		t.Errorf("GetDimensions() = (%v, %v), want (250, 125)", w, h)
	}
}
