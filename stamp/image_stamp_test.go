package stamp

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// createTestPNG creates a simple PNG image for testing.
func createTestPNG(width, height int, hasAlpha bool) []byte {
	var img image.Image
	if hasAlpha {
		rgba := image.NewRGBA(image.Rect(0, 0, width, height))
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				rgba.Set(x, y, color.RGBA{
					R: uint8(x % 256),
					G: uint8(y % 256),
					B: uint8((x + y) % 256),
					A: uint8((x * y) % 256),
				})
			}
		}
		img = rgba
	} else {
		rgb := image.NewRGBA(image.Rect(0, 0, width, height))
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				rgb.Set(x, y, color.RGBA{
					R: uint8(x % 256),
					G: uint8(y % 256),
					B: uint8((x + y) % 256),
					A: 255,
				})
			}
		}
		img = rgb
	}

	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

func TestImageScaleMode_String(t *testing.T) {
	tests := []struct {
		mode     ImageScaleMode
		expected string
	}{
		{ImageScaleFit, "fit"},
		{ImageScaleFill, "fill"},
		{ImageScaleStretch, "stretch"},
		{ImageScaleNone, "none"},
		{ImageScaleMode(99), "unknown"},
	}

	for _, tc := range tests {
		if got := tc.mode.String(); got != tc.expected {
			t.Errorf("ImageScaleMode(%d).String() = %q, want %q", tc.mode, got, tc.expected)
		}
	}
}

func TestParseImageScaleMode(t *testing.T) {
	tests := []struct {
		input    string
		expected ImageScaleMode
		wantErr  bool
	}{
		{"fit", ImageScaleFit, false},
		{"fill", ImageScaleFill, false},
		{"stretch", ImageScaleStretch, false},
		{"none", ImageScaleNone, false},
		{"invalid", ImageScaleFit, true},
	}

	for _, tc := range tests {
		got, err := ParseImageScaleMode(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseImageScaleMode(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			continue
		}
		if got != tc.expected {
			t.Errorf("ParseImageScaleMode(%q) = %v, want %v", tc.input, got, tc.expected)
		}
	}
}

func TestDefaultImageStampStyle(t *testing.T) {
	style := DefaultImageStampStyle()

	if style.ScaleMode != ImageScaleFit {
		t.Errorf("ScaleMode = %v, want %v", style.ScaleMode, ImageScaleFit)
	}
	if style.Position != ImagePositionCenter {
		t.Errorf("Position = %v, want %v", style.Position, ImagePositionCenter)
	}
	if style.Opacity != 1.0 {
		t.Errorf("Opacity = %v, want 1.0", style.Opacity)
	}
	if style.BorderWidth != 0 {
		t.Errorf("BorderWidth = %v, want 0", style.BorderWidth)
	}
	if style.Padding != 0 {
		t.Errorf("Padding = %v, want 0", style.Padding)
	}
}

func TestNewImageStamp(t *testing.T) {
	imageData := createTestPNG(100, 100, false)

	t.Run("BasicCreation", func(t *testing.T) {
		stamp, err := NewImageStamp(imageData, 200, 200, nil)
		if err != nil {
			t.Fatalf("NewImageStamp() error = %v", err)
		}
		if stamp == nil {
			t.Fatal("NewImageStamp() returned nil")
		}
		if stamp.Width != 200 || stamp.Height != 200 {
			t.Errorf("Dimensions = (%v, %v), want (200, 200)", stamp.Width, stamp.Height)
		}
	})

	t.Run("WithCustomStyle", func(t *testing.T) {
		style := DefaultImageStampStyle()
		style.ScaleMode = ImageScaleStretch
		style.Padding = 10

		stamp, err := NewImageStamp(imageData, 200, 200, style)
		if err != nil {
			t.Fatalf("NewImageStamp() error = %v", err)
		}
		if stamp.Style.ScaleMode != ImageScaleStretch {
			t.Errorf("ScaleMode = %v, want %v", stamp.Style.ScaleMode, ImageScaleStretch)
		}
	})

	t.Run("InvalidImageData", func(t *testing.T) {
		_, err := NewImageStamp([]byte("not an image"), 200, 200, nil)
		if err == nil {
			t.Error("NewImageStamp() expected error for invalid image data")
		}
	})
}

func TestNewImageStamp_WithAlpha(t *testing.T) {
	imageData := createTestPNG(100, 100, true)

	stamp, err := NewImageStamp(imageData, 200, 200, nil)
	if err != nil {
		t.Fatalf("NewImageStamp() error = %v", err)
	}

	if !stamp.HasAlpha() {
		t.Error("HasAlpha() = false, want true")
	}
}

func TestImageStamp_Layout(t *testing.T) {
	imageData := createTestPNG(100, 50, false) // 2:1 aspect ratio

	tests := []struct {
		name       string
		scaleMode  ImageScaleMode
		position   ImagePosition
		width      float64
		height     float64
		wantImgW   float64
		wantImgH   float64
	}{
		{
			name:      "FitWide",
			scaleMode: ImageScaleFit,
			position:  ImagePositionCenter,
			width:     200,
			height:    200,
			wantImgW:  200, // Constrained by width
			wantImgH:  100,
		},
		{
			name:      "FitTall",
			scaleMode: ImageScaleFit,
			position:  ImagePositionCenter,
			width:     100,
			height:    200,
			wantImgW:  100,
			wantImgH:  50,
		},
		{
			name:      "Stretch",
			scaleMode: ImageScaleStretch,
			position:  ImagePositionCenter,
			width:     200,
			height:    200,
			wantImgW:  200,
			wantImgH:  200,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			style := DefaultImageStampStyle()
			style.ScaleMode = tc.scaleMode
			style.Position = tc.position

			stamp, err := NewImageStamp(imageData, tc.width, tc.height, style)
			if err != nil {
				t.Fatalf("NewImageStamp() error = %v", err)
			}

			w, h, _, _ := stamp.GetImageDimensions()
			if w != tc.wantImgW || h != tc.wantImgH {
				t.Errorf("Image dimensions = (%v, %v), want (%v, %v)", w, h, tc.wantImgW, tc.wantImgH)
			}
		})
	}
}

func TestImageStamp_Render(t *testing.T) {
	imageData := createTestPNG(100, 100, false)

	stamp, err := NewImageStamp(imageData, 200, 200, nil)
	if err != nil {
		t.Fatalf("NewImageStamp() error = %v", err)
	}

	content := stamp.Render()
	if len(content) == 0 {
		t.Error("Render() returned empty content")
	}

	// Check for expected PDF operators
	contentStr := string(content)
	if !bytes.Contains(content, []byte("q\n")) {
		t.Error("Render() missing graphics state save")
	}
	if !bytes.Contains(content, []byte("Q\n")) {
		t.Error("Render() missing graphics state restore")
	}
	if !bytes.Contains(content, []byte("/Im1 Do")) {
		t.Error("Render() missing image draw operator")
	}
	_ = contentStr
}

func TestImageStamp_CreateAppearanceStream(t *testing.T) {
	imageData := createTestPNG(100, 100, false)

	stamp, err := NewImageStamp(imageData, 200, 200, nil)
	if err != nil {
		t.Fatalf("NewImageStamp() error = %v", err)
	}

	formStream, additionalStreams, err := stamp.CreateAppearanceStream()
	if err != nil {
		t.Fatalf("CreateAppearanceStream() error = %v", err)
	}

	if formStream == nil {
		t.Error("CreateAppearanceStream() returned nil form stream")
	}

	if len(additionalStreams) == 0 {
		t.Error("CreateAppearanceStream() returned no additional streams (expected image XObject)")
	}
}

func TestImageStamp_CreateAppearanceStream_WithAlpha(t *testing.T) {
	imageData := createTestPNG(100, 100, true)

	stamp, err := NewImageStamp(imageData, 200, 200, nil)
	if err != nil {
		t.Fatalf("NewImageStamp() error = %v", err)
	}

	formStream, additionalStreams, err := stamp.CreateAppearanceStream()
	if err != nil {
		t.Fatalf("CreateAppearanceStream() error = %v", err)
	}

	if formStream == nil {
		t.Error("CreateAppearanceStream() returned nil form stream")
	}

	// Should have both image and alpha mask
	if len(additionalStreams) < 2 {
		t.Errorf("CreateAppearanceStream() returned %d streams, want >= 2 (image + alpha)", len(additionalStreams))
	}
}

func TestImageStamp_GetDimensions(t *testing.T) {
	imageData := createTestPNG(100, 100, false)

	stamp, err := NewImageStamp(imageData, 200, 150, nil)
	if err != nil {
		t.Fatalf("NewImageStamp() error = %v", err)
	}

	w, h := stamp.GetDimensions()
	if w != 200 || h != 150 {
		t.Errorf("GetDimensions() = (%v, %v), want (200, 150)", w, h)
	}
}

func TestImageStamp_WithOpacity(t *testing.T) {
	imageData := createTestPNG(100, 100, false)
	style := DefaultImageStampStyle()
	style.Opacity = 0.5

	stamp, err := NewImageStamp(imageData, 200, 200, style)
	if err != nil {
		t.Fatalf("NewImageStamp() error = %v", err)
	}

	content := stamp.Render()
	if !bytes.Contains(content, []byte("/GS1 gs")) {
		t.Error("Render() should include graphics state for opacity")
	}
}

func TestImageStamp_WithBorder(t *testing.T) {
	imageData := createTestPNG(100, 100, false)
	style := DefaultImageStampStyle()
	style.BorderWidth = 2
	style.BorderColor = color.RGBA{255, 0, 0, 255}

	stamp, err := NewImageStamp(imageData, 200, 200, style)
	if err != nil {
		t.Fatalf("NewImageStamp() error = %v", err)
	}

	content := stamp.Render()
	// Should have stroke color and width
	if !bytes.Contains(content, []byte("RG")) {
		t.Error("Render() should include stroke color for border")
	}
	if !bytes.Contains(content, []byte("re S")) {
		t.Error("Render() should include rectangle stroke for border")
	}
}

func TestDefaultImageTextStampStyle(t *testing.T) {
	style := DefaultImageTextStampStyle()

	if style.ImageStyle == nil {
		t.Error("ImageStyle is nil")
	}
	if style.TextStyle == nil {
		t.Error("TextStyle is nil")
	}
	if style.ImagePosition != ImageTextPositionLeft {
		t.Errorf("ImagePosition = %v, want %v", style.ImagePosition, ImageTextPositionLeft)
	}
	if style.ImageRatio != 0.4 {
		t.Errorf("ImageRatio = %v, want 0.4", style.ImageRatio)
	}
	if style.Separation != 5 {
		t.Errorf("Separation = %v, want 5", style.Separation)
	}
}

func TestNewImageTextStamp(t *testing.T) {
	imageData := createTestPNG(100, 100, false)
	lines := []string{"Line 1", "Line 2", "Line 3"}

	t.Run("BasicCreation", func(t *testing.T) {
		stamp, err := NewImageTextStamp(imageData, lines, 300, 200, nil)
		if err != nil {
			t.Fatalf("NewImageTextStamp() error = %v", err)
		}
		if stamp == nil {
			t.Fatal("NewImageTextStamp() returned nil")
		}
		if stamp.Width != 300 || stamp.Height != 200 {
			t.Errorf("Dimensions = (%v, %v), want (300, 200)", stamp.Width, stamp.Height)
		}
	})

	t.Run("WithCustomStyle", func(t *testing.T) {
		style := DefaultImageTextStampStyle()
		style.ImagePosition = ImageTextPositionRight
		style.ImageRatio = 0.5

		stamp, err := NewImageTextStamp(imageData, lines, 300, 200, style)
		if err != nil {
			t.Fatalf("NewImageTextStamp() error = %v", err)
		}
		if stamp.Style.ImagePosition != ImageTextPositionRight {
			t.Errorf("ImagePosition = %v, want %v", stamp.Style.ImagePosition, ImageTextPositionRight)
		}
	})
}

func TestImageTextStamp_Render(t *testing.T) {
	imageData := createTestPNG(100, 100, false)
	lines := []string{"Test Line"}

	stamp, err := NewImageTextStamp(imageData, lines, 300, 200, nil)
	if err != nil {
		t.Fatalf("NewImageTextStamp() error = %v", err)
	}

	content := stamp.Render()
	if len(content) == 0 {
		t.Error("Render() returned empty content")
	}

	// Check for expected PDF operators
	if !bytes.Contains(content, []byte("BT\n")) {
		t.Error("Render() missing begin text operator")
	}
	if !bytes.Contains(content, []byte("ET\n")) {
		t.Error("Render() missing end text operator")
	}
	if !bytes.Contains(content, []byte("/Im1 Do")) {
		t.Error("Render() missing image draw operator")
	}
}

func TestImageTextStamp_Positions(t *testing.T) {
	imageData := createTestPNG(100, 100, false)
	lines := []string{"Test"}

	positions := []ImageTextPosition{
		ImageTextPositionLeft,
		ImageTextPositionRight,
		ImageTextPositionAbove,
		ImageTextPositionBelow,
		ImageTextPositionBackground,
	}

	for _, pos := range positions {
		t.Run(pos.String(), func(t *testing.T) {
			style := DefaultImageTextStampStyle()
			style.ImagePosition = pos

			stamp, err := NewImageTextStamp(imageData, lines, 300, 200, style)
			if err != nil {
				t.Fatalf("NewImageTextStamp() error = %v", err)
			}

			content := stamp.Render()
			if len(content) == 0 {
				t.Error("Render() returned empty content")
			}
		})
	}
}

func (p ImageTextPosition) String() string {
	switch p {
	case ImageTextPositionLeft:
		return "left"
	case ImageTextPositionRight:
		return "right"
	case ImageTextPositionAbove:
		return "above"
	case ImageTextPositionBelow:
		return "below"
	case ImageTextPositionBackground:
		return "background"
	default:
		return "unknown"
	}
}
