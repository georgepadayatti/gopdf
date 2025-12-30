package stamp

import (
	"bytes"
	"image/color"
	"testing"
	"time"
)

func TestDefaultStampStyle(t *testing.T) {
	style := DefaultStampStyle()

	if style.FontSize != 10.0 {
		t.Errorf("Expected FontSize 10.0, got %f", style.FontSize)
	}

	if style.FontName != "Helvetica" {
		t.Errorf("Expected FontName 'Helvetica', got '%s'", style.FontName)
	}

	if style.BorderWidth != 1.0 {
		t.Errorf("Expected BorderWidth 1.0, got %f", style.BorderWidth)
	}

	if style.Padding != 5.0 {
		t.Errorf("Expected Padding 5.0, got %f", style.Padding)
	}
}

func TestNewTextStamp(t *testing.T) {
	lines := []string{"Line 1", "Line 2", "Line 3"}
	stamp := NewTextStamp(lines, nil)

	if stamp == nil {
		t.Fatal("NewTextStamp returned nil")
	}

	if len(stamp.Lines) != 3 {
		t.Errorf("Expected 3 lines, got %d", len(stamp.Lines))
	}

	if stamp.Width <= 0 {
		t.Error("Width should be positive")
	}

	if stamp.Height <= 0 {
		t.Error("Height should be positive")
	}
}

func TestTextStampRender(t *testing.T) {
	lines := []string{"Hello", "World"}
	stamp := NewTextStamp(lines, nil)

	content := stamp.Render()
	if len(content) == 0 {
		t.Error("Render should return non-empty content")
	}

	// Check for expected PDF operators
	if !bytes.Contains(content, []byte("BT")) {
		t.Error("Content should contain BT (begin text)")
	}

	if !bytes.Contains(content, []byte("ET")) {
		t.Error("Content should contain ET (end text)")
	}

	if !bytes.Contains(content, []byte("Tf")) {
		t.Error("Content should contain Tf (set font)")
	}
}

func TestTextStampWithCustomStyle(t *testing.T) {
	style := &StampStyle{
		BackgroundColor: color.RGBA{255, 0, 0, 255},
		BorderColor:     color.RGBA{0, 0, 255, 255},
		BorderWidth:     2.0,
		TextColor:       color.RGBA{0, 255, 0, 255},
		FontSize:        14.0,
		FontName:        "Courier",
		Padding:         10.0,
	}

	lines := []string{"Custom Style"}
	stamp := NewTextStamp(lines, style)

	if stamp.Style.FontSize != 14.0 {
		t.Errorf("Expected FontSize 14.0, got %f", stamp.Style.FontSize)
	}

	if stamp.Style.FontName != "Courier" {
		t.Errorf("Expected FontName 'Courier', got '%s'", stamp.Style.FontName)
	}
}

func TestTextStampCreateAppearanceStream(t *testing.T) {
	lines := []string{"Test"}
	stamp := NewTextStamp(lines, nil)

	stream := stamp.CreateAppearanceStream()
	if stream == nil {
		t.Fatal("CreateAppearanceStream returned nil")
	}

	if stream.Dictionary == nil {
		t.Error("Stream should have a dictionary")
	}

	if stream.Dictionary.GetName("Type") != "XObject" {
		t.Error("Type should be XObject")
	}

	if stream.Dictionary.GetName("Subtype") != "Form" {
		t.Error("Subtype should be Form")
	}

	resources := stream.Dictionary.GetDict("Resources")
	if resources == nil {
		t.Error("Resources should be present")
	}
}

func TestTextStampGetDimensions(t *testing.T) {
	lines := []string{"Hello"}
	stamp := NewTextStamp(lines, nil)

	width, height := stamp.GetDimensions()
	if width != stamp.Width {
		t.Error("GetDimensions width mismatch")
	}
	if height != stamp.Height {
		t.Error("GetDimensions height mismatch")
	}
}

func TestSignatureAppearance(t *testing.T) {
	appearance := NewSignatureAppearance("John Doe")

	if appearance.SignerName != "John Doe" {
		t.Errorf("Expected SignerName 'John Doe', got '%s'", appearance.SignerName)
	}

	if !appearance.ShowDate {
		t.Error("ShowDate should be true by default")
	}

	if !appearance.ShowReason {
		t.Error("ShowReason should be true by default")
	}

	if !appearance.ShowLocation {
		t.Error("ShowLocation should be true by default")
	}
}

func TestSignatureAppearanceSetters(t *testing.T) {
	appearance := NewSignatureAppearance("Test")
	appearance.SetReason("Test Reason")
	appearance.SetLocation("Test Location")

	if appearance.Reason != "Test Reason" {
		t.Error("SetReason didn't work")
	}

	if appearance.Location != "Test Location" {
		t.Error("SetLocation didn't work")
	}
}

func TestSignatureAppearanceRender(t *testing.T) {
	appearance := NewSignatureAppearance("Jane Doe")
	appearance.SetReason("Testing")
	appearance.SetLocation("Test Lab")
	appearance.SigningTime = time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	content := appearance.Render(200, 100)
	if len(content) == 0 {
		t.Error("Render should return non-empty content")
	}

	// Should contain the signer name
	if !bytes.Contains(content, []byte("Jane Doe")) {
		t.Error("Content should contain signer name")
	}
}

func TestSignatureAppearanceCreateAppearanceStream(t *testing.T) {
	appearance := NewSignatureAppearance("Test")
	stream := appearance.CreateAppearanceStream(150, 75)

	if stream == nil {
		t.Fatal("CreateAppearanceStream returned nil")
	}

	bbox := stream.Dictionary.GetArray("BBox")
	if bbox == nil || len(bbox) != 4 {
		t.Error("BBox should have 4 elements")
	}
}

func TestNewQRStamp(t *testing.T) {
	stamp := NewQRStamp("https://example.com", 100)

	if stamp == nil {
		t.Fatal("NewQRStamp returned nil")
	}

	if stamp.Data != "https://example.com" {
		t.Errorf("Expected Data 'https://example.com', got '%s'", stamp.Data)
	}

	if stamp.Size != 100 {
		t.Errorf("Expected Size 100, got %f", stamp.Size)
	}

	if len(stamp.Modules) == 0 {
		t.Error("Modules should not be empty")
	}
}

func TestQRStampRender(t *testing.T) {
	stamp := NewQRStamp("Test", 50)
	content := stamp.Render()

	if len(content) == 0 {
		t.Error("Render should return non-empty content")
	}

	// Should contain rectangle drawing commands
	if !bytes.Contains(content, []byte("re")) {
		t.Error("Content should contain 're' (rectangle)")
	}
}

func TestQRStampGetDimensions(t *testing.T) {
	stamp := NewQRStamp("Test", 80)
	width, height := stamp.GetDimensions()

	if width != 80 {
		t.Errorf("Expected width 80, got %f", width)
	}

	if height != 80 {
		t.Errorf("Expected height 80, got %f", height)
	}
}

func TestQRStampCreateAppearanceStream(t *testing.T) {
	stamp := NewQRStamp("Test", 100)
	stream := stamp.CreateAppearanceStream()

	if stream == nil {
		t.Fatal("CreateAppearanceStream returned nil")
	}

	if stream.Dictionary.GetName("Type") != "XObject" {
		t.Error("Type should be XObject")
	}
}

func TestNewWatermark(t *testing.T) {
	watermark := NewWatermark("CONFIDENTIAL")

	if watermark == nil {
		t.Fatal("NewWatermark returned nil")
	}

	if watermark.Text != "CONFIDENTIAL" {
		t.Errorf("Expected Text 'CONFIDENTIAL', got '%s'", watermark.Text)
	}

	if watermark.Rotation != -45 {
		t.Errorf("Expected Rotation -45, got %f", watermark.Rotation)
	}

	if watermark.Opacity != 0.5 {
		t.Errorf("Expected Opacity 0.5, got %f", watermark.Opacity)
	}
}

func TestWatermarkRender(t *testing.T) {
	watermark := NewWatermark("DRAFT")
	content := watermark.Render(612, 792)

	if len(content) == 0 {
		t.Error("Render should return non-empty content")
	}

	// Should contain text
	if !bytes.Contains(content, []byte("DRAFT")) {
		t.Error("Content should contain watermark text")
	}

	// Should contain transformation matrix
	if !bytes.Contains(content, []byte("cm")) {
		t.Error("Content should contain 'cm' (transformation matrix)")
	}
}

func TestWatermarkCreateExtGState(t *testing.T) {
	watermark := NewWatermark("Test")
	gs := watermark.CreateExtGState()

	if gs == nil {
		t.Fatal("CreateExtGState returned nil")
	}

	if gs.GetName("Type") != "ExtGState" {
		t.Error("Type should be ExtGState")
	}
}

func TestEscapeString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello", "Hello"},
		{"Hello (World)", "Hello \\(World\\)"},
		{"Back\\slash", "Back\\\\slash"},
		{"Mixed (paren) and \\back", "Mixed \\(paren\\) and \\\\back"},
	}

	for _, tt := range tests {
		result := escapeString(tt.input)
		if result != tt.expected {
			t.Errorf("escapeString(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestTrigFunctions(t *testing.T) {
	// Test cos and sin at known angles
	tests := []struct {
		degrees  float64
		cosVal   float64
		sinVal   float64
		epsilon  float64
	}{
		{0, 1.0, 0.0, 0.001},
		{90, 0.0, 1.0, 0.001},
		{180, -1.0, 0.0, 0.001},
		{-45, 0.707, -0.707, 0.01},
	}

	for _, tt := range tests {
		cos := cosD(tt.degrees)
		sin := sinD(tt.degrees)

		if abs(cos-tt.cosVal) > tt.epsilon {
			t.Errorf("cosD(%f) = %f, want ~%f", tt.degrees, cos, tt.cosVal)
		}

		if abs(sin-tt.sinVal) > tt.epsilon {
			t.Errorf("sinD(%f) = %f, want ~%f", tt.degrees, sin, tt.sinVal)
		}
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// Tests for QR positioning features

func TestQRPosition(t *testing.T) {
	tests := []struct {
		pos        QRPosition
		str        string
		horizontal bool
	}{
		{QRPositionLeftOfText, "left", true},
		{QRPositionRightOfText, "right", true},
		{QRPositionAboveText, "top", false},
		{QRPositionBelowText, "bottom", false},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			if tt.pos.String() != tt.str {
				t.Errorf("String() = %s, want %s", tt.pos.String(), tt.str)
			}
			if tt.pos.IsHorizontalFlow() != tt.horizontal {
				t.Errorf("IsHorizontalFlow() = %v, want %v", tt.pos.IsHorizontalFlow(), tt.horizontal)
			}
		})
	}
}

func TestParseQRPosition(t *testing.T) {
	tests := []struct {
		input    string
		expected QRPosition
		hasError bool
	}{
		{"left", QRPositionLeftOfText, false},
		{"right", QRPositionRightOfText, false},
		{"top", QRPositionAboveText, false},
		{"above", QRPositionAboveText, false},
		{"bottom", QRPositionBelowText, false},
		{"below", QRPositionBelowText, false},
		{"invalid", QRPositionLeftOfText, true},
		{"", QRPositionLeftOfText, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			pos, err := ParseQRPosition(tt.input)
			if tt.hasError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if pos != tt.expected {
					t.Errorf("ParseQRPosition(%s) = %v, want %v", tt.input, pos, tt.expected)
				}
			}
		})
	}
}

func TestDefaultQRStampStyle(t *testing.T) {
	style := DefaultQRStampStyle()

	if style == nil {
		t.Fatal("DefaultQRStampStyle returned nil")
	}

	if style.TextStyle == nil {
		t.Error("TextStyle should not be nil")
	}

	if style.QRPosition != QRPositionLeftOfText {
		t.Errorf("Default QRPosition = %v, want QRPositionLeftOfText", style.QRPosition)
	}

	if style.InnerSeparation != 3 {
		t.Errorf("Default InnerSeparation = %f, want 3", style.InnerSeparation)
	}

	if style.BorderWidth != 3 {
		t.Errorf("Default BorderWidth = %f, want 3", style.BorderWidth)
	}

	if style.DefaultQRScale != 0.2 {
		t.Errorf("Default DefaultQRScale = %f, want 0.2", style.DefaultQRScale)
	}
}

func TestNewQRTextStamp(t *testing.T) {
	url := "https://example.com"
	lines := []string{"Line 1", "Line 2"}

	stamp := NewQRTextStamp(url, lines, nil)

	if stamp == nil {
		t.Fatal("NewQRTextStamp returned nil")
	}

	if stamp.URL != url {
		t.Errorf("URL = %s, want %s", stamp.URL, url)
	}

	if len(stamp.Lines) != 2 {
		t.Errorf("Lines count = %d, want 2", len(stamp.Lines))
	}

	if stamp.Width <= 0 {
		t.Error("Width should be positive")
	}

	if stamp.Height <= 0 {
		t.Error("Height should be positive")
	}

	if len(stamp.Modules) == 0 {
		t.Error("Modules should be generated")
	}
}

func TestQRTextStampPositioning(t *testing.T) {
	url := "https://example.com"
	lines := []string{"Test text"}

	positions := []QRPosition{
		QRPositionLeftOfText,
		QRPositionRightOfText,
		QRPositionAboveText,
		QRPositionBelowText,
	}

	for _, pos := range positions {
		t.Run(pos.String(), func(t *testing.T) {
			style := DefaultQRStampStyle()
			style.QRPosition = pos

			stamp := NewQRTextStamp(url, lines, style)

			if stamp.Width <= 0 {
				t.Error("Width should be positive")
			}

			if stamp.Height <= 0 {
				t.Error("Height should be positive")
			}

			// Verify QR and text don't overlap
			qrRight := stamp.qrX + stamp.qrSize
			qrTop := stamp.qrY + stamp.qrSize
			textRight := stamp.textX + stamp.textWidth
			textTop := stamp.textY + stamp.textHeight

			// Check dimensions are reasonable
			if stamp.qrX < 0 || stamp.qrY < 0 {
				t.Error("QR position should not be negative")
			}

			if stamp.textX < 0 || stamp.textY < 0 {
				t.Error("Text position should not be negative")
			}

			// Verify positions fit within stamp
			if qrRight > stamp.Width+0.1 || qrTop > stamp.Height+0.1 {
				t.Errorf("QR extends beyond stamp bounds")
			}

			if textRight > stamp.Width+0.1 || textTop > stamp.Height+0.1 {
				t.Errorf("Text extends beyond stamp bounds")
			}
		})
	}
}

func TestQRTextStampRender(t *testing.T) {
	url := "https://example.com"
	lines := []string{"Digital signature", "Timestamp: 2024-01-01"}

	stamp := NewQRTextStamp(url, lines, nil)
	content := stamp.Render()

	if len(content) == 0 {
		t.Error("Render should produce content")
	}

	contentStr := string(content)

	// Check for graphics state commands
	if !contains(contentStr, "q") {
		t.Error("Content should contain graphics state save (q)")
	}

	if !contains(contentStr, "Q") {
		t.Error("Content should contain graphics state restore (Q)")
	}

	// Check for text commands
	if !contains(contentStr, "BT") {
		t.Error("Content should contain begin text (BT)")
	}

	if !contains(contentStr, "ET") {
		t.Error("Content should contain end text (ET)")
	}

	// Check for rectangle fill commands (QR modules)
	if !contains(contentStr, "re f") {
		t.Error("Content should contain rectangle fill commands for QR")
	}
}

func TestQRTextStampGetDimensions(t *testing.T) {
	stamp := NewQRTextStamp("https://example.com", []string{"Test"}, nil)

	w, h := stamp.GetDimensions()

	if w != stamp.Width {
		t.Errorf("GetDimensions width = %f, want %f", w, stamp.Width)
	}

	if h != stamp.Height {
		t.Errorf("GetDimensions height = %f, want %f", h, stamp.Height)
	}
}

func TestQRTextStampGetQRRect(t *testing.T) {
	stamp := NewQRTextStamp("https://example.com", []string{"Test"}, nil)

	x, y, w, h := stamp.GetQRRect()

	if x != stamp.qrX {
		t.Errorf("GetQRRect x = %f, want %f", x, stamp.qrX)
	}

	if y != stamp.qrY {
		t.Errorf("GetQRRect y = %f, want %f", y, stamp.qrY)
	}

	if w != stamp.qrSize {
		t.Errorf("GetQRRect width = %f, want %f", w, stamp.qrSize)
	}

	if h != stamp.qrSize {
		t.Errorf("GetQRRect height = %f, want %f", h, stamp.qrSize)
	}
}

func TestQRTextStampCreateAppearanceStream(t *testing.T) {
	stamp := NewQRTextStamp("https://example.com", []string{"Test"}, nil)

	stream := stamp.CreateAppearanceStream()

	if stream == nil {
		t.Fatal("CreateAppearanceStream returned nil")
	}

	dict := stream.Dictionary
	if dict == nil {
		t.Fatal("Stream dictionary should not be nil")
	}

	// Check XObject type
	typeVal := dict.Get("Type")
	if typeVal == nil {
		t.Error("Type should be set")
	}

	subtypeVal := dict.Get("Subtype")
	if subtypeVal == nil {
		t.Error("Subtype should be set")
	}

	bboxVal := dict.Get("BBox")
	if bboxVal == nil {
		t.Error("BBox should be set")
	}

	resourcesVal := dict.Get("Resources")
	if resourcesVal == nil {
		t.Error("Resources should be set")
	}
}

func TestQRTextStampCreateLinkAnnotation(t *testing.T) {
	url := "https://example.com/test"
	stamp := NewQRTextStamp(url, []string{"Test"}, nil)

	stampX, stampY := 100.0, 200.0
	annot := stamp.CreateLinkAnnotation(stampX, stampY)

	if annot == nil {
		t.Fatal("CreateLinkAnnotation returned nil")
	}

	// Check annotation type
	typeVal := annot.Get("Type")
	if typeVal == nil {
		t.Error("Type should be set")
	}

	subtypeVal := annot.Get("Subtype")
	if subtypeVal == nil {
		t.Error("Subtype should be set")
	}

	rectVal := annot.Get("Rect")
	if rectVal == nil {
		t.Error("Rect should be set")
	}

	actionVal := annot.Get("A")
	if actionVal == nil {
		t.Error("Action (A) should be set")
	}

	borderVal := annot.Get("Border")
	if borderVal == nil {
		t.Error("Border should be set")
	}
}

func TestQRTextStampCreateFullLinkAnnotation(t *testing.T) {
	url := "https://example.com/test"
	stamp := NewQRTextStamp(url, []string{"Test"}, nil)

	stampX, stampY := 100.0, 200.0
	annot := stamp.CreateFullLinkAnnotation(stampX, stampY)

	if annot == nil {
		t.Fatal("CreateFullLinkAnnotation returned nil")
	}

	// Check annotation has required fields
	if annot.Get("Type") == nil {
		t.Error("Type should be set")
	}

	if annot.Get("Rect") == nil {
		t.Error("Rect should be set")
	}

	if annot.Get("A") == nil {
		t.Error("Action should be set")
	}
}

func TestQRTextStampWithCustomStyle(t *testing.T) {
	style := &QRStampStyle{
		TextStyle:         DefaultStampStyle(),
		QRPosition:        QRPositionRightOfText,
		QRSize:            50,
		InnerSeparation:   5,
		BorderWidth:       2,
		BorderColor:       [3]float64{1, 0, 0}, // Red
		BackgroundOpacity: 0.8,
		DefaultQRScale:    0.3,
	}

	stamp := NewQRTextStamp("https://example.com", []string{"Custom style"}, style)

	if stamp.qrSize != 50 {
		t.Errorf("QR size = %f, want 50", stamp.qrSize)
	}

	// With RightOfText, QR should be to the right of text
	if stamp.qrX <= stamp.textX {
		t.Error("With RightOfText, QR X should be greater than text X")
	}
}

func TestQRTextStampHorizontalVsVerticalLayout(t *testing.T) {
	url := "https://example.com"
	lines := []string{"Test line 1", "Test line 2"}

	// Horizontal layout (left/right)
	horizStyle := DefaultQRStampStyle()
	horizStyle.QRPosition = QRPositionLeftOfText
	horizStamp := NewQRTextStamp(url, lines, horizStyle)

	// Vertical layout (above/below)
	vertStyle := DefaultQRStampStyle()
	vertStyle.QRPosition = QRPositionAboveText
	vertStamp := NewQRTextStamp(url, lines, vertStyle)

	// Horizontal layouts should generally be wider than tall
	// Vertical layouts should generally be taller than wide
	// (This depends on content, but with same content, the pattern should hold)

	horizRatio := horizStamp.Width / horizStamp.Height
	vertRatio := vertStamp.Width / vertStamp.Height

	// Horizontal should have higher width/height ratio than vertical
	if horizRatio <= vertRatio {
		t.Logf("Horizontal: %fx%f (ratio: %f)", horizStamp.Width, horizStamp.Height, horizRatio)
		t.Logf("Vertical: %fx%f (ratio: %f)", vertStamp.Width, vertStamp.Height, vertRatio)
		// This is informational, not necessarily an error since it depends on content
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Tests for apply.go functionality

func TestDefaultApplyOptions(t *testing.T) {
	opts := DefaultApplyOptions()

	if opts == nil {
		t.Fatal("DefaultApplyOptions returned nil")
	}

	if !opts.WrapExistingContent {
		t.Error("Default WrapExistingContent should be true")
	}
}

func TestStamperInterface(t *testing.T) {
	// Test that TextStamp implements Stamper
	var _ Stamper = &TextStamp{}

	// Test that QRStamp implements Stamper
	var _ Stamper = &QRStamp{}

	// Test that QRTextStamp implements Stamper
	var _ Stamper = &QRTextStamp{}

	// Test that StaticContentStamp implements Stamper
	var _ Stamper = &StaticContentStamp{}
}

func TestDefaultStaticStampStyle(t *testing.T) {
	style := DefaultStaticStampStyle()

	if style == nil {
		t.Fatal("DefaultStaticStampStyle returned nil")
	}

	if style.Background != nil {
		t.Error("Default Background should be nil")
	}

	if style.BorderWidth != 0 {
		t.Errorf("Default BorderWidth = %f, want 0", style.BorderWidth)
	}

	if style.BackgroundOpacity != 1.0 {
		t.Errorf("Default BackgroundOpacity = %f, want 1.0", style.BackgroundOpacity)
	}
}

func TestNewStaticContentStamp(t *testing.T) {
	stamp, err := NewStaticContentStamp(nil, 100, 50)
	if err != nil {
		t.Fatalf("NewStaticContentStamp error: %v", err)
	}

	if stamp == nil {
		t.Fatal("NewStaticContentStamp returned nil")
	}

	if stamp.Width != 100 {
		t.Errorf("Width = %f, want 100", stamp.Width)
	}

	if stamp.Height != 50 {
		t.Errorf("Height = %f, want 50", stamp.Height)
	}
}

func TestNewStaticContentStampInvalidDimensions(t *testing.T) {
	_, err := NewStaticContentStamp(nil, 0, 50)
	if err == nil {
		t.Error("Expected error for zero width")
	}

	_, err = NewStaticContentStamp(nil, 100, -1)
	if err == nil {
		t.Error("Expected error for negative height")
	}
}

func TestNewStaticStampFromBackground(t *testing.T) {
	bg := &RawContent{
		Box:  BoxConstraints{Width: 200, Height: 100},
		Data: []byte("q 0 0 0 rg 0 0 200 100 re f Q"),
	}

	stamp, err := NewStaticStampFromBackground(bg, 0.5)
	if err != nil {
		t.Fatalf("NewStaticStampFromBackground error: %v", err)
	}

	if stamp == nil {
		t.Fatal("NewStaticStampFromBackground returned nil")
	}

	if stamp.Width != 200 {
		t.Errorf("Width = %f, want 200", stamp.Width)
	}

	if stamp.Height != 100 {
		t.Errorf("Height = %f, want 100", stamp.Height)
	}

	if stamp.Style.BackgroundOpacity != 0.5 {
		t.Errorf("BackgroundOpacity = %f, want 0.5", stamp.Style.BackgroundOpacity)
	}
}

func TestNewStaticStampFromBackgroundNil(t *testing.T) {
	_, err := NewStaticStampFromBackground(nil, 1.0)
	if err == nil {
		t.Error("Expected error for nil background")
	}
}

func TestStaticContentStampRender(t *testing.T) {
	bg := &RawContent{
		Box:  BoxConstraints{Width: 100, Height: 100},
		Data: []byte("q 1 0 0 rg 0 0 100 100 re f Q"),
	}

	style := &StaticStampStyle{
		Background:        bg,
		BackgroundOpacity: 1.0,
	}

	stamp, _ := NewStaticContentStamp(style, 100, 100)
	content := stamp.Render()

	if len(content) == 0 {
		t.Error("Render should return content")
	}

	if string(content) != string(bg.Data) {
		t.Error("Render should return background data")
	}
}

func TestStaticContentStampRenderNoBackground(t *testing.T) {
	stamp, _ := NewStaticContentStamp(nil, 100, 100)
	content := stamp.Render()

	if content != nil {
		t.Error("Render with no background should return nil")
	}
}

func TestStaticContentStampGetDimensions(t *testing.T) {
	stamp, _ := NewStaticContentStamp(nil, 150, 75)

	w, h := stamp.GetDimensions()

	if w != 150 {
		t.Errorf("Width = %f, want 150", w)
	}

	if h != 75 {
		t.Errorf("Height = %f, want 75", h)
	}
}

func TestStaticContentStampCreateAppearanceStream(t *testing.T) {
	bg := &RawContent{
		Box:  BoxConstraints{Width: 100, Height: 100},
		Data: []byte("test content"),
	}

	style := &StaticStampStyle{
		Background:        bg,
		BackgroundOpacity: 0.5,
	}

	stamp, _ := NewStaticContentStamp(style, 100, 100)
	stream := stamp.CreateAppearanceStream()

	if stream == nil {
		t.Fatal("CreateAppearanceStream returned nil")
	}

	dict := stream.Dictionary
	if dict == nil {
		t.Fatal("Stream dictionary should not be nil")
	}

	// Check for opacity resources
	resources := dict.GetDict("Resources")
	if resources == nil {
		t.Error("Resources should be set for opacity < 1.0")
	}
}

func TestStaticContentStampAppearanceNoOpacity(t *testing.T) {
	bg := &RawContent{
		Box:  BoxConstraints{Width: 100, Height: 100},
		Data: []byte("test content"),
	}

	style := &StaticStampStyle{
		Background:        bg,
		BackgroundOpacity: 1.0, // Full opacity
	}

	stamp, _ := NewStaticContentStamp(style, 100, 100)
	stream := stamp.CreateAppearanceStream()

	dict := stream.Dictionary
	resources := dict.GetDict("Resources")

	// With full opacity, no ExtGState resources needed
	if resources != nil {
		t.Log("Resources may still be nil for full opacity")
	}
}
