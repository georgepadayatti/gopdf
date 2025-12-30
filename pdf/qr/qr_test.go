package qr

import (
	"bytes"
	"testing"
)

func TestNewQRCode(t *testing.T) {
	qr := NewQRCode("Hello", ECLevelL)

	if qr == nil {
		t.Fatal("NewQRCode returned nil")
	}

	if qr.Version < 1 {
		t.Error("Version should be at least 1")
	}

	if qr.Size != 4*qr.Version+17 {
		t.Errorf("Size should be 4*version+17, got %d", qr.Size)
	}

	if len(qr.Modules) != qr.Size {
		t.Errorf("Modules rows should match size")
	}
}

func TestQRCodeVersionSelection(t *testing.T) {
	tests := []struct {
		data    string
		ecLevel ErrorCorrectionLevel
		minVer  int
		maxVer  int
	}{
		{"Hi", ECLevelL, 1, 1},
		{"Hello World", ECLevelL, 1, 2},
		{"Hello World", ECLevelH, 1, 2},
		{"This is a longer string that requires more capacity", ECLevelL, 2, 5},
	}

	for _, tt := range tests {
		qr := NewQRCode(tt.data, tt.ecLevel)
		if qr.Version < tt.minVer || qr.Version > tt.maxVer {
			t.Errorf("For data '%s' with EC %d, expected version between %d-%d, got %d",
				tt.data, tt.ecLevel, tt.minVer, tt.maxVer, qr.Version)
		}
	}
}

func TestQRCodeFinderPatterns(t *testing.T) {
	qr := NewQRCode("Test", ECLevelL)

	// Check top-left finder pattern
	// Outer border should be true
	for i := 0; i < 7; i++ {
		if !qr.Modules[0][i] {
			t.Errorf("Top-left finder pattern: expected module at (0,%d) to be true", i)
		}
		if !qr.Modules[6][i] {
			t.Errorf("Top-left finder pattern: expected module at (6,%d) to be true", i)
		}
	}

	// Check that separator is white
	for i := 0; i < 8; i++ {
		if qr.Modules[7][i] && i < qr.Size-8 {
			t.Errorf("Separator at (7,%d) should be false", i)
		}
	}
}

func TestQRCodeTimingPatterns(t *testing.T) {
	qr := NewQRCode("Test", ECLevelL)

	// Timing patterns alternate
	for i := 8; i < qr.Size-8; i++ {
		expected := (i % 2) == 0
		if qr.Modules[6][i] != expected {
			t.Errorf("Horizontal timing pattern at column %d: expected %v, got %v",
				i, expected, qr.Modules[6][i])
		}
		if qr.Modules[i][6] != expected {
			t.Errorf("Vertical timing pattern at row %d: expected %v, got %v",
				i, expected, qr.Modules[i][6])
		}
	}
}

func TestQRCodeTotalWidth(t *testing.T) {
	qr := NewQRCode("Test", ECLevelL)
	qr.BoxSize = 2.0
	qr.Border = 4

	expected := float64(qr.Size+qr.Border*2) * qr.BoxSize
	got := qr.TotalWidth()

	if got != expected {
		t.Errorf("Expected total width %f, got %f", expected, got)
	}
}

func TestQRCodeRenderPDF(t *testing.T) {
	qr := NewQRCode("Test", ECLevelL)

	pdf := qr.RenderPDF()

	if len(pdf) == 0 {
		t.Error("RenderPDF returned empty content")
	}

	// Check for expected PDF operators
	if !bytes.Contains(pdf, []byte("rg")) {
		t.Error("PDF should contain 'rg' (set fill color)")
	}

	if !bytes.Contains(pdf, []byte("cm")) {
		t.Error("PDF should contain 'cm' (coordinate transformation)")
	}

	if !bytes.Contains(pdf, []byte("re")) {
		t.Error("PDF should contain 're' (rectangle operator)")
	}

	if !bytes.Contains(pdf, []byte("f")) {
		t.Error("PDF should contain 'f' (fill operator)")
	}
}

func TestQRCodeCustomColor(t *testing.T) {
	qr := NewQRCode("Test", ECLevelL)
	qr.QRColor = [3]float64{0.5, 0.2, 0.8}

	pdf := qr.RenderPDF()

	// Check that the color is set
	if !bytes.Contains(pdf, []byte("0.5 0.2 0.8 rg")) {
		t.Error("PDF should contain custom fill color")
	}
}

func TestNewFancyQRCode(t *testing.T) {
	fqr := NewFancyQRCode("Hello", ECLevelM, nil)

	if fqr == nil {
		t.Fatal("NewFancyQRCode returned nil")
	}

	if fqr.QRCode == nil {
		t.Error("FancyQRCode should have embedded QRCode")
	}

	if fqr.CenterpieceCornerRadius != 0.2 {
		t.Errorf("Default corner radius should be 0.2, got %f", fqr.CenterpieceCornerRadius)
	}
}

func TestFancyQRCodeIsPositionPattern(t *testing.T) {
	fqr := NewFancyQRCode("Test", ECLevelL, nil)

	// Top-left finder pattern
	if !fqr.IsPositionPattern(0, 0) {
		t.Error("(0,0) should be in position pattern")
	}

	if !fqr.IsPositionPattern(3, 3) {
		t.Error("(3,3) should be in position pattern")
	}

	// Top-right finder pattern
	if !fqr.IsPositionPattern(0, fqr.Size-1) {
		t.Error("Top-right corner should be in position pattern")
	}

	// Bottom-left finder pattern
	if !fqr.IsPositionPattern(fqr.Size-1, 0) {
		t.Error("Bottom-left corner should be in position pattern")
	}

	// Center should not be in finder pattern (for small version)
	center := fqr.Size / 2
	if fqr.IsPositionPattern(center, center) {
		t.Error("Center should not be in finder pattern for version 1")
	}
}

func TestFancyQRCodeRenderPDF(t *testing.T) {
	fqr := NewFancyQRCode("Hello World", ECLevelM, nil)

	pdf := fqr.RenderPDF()

	if len(pdf) == 0 {
		t.Error("RenderPDF returned empty content")
	}

	// Should contain rounded square operations (Bezier curves)
	if !bytes.Contains(pdf, []byte("c")) {
		t.Error("Fancy QR should contain 'c' (curve operator)")
	}

	// Should contain stroke operations for position pattern borders
	if !bytes.Contains(pdf, []byte("S")) {
		t.Error("Fancy QR should contain 'S' (stroke operator)")
	}
}

func TestFancyQRCodeWithCenterpiece(t *testing.T) {
	centerpiece := &PdfContent{
		Box:  BoxConstraints{Width: 50, Height: 50},
		Data: []byte("BT /F1 12 Tf (Logo) Tj ET"),
	}

	fqr := NewFancyQRCode("Hello World", ECLevelH, centerpiece)

	pdf := fqr.RenderPDF()

	if len(pdf) == 0 {
		t.Error("RenderPDF returned empty content")
	}

	// Should contain clipping operators
	if !bytes.Contains(pdf, []byte("W")) {
		t.Error("Fancy QR with centerpiece should contain 'W' (clipping operator)")
	}

	// Should contain the centerpiece content
	if !bytes.Contains(pdf, []byte("Logo")) {
		t.Error("Fancy QR should contain centerpiece content")
	}
}

func TestRoundedSquare(t *testing.T) {
	result := roundedSquare(10, 20, 50, 5)

	if len(result) == 0 {
		t.Error("roundedSquare returned empty content")
	}

	// Should start with move
	if !bytes.Contains(result, []byte("m")) {
		t.Error("Rounded square should contain 'm' (move operator)")
	}

	// Should contain lines
	if !bytes.Contains(result, []byte("l")) {
		t.Error("Rounded square should contain 'l' (line operator)")
	}

	// Should contain Bezier curves for rounded corners
	if !bytes.Contains(result, []byte("c")) {
		t.Error("Rounded square should contain 'c' (curve operator)")
	}

	// Should close the path
	if !bytes.Contains(result, []byte("h")) {
		t.Error("Rounded square should contain 'h' (close path)")
	}
}

func TestDetermineVersion(t *testing.T) {
	tests := []struct {
		dataLen int
		ecLevel ErrorCorrectionLevel
		minVer  int
		maxVer  int
	}{
		{5, ECLevelL, 1, 1},
		{20, ECLevelL, 1, 2},
		{50, ECLevelL, 2, 4},
		{100, ECLevelL, 3, 6},
		{5, ECLevelH, 1, 2},
		{10, ECLevelH, 2, 3},
	}

	for _, tt := range tests {
		data := make([]byte, tt.dataLen)
		for i := range data {
			data[i] = 'A'
		}
		version := determineVersion(string(data), tt.ecLevel)
		if version < tt.minVer || version > tt.maxVer {
			t.Errorf("For data length %d with EC %d, expected version between %d-%d, got %d",
				tt.dataLen, tt.ecLevel, tt.minVer, tt.maxVer, version)
		}
	}
}

func TestErrorCorrectionLevels(t *testing.T) {
	data := "Test data for QR code"

	levels := []ErrorCorrectionLevel{ECLevelL, ECLevelM, ECLevelQ, ECLevelH}

	for _, level := range levels {
		qr := NewQRCode(data, level)
		if qr == nil {
			t.Errorf("NewQRCode with EC level %d returned nil", level)
		}
		if qr.ECLevel != level {
			t.Errorf("Expected EC level %d, got %d", level, qr.ECLevel)
		}
	}
}

func TestQRCodeDefaultValues(t *testing.T) {
	qr := NewQRCode("Test", ECLevelL)

	if qr.BoxSize != 1.0 {
		t.Errorf("Default BoxSize should be 1.0, got %f", qr.BoxSize)
	}

	if qr.Border != 4 {
		t.Errorf("Default Border should be 4, got %d", qr.Border)
	}

	if qr.QRColor != [3]float64{0, 0, 0} {
		t.Errorf("Default color should be black")
	}
}

func TestQRCodeAlignmentPatterns(t *testing.T) {
	// Version 2+ should have alignment patterns
	qr := NewQRCode("This is a longer string that needs version 2 or higher", ECLevelL)

	if qr.Version >= 2 {
		positions := qr.getAlignmentPatternPositions()
		if positions == nil {
			t.Error("Version 2+ should have alignment pattern positions")
		}
	}
}

func TestFancyQRCodeMeasureCenterpiece(t *testing.T) {
	fqr := NewFancyQRCode("Test", ECLevelL, nil)

	x, y, size := fqr.measureCenterpiece()

	expectedSize := 0.28 * float64(fqr.Size)
	if size != expectedSize {
		t.Errorf("Expected centerpiece size %f, got %f", expectedSize, size)
	}

	expectedX := (float64(fqr.Size) - size) / 2
	if x != expectedX {
		t.Errorf("Expected centerpiece x %f, got %f", expectedX, x)
	}

	if y != expectedX {
		t.Errorf("Expected centerpiece y to equal x for centered position")
	}
}

func BenchmarkNewQRCode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewQRCode("Hello World", ECLevelM)
	}
}

func BenchmarkQRCodeRenderPDF(b *testing.B) {
	qr := NewQRCode("Hello World", ECLevelM)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qr.RenderPDF()
	}
}

func BenchmarkFancyQRCodeRenderPDF(b *testing.B) {
	fqr := NewFancyQRCode("Hello World", ECLevelM, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fqr.RenderPDF()
	}
}
