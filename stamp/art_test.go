package stamp

import (
	"bytes"
	"testing"
)

func TestStampArtContent(t *testing.T) {
	// Verify the stamp art content exists and has valid dimensions
	if StampArtContent == nil {
		t.Fatal("StampArtContent should not be nil")
	}

	if StampArtContent.Box.Width != 100 {
		t.Errorf("Expected width 100, got %f", StampArtContent.Box.Width)
	}

	if StampArtContent.Box.Height != 100 {
		t.Errorf("Expected height 100, got %f", StampArtContent.Box.Height)
	}

	if len(StampArtContent.Data) == 0 {
		t.Error("StampArtContent.Data should not be empty")
	}
}

func TestRawContentRender(t *testing.T) {
	content := &RawContent{
		Box:  BoxConstraints{Width: 50, Height: 50},
		Data: []byte("q 1 0 0 1 0 0 cm Q"),
	}

	rendered := content.Render()
	if !bytes.Equal(rendered, content.Data) {
		t.Error("Render should return the raw data unchanged")
	}
}

func TestRawContentGetDimensions(t *testing.T) {
	content := &RawContent{
		Box:  BoxConstraints{Width: 75, Height: 100},
		Data: []byte("test"),
	}

	w, h := content.GetDimensions()
	if w != 75 {
		t.Errorf("Expected width 75, got %f", w)
	}
	if h != 100 {
		t.Errorf("Expected height 100, got %f", h)
	}
}

func TestRawContentCreateAppearanceStream(t *testing.T) {
	content := &RawContent{
		Box:  BoxConstraints{Width: 100, Height: 100},
		Data: []byte("q 0 0 0 rg 0 0 100 100 re f Q"),
	}

	stream := content.CreateAppearanceStream()
	if stream == nil {
		t.Fatal("CreateAppearanceStream should not return nil")
	}

	// Check that the stream dictionary has required keys
	if stream.Dictionary.GetName("Type") != "XObject" {
		t.Error("Stream should have Type /XObject")
	}

	if stream.Dictionary.GetName("Subtype") != "Form" {
		t.Error("Stream should have Subtype /Form")
	}

	bbox := stream.Dictionary.GetArray("BBox")
	if bbox == nil || len(bbox) != 4 {
		t.Error("Stream should have BBox array with 4 elements")
	}
}

func TestNewStampWithBackground(t *testing.T) {
	lines := []string{"Test Line 1", "Test Line 2"}
	stamp := NewStampWithBackground(lines, nil)

	if stamp == nil {
		t.Fatal("NewStampWithBackground should not return nil")
	}

	if stamp.Background != StampArtContent {
		t.Error("Background should be StampArtContent")
	}

	if stamp.TextStamp == nil {
		t.Error("TextStamp should not be nil")
	}

	if len(stamp.TextStamp.Lines) != 2 {
		t.Errorf("Expected 2 lines, got %d", len(stamp.TextStamp.Lines))
	}
}

func TestStampWithBackgroundRender(t *testing.T) {
	lines := []string{"Hello", "World"}
	stamp := NewStampWithBackground(lines, nil)

	rendered := stamp.Render()
	if len(rendered) == 0 {
		t.Error("Render should return non-empty content")
	}

	// Check that the rendered content contains the background
	if !bytes.Contains(rendered, []byte("0.603922")) {
		t.Error("Rendered content should contain background color")
	}

	// Check that it contains text operations
	if !bytes.Contains(rendered, []byte("BT")) {
		t.Error("Rendered content should contain text begin operator")
	}
}

func TestStampWithBackgroundGetDimensions(t *testing.T) {
	stamp := NewStampWithBackground([]string{"Test"}, nil)

	w, h := stamp.GetDimensions()
	if w != 100 {
		t.Errorf("Expected width 100, got %f", w)
	}
	if h != 100 {
		t.Errorf("Expected height 100, got %f", h)
	}
}

func TestStampWithBackgroundCreateAppearanceStream(t *testing.T) {
	stamp := NewStampWithBackground([]string{"Test"}, nil)

	stream := stamp.CreateAppearanceStream()
	if stream == nil {
		t.Fatal("CreateAppearanceStream should not return nil")
	}

	// Check stream properties
	if stream.Dictionary.GetName("Type") != "XObject" {
		t.Error("Stream should have Type /XObject")
	}

	// Check that resources include font
	resources := stream.Dictionary.GetDict("Resources")
	if resources == nil {
		t.Error("Stream should have Resources")
	}

	fonts := resources.GetDict("Font")
	if fonts == nil {
		t.Error("Resources should include Font dictionary")
	}
}

func TestStampWithBackgroundCustomStyle(t *testing.T) {
	style := DefaultStampStyle()
	style.FontSize = 14
	style.FontName = "Times-Roman"

	stamp := NewStampWithBackground([]string{"Custom"}, style)

	if stamp.TextStamp.Style.FontSize != 14 {
		t.Errorf("Expected font size 14, got %f", stamp.TextStamp.Style.FontSize)
	}

	if stamp.TextStamp.Style.FontName != "Times-Roman" {
		t.Errorf("Expected font Times-Roman, got %s", stamp.TextStamp.Style.FontName)
	}
}
