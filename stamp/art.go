// Package stamp provides PDF stamping and signature appearance functionality.
// This file contains pre-defined stamp art content.
package stamp

import (
	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// StampArtContent contains a hardcoded stamp background that renders a stylized
// image of a stamp using PDF graphics operators.
// The stamp shows a silhouette figure with horizontal bars below it.
var StampArtContent = &RawContent{
	Box: BoxConstraints{Width: 100, Height: 100},
	Data: []byte(`
q 1 0 0 -1 0 100 cm
0.603922 0.345098 0.54902 rg
3.699 65.215 m 3.699 65.215 2.375 57.277 7.668 51.984 c 12.957 46.695 27.512
 49.34 39.418 41.402 c 39.418 41.402 31.48 40.078 32.801 33.465 c 34.125
 26.852 39.418 28.172 39.418 24.203 c 39.418 20.234 30.156 17.59 30.156
14.945 c 30.156 12.297 28.465 1.715 50 1.715 c 71.535 1.715 69.844 12.297
 69.844 14.945 c 69.844 17.59 60.582 20.234 60.582 24.203 c 60.582 28.172
 65.875 26.852 67.199 33.465 c 68.52 40.078 60.582 41.402 60.582 41.402
c 72.488 49.34 87.043 46.695 92.332 51.984 c 97.625 57.277 96.301 65.215
 96.301 65.215 c h f
3.801 68.734 92.398 7.391 re f
3.801 79.512 92.398 7.391 re f
3.801 90.289 92.398 7.391 re f
Q
`),
}

// BoxConstraints represents width and height constraints for content.
type BoxConstraints struct {
	Width  float64
	Height float64
}

// RawContent represents raw PDF content with its bounding box.
type RawContent struct {
	Box  BoxConstraints
	Data []byte
}

// Render returns the raw content data.
func (r *RawContent) Render() []byte {
	return r.Data
}

// GetDimensions returns the content dimensions.
func (r *RawContent) GetDimensions() (width, height float64) {
	return r.Box.Width, r.Box.Height
}

// CreateAppearanceStream creates a PDF form XObject from the raw content.
func (r *RawContent) CreateAppearanceStream() *generic.StreamObject {
	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XObject"))
	dict.Set("Subtype", generic.NameObject("Form"))
	dict.Set("BBox", generic.ArrayObject{
		generic.RealObject(0),
		generic.RealObject(0),
		generic.RealObject(r.Box.Width),
		generic.RealObject(r.Box.Height),
	})

	return generic.NewStream(dict, r.Data)
}

// StampWithBackground creates a stamp that includes the standard stamp art background
// with text overlay.
type StampWithBackground struct {
	Background *RawContent
	TextStamp  *TextStamp
}

// NewStampWithBackground creates a new stamp with the standard background art.
func NewStampWithBackground(lines []string, style *StampStyle) *StampWithBackground {
	if style == nil {
		style = DefaultStampStyle()
	}

	textStamp := NewTextStamp(lines, style)
	// Scale text stamp to fit within the background
	textStamp.Width = StampArtContent.Box.Width
	textStamp.Height = StampArtContent.Box.Height

	return &StampWithBackground{
		Background: StampArtContent,
		TextStamp:  textStamp,
	}
}

// Render renders the stamp with background to a PDF content stream.
func (s *StampWithBackground) Render() []byte {
	// First render the background, then overlay the text
	result := make([]byte, 0, len(s.Background.Data)+len(s.TextStamp.Render()))
	result = append(result, s.Background.Data...)
	result = append(result, s.TextStamp.Render()...)
	return result
}

// GetDimensions returns the stamp dimensions.
func (s *StampWithBackground) GetDimensions() (width, height float64) {
	return s.Background.Box.Width, s.Background.Box.Height
}

// CreateAppearanceStream creates a PDF appearance stream for the stamp with background.
func (s *StampWithBackground) CreateAppearanceStream() *generic.StreamObject {
	content := s.Render()

	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XObject"))
	dict.Set("Subtype", generic.NameObject("Form"))
	dict.Set("BBox", generic.ArrayObject{
		generic.RealObject(0),
		generic.RealObject(0),
		generic.RealObject(s.Background.Box.Width),
		generic.RealObject(s.Background.Box.Height),
	})

	// Resources
	resources := generic.NewDictionary()
	fonts := generic.NewDictionary()
	font := generic.NewDictionary()
	font.Set("Type", generic.NameObject("Font"))
	font.Set("Subtype", generic.NameObject("Type1"))
	font.Set("BaseFont", generic.NameObject(s.TextStamp.Style.FontName))
	fonts.Set("F1", font)
	resources.Set("Font", fonts)
	dict.Set("Resources", resources)

	return generic.NewStream(dict, content)
}
