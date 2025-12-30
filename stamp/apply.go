// Package stamp provides PDF stamping and signature appearance functionality.
// This file contains functions for applying stamps to PDF documents.
package stamp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/pdf/reader"
	"github.com/georgepadayatti/gopdf/pdf/writer"
)

// Stamper is an interface for objects that can be stamped onto a PDF page.
type Stamper interface {
	// CreateAppearanceStream creates the PDF appearance stream for this stamp.
	CreateAppearanceStream() *generic.StreamObject
	// GetDimensions returns the width and height of the stamp.
	GetDimensions() (width, height float64)
}

// ApplyOptions configures how a stamp is applied to a page.
type ApplyOptions struct {
	// WrapExistingContent wraps existing page content in q/Q to isolate graphics state.
	// Default is true.
	WrapExistingContent bool
}

// DefaultApplyOptions returns the default apply options.
func DefaultApplyOptions() *ApplyOptions {
	return &ApplyOptions{
		WrapExistingContent: true,
	}
}

// ApplyStamp applies a stamp to a page in the given incremental writer.
// Returns the page reference and the stamp dimensions.
func ApplyStamp(w *writer.IncrementalPdfFileWriter, stamp Stamper, pageNum int, x, y float64, opts *ApplyOptions) (generic.Reference, float64, float64, error) {
	if opts == nil {
		opts = DefaultApplyOptions()
	}

	// Create the stamp appearance stream
	appearance := stamp.CreateAppearanceStream()

	// Add the appearance as an object
	stampRef := w.AddObject(appearance)

	// Generate a unique resource name
	randBytes := make([]byte, 8)
	rand.Read(randBytes)
	resourceName := "/Stamp" + hex.EncodeToString(randBytes)

	// Create the stamp painting command
	width, height := stamp.GetDimensions()
	stampPaint := fmt.Sprintf("q 1 0 0 1 %f %f cm %s Do Q", x, y, resourceName)
	stampWrapperStream := generic.NewStream(nil, []byte(stampPaint))

	// Create resources for the stamp
	resources := generic.NewDictionary()
	xobjects := generic.NewDictionary()
	xobjects.Set(resourceName[1:], stampRef) // Remove leading /
	resources.Set("XObject", xobjects)

	// If wrapping existing content, add q/Q streams
	if opts.WrapExistingContent {
		// Add "q" at the beginning
		qStream := generic.NewStream(nil, []byte("q"))
		qRef := w.AddObject(qStream)
		if _, err := w.AddStreamToPage(pageNum, qRef, nil, true); err != nil {
			return generic.Reference{}, 0, 0, err
		}

		// Add "Q" after existing content
		bigQStream := generic.NewStream(nil, []byte("Q"))
		bigQRef := w.AddObject(bigQStream)
		if _, err := w.AddStreamToPage(pageNum, bigQRef, nil, false); err != nil {
			return generic.Reference{}, 0, 0, err
		}
	}

	// Add the stamp wrapper stream
	wrapperRef := w.AddObject(stampWrapperStream)
	pageRef, err := w.AddStreamToPage(pageNum, wrapperRef, resources, false)
	if err != nil {
		return generic.Reference{}, 0, 0, err
	}

	return pageRef, width, height, nil
}

// TextStampFile adds a text stamp to a PDF file and writes the result to output.
func TextStampFile(inputPath, outputPath string, lines []string, style *StampStyle, pageNum int, x, y float64) error {
	// Open input file
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Create reader
	r, err := reader.NewPdfFileReaderFromBytes(inputData)
	if err != nil {
		return fmt.Errorf("failed to parse PDF: %w", err)
	}

	// Create incremental writer
	w := writer.NewIncrementalPdfFileWriter(r)

	// Create and apply stamp
	stamp := NewTextStamp(lines, style)
	if _, _, _, err := ApplyStamp(w, stamp, pageNum, x, y, nil); err != nil {
		return fmt.Errorf("failed to apply stamp: %w", err)
	}

	// Write output
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	if err := w.Write(outFile); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	return nil
}

// QRStampFile adds a QR stamp to a PDF file and writes the result to output.
func QRStampFile(inputPath, outputPath string, url string, lines []string, style *QRStampStyle, pageNum int, x, y float64) error {
	// Open input file
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Create reader
	r, err := reader.NewPdfFileReaderFromBytes(inputData)
	if err != nil {
		return fmt.Errorf("failed to parse PDF: %w", err)
	}

	// Create incremental writer
	w := writer.NewIncrementalPdfFileWriter(r)

	// Create and apply stamp
	stamp := NewQRTextStamp(url, lines, style)
	if _, _, _, err := ApplyStamp(w, stamp, pageNum, x, y, nil); err != nil {
		return fmt.Errorf("failed to apply stamp: %w", err)
	}

	// Write output
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	if err := w.Write(outFile); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	return nil
}

// StampReader applies a stamp using a reader and writer for more control.
func StampReader(r *reader.PdfFileReader, stamp Stamper, pageNum int, x, y float64, opts *ApplyOptions) (*writer.IncrementalPdfFileWriter, error) {
	w := writer.NewIncrementalPdfFileWriter(r)

	if _, _, _, err := ApplyStamp(w, stamp, pageNum, x, y, opts); err != nil {
		return nil, err
	}

	return w, nil
}

// StampAndWrite stamps a PDF and writes to the given writer.
func StampAndWrite(inputData []byte, stamp Stamper, pageNum int, x, y float64, output io.Writer) error {
	r, err := reader.NewPdfFileReaderFromBytes(inputData)
	if err != nil {
		return fmt.Errorf("failed to parse PDF: %w", err)
	}

	w, err := StampReader(r, stamp, pageNum, x, y, nil)
	if err != nil {
		return fmt.Errorf("failed to apply stamp: %w", err)
	}

	if err := w.Write(output); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	return nil
}

// StaticStampStyle represents a style for a static content stamp (background only).
type StaticStampStyle struct {
	// Background is the content to use as the stamp background.
	Background *RawContent

	// BorderWidth is the border width around the stamp.
	BorderWidth float64

	// BorderColor is the border color (RGB, 0-1 range).
	BorderColor [3]float64

	// BackgroundOpacity is the opacity of the background (0-1).
	BackgroundOpacity float64
}

// DefaultStaticStampStyle returns the default static stamp style.
func DefaultStaticStampStyle() *StaticStampStyle {
	return &StaticStampStyle{
		Background:        nil,
		BorderWidth:       0,
		BorderColor:       [3]float64{0, 0, 0},
		BackgroundOpacity: 1.0,
	}
}

// StaticContentStamp is a stamp that only renders static background content.
type StaticContentStamp struct {
	Style  *StaticStampStyle
	Width  float64
	Height float64
}

// NewStaticContentStamp creates a new static content stamp.
// The box constraints must have both width and height defined.
func NewStaticContentStamp(style *StaticStampStyle, width, height float64) (*StaticContentStamp, error) {
	if style == nil {
		style = DefaultStaticStampStyle()
	}

	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("static content stamp requires positive width and height")
	}

	return &StaticContentStamp{
		Style:  style,
		Width:  width,
		Height: height,
	}, nil
}

// NewStaticStampFromBackground creates a static stamp using the given background content.
func NewStaticStampFromBackground(background *RawContent, opacity float64) (*StaticContentStamp, error) {
	if background == nil {
		return nil, fmt.Errorf("background cannot be nil")
	}

	style := &StaticStampStyle{
		Background:        background,
		BackgroundOpacity: opacity,
	}

	return NewStaticContentStamp(style, background.Box.Width, background.Box.Height)
}

// Render renders the static stamp to PDF content.
func (s *StaticContentStamp) Render() []byte {
	if s.Style.Background == nil {
		return nil
	}

	// Just return the background content
	return s.Style.Background.Render()
}

// GetDimensions returns the stamp dimensions.
func (s *StaticContentStamp) GetDimensions() (width, height float64) {
	return s.Width, s.Height
}

// CreateAppearanceStream creates a PDF appearance stream for the static stamp.
func (s *StaticContentStamp) CreateAppearanceStream() *generic.StreamObject {
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

	// Add graphics state for opacity if not 1.0
	if s.Style.BackgroundOpacity < 1.0 {
		resources := generic.NewDictionary()
		extGState := generic.NewDictionary()
		gs := generic.NewDictionary()
		gs.Set("CA", generic.RealObject(s.Style.BackgroundOpacity))
		gs.Set("ca", generic.RealObject(s.Style.BackgroundOpacity))
		extGState.Set("GS0", gs)
		resources.Set("ExtGState", extGState)
		dict.Set("Resources", resources)
	}

	return generic.NewStream(dict, content)
}
