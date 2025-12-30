// Package main demonstrates adding watermarks to PDF documents.
//
// This example shows:
//   - Creating text watermarks
//   - Customizing watermark appearance
//   - Applying watermarks to PDF pages
package main

import (
	"bytes"
	"flag"
	"fmt"
	"image/color"
	"os"
	"path/filepath"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/pdf/reader"
	"github.com/georgepadayatti/gopdf/pdf/writer"
	"github.com/georgepadayatti/gopdf/stamp"
)

func main() {
	// Parse command line flags
	inputFile := flag.String("input", "", "Input PDF file")
	outputFile := flag.String("output", "", "Output PDF file")
	text := flag.String("text", "CONFIDENTIAL", "Watermark text")
	rotation := flag.Float64("rotation", -45, "Rotation angle in degrees")
	opacity := flag.Float64("opacity", 0.15, "Opacity (0.0 to 1.0)")
	fontSize := flag.Float64("fontsize", 72, "Font size in points")
	colorR := flag.Int("color-r", 128, "Text color red (0-255)")
	colorG := flag.Int("color-g", 128, "Text color green (0-255)")
	colorB := flag.Int("color-b", 128, "Text color blue (0-255)")
	allPages := flag.Bool("all-pages", true, "Apply to all pages")
	pageNum := flag.Int("page", 0, "Specific page number (0-indexed)")
	flag.Parse()

	fmt.Println("PDF Watermark Example")
	fmt.Println("=====================")
	fmt.Println()

	// Use default paths if not specified
	if *inputFile == "" {
		testdataDir := getTestdataDir()
		*inputFile = filepath.Join(testdataDir, "terms.pdf")
	}

	if *outputFile == "" {
		*outputFile = "watermarked_output.pdf"
	}

	// Read input PDF
	pdfData, err := os.ReadFile(*inputFile)
	if err != nil {
		fmt.Printf("Error reading PDF: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Input: %s (%d bytes)\n", *inputFile, len(pdfData))

	// Parse PDF
	pdfReader, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		fmt.Printf("Error parsing PDF: %v\n", err)
		os.Exit(1)
	}

	pageCount := pdfReader.GetPageCount()
	fmt.Printf("Pages: %d\n", pageCount)

	// Create watermark
	watermark := stamp.NewWatermark(*text)
	watermark.Rotation = *rotation
	watermark.Opacity = *opacity
	watermark.Style = &stamp.StampStyle{
		FontSize:  *fontSize,
		FontName:  "Helvetica-Bold",
		TextColor: color.RGBA{uint8(*colorR), uint8(*colorG), uint8(*colorB), 255},
	}

	fmt.Printf("\nWatermark: \"%s\"\n", *text)
	fmt.Printf("  Rotation: %.1f degrees\n", *rotation)
	fmt.Printf("  Opacity: %.2f\n", *opacity)
	fmt.Printf("  Font Size: %.1f pt\n", *fontSize)
	fmt.Printf("  Color: RGB(%d, %d, %d)\n", *colorR, *colorG, *colorB)

	// Create incremental writer
	incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

	// Determine which pages to watermark
	var pagesToWatermark []int
	if *allPages {
		for i := 0; i < pageCount; i++ {
			pagesToWatermark = append(pagesToWatermark, i)
		}
	} else {
		if *pageNum >= 0 && *pageNum < pageCount {
			pagesToWatermark = []int{*pageNum}
		} else {
			fmt.Printf("Error: page %d does not exist (document has %d pages)\n", *pageNum, pageCount)
			os.Exit(1)
		}
	}

	// Apply watermark to pages
	fmt.Printf("\nApplying watermark to %d page(s)...\n", len(pagesToWatermark))

	for _, pageIdx := range pagesToWatermark {
		err := addWatermarkToPage(incWriter, pdfReader, watermark, pageIdx)
		if err != nil {
			fmt.Printf("Error watermarking page %d: %v\n", pageIdx, err)
			continue
		}
		fmt.Printf("  Page %d: watermarked\n", pageIdx+1)
	}

	// Write output
	var buf bytes.Buffer
	if err := incWriter.Write(&buf); err != nil {
		fmt.Printf("Error writing PDF: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outputFile, buf.Bytes(), 0644); err != nil {
		fmt.Printf("Error saving PDF: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nOutput: %s (%d bytes)\n", *outputFile, buf.Len())
	fmt.Println("\nWatermark added successfully!")
}

// addWatermarkToPage adds a watermark to a specific page.
func addWatermarkToPage(incWriter *writer.IncrementalPdfFileWriter, pdfReader *reader.PdfFileReader, watermark *stamp.Watermark, pageNum int) error {
	pageWidth, pageHeight, err := getPageDimensions(pdfReader, pageNum)
	if err != nil {
		return fmt.Errorf("failed to get page: %w", err)
	}

	stamper := &watermarkStamper{
		watermark: watermark,
		width:     pageWidth,
		height:    pageHeight,
	}

	if _, _, _, err := stamp.ApplyStampWithPageTransform(incWriter, pdfReader, stamper, pageNum, 0, 0, nil); err != nil {
		return fmt.Errorf("failed to add watermark to page: %w", err)
	}

	return nil
}

// getTestdataDir finds the testdata directory.
func getTestdataDir() string {
	// Try from project root first
	if _, err := os.Stat("testdata"); err == nil {
		return "testdata"
	}
	// Try from examples/watermark directory
	if _, err := os.Stat("../../testdata"); err == nil {
		return "../../testdata"
	}
	// Try from examples directory
	if _, err := os.Stat("../testdata"); err == nil {
		return "../testdata"
	}
	return "testdata"
}

func getPageDimensions(pdfReader *reader.PdfFileReader, pageNum int) (width, height float64, err error) {
	pageDict, err := pdfReader.GetPage(pageNum)
	if err != nil {
		return 0, 0, err
	}

	mediaBoxObj := pageDict.Get("MediaBox")
	if arr, ok := mediaBoxObj.(generic.ArrayObject); ok && len(arr) >= 4 {
		llx := getFloat(arr[0])
		lly := getFloat(arr[1])
		urx := getFloat(arr[2])
		ury := getFloat(arr[3])
		return urx - llx, ury - lly, nil
	}

	return 612, 792, nil
}

// getFloat extracts a float64 from a PDF object.
func getFloat(obj generic.PdfObject) float64 {
	switch v := obj.(type) {
	case generic.IntegerObject:
		return float64(v)
	case generic.RealObject:
		return float64(v)
	default:
		return 0
	}
}

type watermarkStamper struct {
	watermark *stamp.Watermark
	width     float64
	height    float64
}

func (w *watermarkStamper) CreateAppearanceStream() *generic.StreamObject {
	content := w.watermark.Render(w.width, w.height)

	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XObject"))
	dict.Set("Subtype", generic.NameObject("Form"))
	dict.Set("BBox", generic.ArrayObject{
		generic.RealObject(0),
		generic.RealObject(0),
		generic.RealObject(w.width),
		generic.RealObject(w.height),
	})

	resources := generic.NewDictionary()
	extGState := generic.NewDictionary()
	extGState.Set("GS1", w.watermark.CreateExtGState())
	resources.Set("ExtGState", extGState)

	fonts := generic.NewDictionary()
	font := generic.NewDictionary()
	font.Set("Type", generic.NameObject("Font"))
	font.Set("Subtype", generic.NameObject("Type1"))
	font.Set("BaseFont", generic.NameObject(w.watermark.Style.FontName))
	fonts.Set("F1", font)
	resources.Set("Font", fonts)

	dict.Set("Resources", resources)

	return generic.NewStream(dict, content)
}

func (w *watermarkStamper) GetDimensions() (width, height float64) {
	return w.width, w.height
}
