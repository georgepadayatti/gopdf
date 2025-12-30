// Package main demonstrates creating visual signatures and stamps.
//
// This example shows:
//   - Creating text stamps
//   - Creating visual signatures with images
//   - Creating QR code stamps
//   - Applying stamps to PDF pages
package main

import (
	"bytes"
	"flag"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/pdf/reader"
	"github.com/georgepadayatti/gopdf/pdf/writer"
	"github.com/georgepadayatti/gopdf/stamp"
)

func main() {
	// Parse command line flags
	action := flag.String("action", "demo", "Action: demo, text, visual, qr")
	inputFile := flag.String("input", "", "Input PDF file")
	outputFile := flag.String("output", "", "Output PDF file")
	signerName := flag.String("name", "John Doe", "Signer name")
	reason := flag.String("reason", "Document approval", "Signing reason")
	location := flag.String("location", "Berlin, Germany", "Signing location")
	imagePath := flag.String("image", "", "Signature image path")
	x := flag.Float64("x", 50, "X position in points")
	y := flag.Float64("y", 50, "Y position in points")
	width := flag.Float64("width", 200, "Stamp width in points")
	height := flag.Float64("height", 70, "Stamp height in points")
	pageNum := flag.Int("page", 0, "Page number (0-indexed)")
	flag.Parse()

	fmt.Println("Visual Signature & Stamp Example")
	fmt.Println("=================================")
	fmt.Println()

	var err error
	switch *action {
	case "demo":
		err = runDemo()
	case "text":
		err = runTextStamp(*inputFile, *outputFile, *signerName, *reason, *location, *pageNum, *x, *y)
	case "visual":
		err = runVisualSignature(*inputFile, *outputFile, *signerName, *reason, *location, *imagePath, *pageNum, *x, *y, *width, *height)
	case "qr":
		err = runQRStamp(*inputFile, *outputFile, *pageNum, *x, *y)
	default:
		fmt.Printf("Unknown action: %s\n", *action)
		fmt.Println("Available actions: demo, text, visual, qr")
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

// runDemo runs all stamp demonstrations.
func runDemo() error {
	fmt.Println("Running visual signature demonstrations...")
	fmt.Println()

	testdataDir := getTestdataDir()
	inputPath := filepath.Join(testdataDir, "terms.pdf")

	// Check if input exists
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return fmt.Errorf("test PDF not found at %s", inputPath)
	}

	// Demo 1: Text Stamp
	fmt.Println("=== Demo 1: Text Stamp ===")
	if err := runTextStamp(inputPath, "demo_text_stamp.pdf", "John Doe", "Document Review", "Berlin", 0, 400, 700); err != nil {
		return fmt.Errorf("text stamp demo failed: %w", err)
	}

	// Demo 2: Visual Signature (with image)
	fmt.Println("\n=== Demo 2: Visual Signature ===")
	signatureImage := filepath.Join(getAssetsDir(), "signature_sample.png")
	if _, err := os.Stat(signatureImage); os.IsNotExist(err) {
		signatureImage = ""
	}
	if err := runVisualSignature(inputPath, "demo_visual_signature.pdf", "Jane Smith", "Contract Approval", "Munich", signatureImage, 0, 50, 50, 250, 80); err != nil {
		return fmt.Errorf("visual signature demo failed: %w", err)
	}

	// Demo 3: QR Code Stamp
	fmt.Println("\n=== Demo 3: QR Code Stamp ===")
	if err := runQRStamp(inputPath, "demo_qr_stamp.pdf", 0, 450, 50); err != nil {
		return fmt.Errorf("QR stamp demo failed: %w", err)
	}

	fmt.Println("\nAll demos completed successfully!")
	return nil
}

// runTextStamp adds a text stamp to a PDF.
func runTextStamp(inputPath, outputPath, name, reason, location string, pageNum int, x, y float64) error {
	if inputPath == "" {
		inputPath = filepath.Join(getTestdataDir(), "terms.pdf")
	}
	if outputPath == "" {
		outputPath = "text_stamped.pdf"
	}

	// Create styled text stamp
	style := &stamp.StampStyle{
		BackgroundColor: color.RGBA{255, 255, 220, 255}, // Light yellow
		BorderColor:     color.RGBA{0, 0, 128, 255},     // Navy blue
		BorderWidth:     1.5,
		TextColor:       color.RGBA{0, 0, 128, 255}, // Navy blue
		FontSize:        10,
		FontName:        "Helvetica",
		Padding:         8,
	}

	lines := []string{
		"APPROVED",
		fmt.Sprintf("By: %s", name),
		fmt.Sprintf("Reason: %s", reason),
		fmt.Sprintf("Location: %s", location),
		fmt.Sprintf("Date: %s", time.Now().Format("2006-01-02 15:04")),
	}

	fmt.Printf("Input: %s\n", inputPath)
	fmt.Printf("Adding text stamp at (%.0f, %.0f)\n", x, y)

	// Read PDF
	pdfData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read PDF: %w", err)
	}

	pdfReader, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		return fmt.Errorf("failed to parse PDF: %w", err)
	}

	// Create incremental writer
	incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

	stamper := stamp.NewTextStamp(lines, style)
	if _, _, _, err := stamp.ApplyStampWithPageTransform(incWriter, pdfReader, stamper, pageNum, x, y, nil); err != nil {
		return fmt.Errorf("failed to apply stamp: %w", err)
	}

	// Write output
	var buf bytes.Buffer
	if err := incWriter.Write(&buf); err != nil {
		return fmt.Errorf("failed to write PDF: %w", err)
	}

	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to save PDF: %w", err)
	}

	fmt.Printf("Output: %s\n", outputPath)
	return nil
}

// runVisualSignature adds a visual signature to a PDF.
func runVisualSignature(inputPath, outputPath, name, reason, location, imagePath string, pageNum int, x, y, width, height float64) error {
	if inputPath == "" {
		inputPath = filepath.Join(getTestdataDir(), "terms.pdf")
	}
	if outputPath == "" {
		outputPath = "visual_signed.pdf"
	}
	if imagePath == "" {
		defaultSignature := filepath.Join(getAssetsDir(), "signature_sample.png")
		if _, err := os.Stat(defaultSignature); err == nil {
			imagePath = defaultSignature
		}
	}

	// Read PDF
	pdfData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read PDF: %w", err)
	}

	pdfReader, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		return fmt.Errorf("failed to parse PDF: %w", err)
	}

	fmt.Printf("Input: %s\n", inputPath)

	// Create visual signature configuration
	config := stamp.DefaultVisualSignatureConfig()
	config.SignerName = name
	config.Reason = reason
	config.Location = location
	config.SigningTime = time.Now()
	config.ShowSignerName = true
	config.ShowDate = true
	config.ShowReason = true
	config.ShowLocation = true
	config.BorderWidth = 1
	config.BorderColor = color.RGBA{0, 0, 0, 255}

	// Load image if provided
	if imagePath != "" {
		imageData, err := os.ReadFile(imagePath)
		if err != nil {
			fmt.Printf("Warning: could not load image %s: %v\n", imagePath, err)
		} else {
			config.Image = imageData
			config.ImagePosition = stamp.ImageTextPositionLeft
			config.ImageRatio = 0.35
			fmt.Printf("Using signature image: %s\n", imagePath)
		}
	}

	// Create visual signature
	vs, err := stamp.NewVisualSignature(width, height, config)
	if err != nil {
		return fmt.Errorf("failed to create visual signature: %w", err)
	}

	fmt.Printf("Adding visual signature at (%.0f, %.0f), size: %.0fx%.0f\n", x, y, width, height)

	// Create incremental writer
	incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

	appearance, extraStreams, err := vs.CreateAppearanceStream()
	if err != nil {
		return fmt.Errorf("failed to create appearance stream: %w", err)
	}

	if vs.HasImage() && len(extraStreams) > 0 {
		resources := appearance.Dictionary.GetDict("Resources")
		if resources == nil {
			resources = generic.NewDictionary()
			appearance.Dictionary.Set("Resources", resources)
		}
		xobjects := resources.GetDict("XObject")
		if xobjects == nil {
			xobjects = generic.NewDictionary()
			resources.Set("XObject", xobjects)
		}

		imageStream := extraStreams[0]
		if len(extraStreams) > 1 {
			alphaRef := incWriter.AddObject(extraStreams[1])
			imageStream.Dictionary.Set("SMask", alphaRef)
		}
		imageRef := incWriter.AddObject(imageStream)
		xobjects.Set("Im1", imageRef)
	}

	// Apply stamp
	stamper := &appearanceStamper{stream: appearance, width: vs.Width, height: vs.Height}
	if _, _, _, err := stamp.ApplyStampWithPageTransform(incWriter, pdfReader, stamper, pageNum, x, y, nil); err != nil {
		return fmt.Errorf("failed to apply stamp: %w", err)
	}

	// Write output
	var buf bytes.Buffer
	if err := incWriter.Write(&buf); err != nil {
		return fmt.Errorf("failed to write PDF: %w", err)
	}

	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to save PDF: %w", err)
	}

	fmt.Printf("Output: %s\n", outputPath)
	return nil
}

// runQRStamp adds a QR code stamp to a PDF.
func runQRStamp(inputPath, outputPath string, pageNum int, x, y float64) error {
	if inputPath == "" {
		inputPath = filepath.Join(getTestdataDir(), "terms.pdf")
	}
	if outputPath == "" {
		outputPath = "qr_stamped.pdf"
	}

	// QR code data
	url := "https://verify.example.com/doc/ABC123456"
	lines := []string{
		"Scan to verify",
		"Document ID: ABC123456",
		fmt.Sprintf("Generated: %s", time.Now().Format("2006-01-02")),
	}

	// Create QR stamp style
	style := stamp.DefaultQRStampStyle()
	style.QRPosition = stamp.QRPositionLeftOfText
	style.QRSize = 50
	style.InnerSeparation = 8
	style.BorderWidth = 1
	style.BorderColor = [3]float64{0, 0, 0}

	fmt.Printf("Input: %s\n", inputPath)
	fmt.Printf("Adding QR stamp at (%.0f, %.0f)\n", x, y)
	fmt.Printf("QR URL: %s\n", url)

	// Read PDF
	pdfData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read PDF: %w", err)
	}

	pdfReader, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		return fmt.Errorf("failed to parse PDF: %w", err)
	}

	// Create incremental writer
	incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

	stamper := stamp.NewQRTextStamp(url, lines, style)
	if _, _, _, err := stamp.ApplyStampWithPageTransform(incWriter, pdfReader, stamper, pageNum, x, y, nil); err != nil {
		return fmt.Errorf("failed to apply stamp: %w", err)
	}

	// Write output
	var buf bytes.Buffer
	if err := incWriter.Write(&buf); err != nil {
		return fmt.Errorf("failed to write PDF: %w", err)
	}

	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to save PDF: %w", err)
	}

	fmt.Printf("Output: %s\n", outputPath)
	return nil
}

type appearanceStamper struct {
	stream *generic.StreamObject
	width  float64
	height float64
}

func (a *appearanceStamper) CreateAppearanceStream() *generic.StreamObject {
	return a.stream
}

func (a *appearanceStamper) GetDimensions() (width, height float64) {
	return a.width, a.height
}

// getTestdataDir finds the testdata directory.
func getTestdataDir() string {
	if _, err := os.Stat("testdata"); err == nil {
		return "testdata"
	}
	if _, err := os.Stat("../../testdata"); err == nil {
		return "../../testdata"
	}
	if _, err := os.Stat("../testdata"); err == nil {
		return "../testdata"
	}
	return "testdata"
}

// getAssetsDir finds the example assets directory.
func getAssetsDir() string {
	if _, err := os.Stat("examples/assets"); err == nil {
		return "examples/assets"
	}
	if _, err := os.Stat("assets"); err == nil {
		return "assets"
	}
	if _, err := os.Stat("../assets"); err == nil {
		return "../assets"
	}
	return "assets"
}
