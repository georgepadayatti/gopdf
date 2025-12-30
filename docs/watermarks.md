# PDF Watermarks

This guide covers adding watermarks to PDF documents using gopdf.

Disclaimer: This is a fun experiment; use at your peril. It is not intended for production use.

## Table of Contents

- [Overview](#overview)
- [Text Watermarks](#text-watermarks)
- [Watermark Styling](#watermark-styling)
- [Applying Watermarks](#applying-watermarks)
- [Multi-Page Watermarks](#multi-page-watermarks)
- [Image Watermarks](#image-watermarks)

## Overview

Watermarks are semi-transparent overlays added to PDF pages. Common uses include:

- Marking documents as CONFIDENTIAL, DRAFT, or SAMPLE
- Adding branding or logos
- Indicating document status
- Copyright protection

## Text Watermarks

### Creating a Basic Watermark

```go
import "github.com/georgepadayatti/gopdf/stamp"

// Create a simple watermark
watermark := stamp.NewWatermark("CONFIDENTIAL")

// Default settings:
// - 48pt font size
// - Light gray color (200, 200, 200)
// - -45 degree rotation (diagonal)
// - 50% opacity
```

### Watermark Properties

```go
// Create watermark with custom settings
watermark := stamp.NewWatermark("DRAFT")

// Adjust rotation (degrees)
watermark.Rotation = -30  // Less steep diagonal

// Adjust opacity (0.0 to 1.0)
watermark.Opacity = 0.2   // More subtle

// Customize style
watermark.Style.FontSize = 72    // Larger text
watermark.Style.FontName = "Helvetica-Bold"
watermark.Style.TextColor = color.RGBA{255, 0, 0, 128}  // Red, semi-transparent
```

## Watermark Styling

### StampStyle Configuration

```go
import (
    "image/color"
    "github.com/georgepadayatti/gopdf/stamp"
)

// Create custom style
style := &stamp.StampStyle{
    BackgroundColor: color.RGBA{0, 0, 0, 0},      // Transparent background
    BorderColor:     color.RGBA{0, 0, 0, 0},      // No border
    BorderWidth:     0,
    TextColor:       color.RGBA{128, 128, 128, 255}, // Gray text
    FontSize:        60,
    FontName:        "Helvetica",
    Padding:         0,
}

// Apply to watermark
watermark := stamp.NewWatermark("SAMPLE")
watermark.Style = style
```

### Available Fonts

Standard PDF fonts that work without embedding:

| Font Name | Description |
|-----------|-------------|
| Helvetica | Sans-serif |
| Helvetica-Bold | Bold sans-serif |
| Times-Roman | Serif |
| Times-Bold | Bold serif |
| Courier | Monospace |
| Courier-Bold | Bold monospace |

## Applying Watermarks

### Apply to Single Page

To apply a watermark, create a stamper that implements the `Stamper` interface and use `ApplyStampWithPageTransform`:

```go
import (
    "bytes"
    "os"

    "github.com/georgepadayatti/gopdf/pdf/generic"
    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/pdf/writer"
    "github.com/georgepadayatti/gopdf/stamp"
)

// watermarkStamper wraps a Watermark to implement the Stamper interface
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

    // Add resources for transparency and font
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

func addWatermarkToPage(inputPath, outputPath string, pageNum int) error {
    // Read PDF
    pdfData, _ := os.ReadFile(inputPath)
    pdfReader, _ := reader.NewPdfFileReaderFromBytes(pdfData)

    // Create watermark
    watermark := stamp.NewWatermark("CONFIDENTIAL")
    watermark.Opacity = 0.3
    watermark.Style.FontSize = 60

    // Create incremental writer
    incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

    // Get page dimensions
    pageWidth, pageHeight := getPageDimensions(pdfReader, pageNum)

    // Create stamper
    stamper := &watermarkStamper{
        watermark: watermark,
        width:     pageWidth,
        height:    pageHeight,
    }

    // Apply watermark at origin (0, 0) - it renders centered
    if _, _, _, err := stamp.ApplyStampWithPageTransform(incWriter, pdfReader, stamper, pageNum, 0, 0, nil); err != nil {
        return err
    }

    // Write output
    var buf bytes.Buffer
    if err := incWriter.Write(&buf); err != nil {
        return err
    }
    return os.WriteFile(outputPath, buf.Bytes(), 0644)
}

// Helper to get page dimensions from MediaBox
func getPageDimensions(r *reader.PdfFileReader, pageNum int) (float64, float64) {
    page, err := r.GetPage(pageNum)
    if err != nil {
        return 612, 792 // Default letter size
    }
    if arr, ok := page.Get("MediaBox").(generic.ArrayObject); ok && len(arr) >= 4 {
        llx := toFloat(arr[0])
        lly := toFloat(arr[1])
        urx := toFloat(arr[2])
        ury := toFloat(arr[3])
        return urx - llx, ury - lly
    }
    return 612, 792
}

func toFloat(obj generic.PdfObject) float64 {
    switch v := obj.(type) {
    case generic.IntegerObject:
        return float64(v)
    case generic.RealObject:
        return float64(v)
    }
    return 0
}
```

### Watermark Position

```go
// Watermarks are automatically centered on the page
// The rotation is applied around the center point

// For diagonal watermark (default)
watermark.Rotation = -45  // Bottom-left to top-right

// For horizontal watermark
watermark.Rotation = 0

// For vertical watermark
watermark.Rotation = 90
```

## Multi-Page Watermarks

### Apply to All Pages

```go
func addWatermarkToAllPages(inputPath, outputPath string) error {
    pdfData, _ := os.ReadFile(inputPath)
    pdfReader, _ := reader.NewPdfFileReaderFromBytes(pdfData)

    // Create watermark
    watermark := stamp.NewWatermark("DRAFT")
    watermark.Opacity = 0.2

    // Create incremental writer
    incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

    // Apply to each page
    pageCount := pdfReader.GetPageCount()
    for i := 0; i < pageCount; i++ {
        // Get page dimensions
        pageWidth, pageHeight := getPageDimensions(pdfReader, i)

        // Create stamper for this page
        stamper := &watermarkStamper{
            watermark: watermark,
            width:     pageWidth,
            height:    pageHeight,
        }

        // Apply watermark
        if _, _, _, err := stamp.ApplyStampWithPageTransform(incWriter, pdfReader, stamper, i, 0, 0, nil); err != nil {
            return err
        }
    }

    // Write output
    var buf bytes.Buffer
    if err := incWriter.Write(&buf); err != nil {
        return err
    }
    return os.WriteFile(outputPath, buf.Bytes(), 0644)
}
```

### Selective Page Watermarking

```go
// Apply watermark to specific pages
pages := []int{0, 2, 4}  // First, third, and fifth pages

for _, pageNum := range pages {
    // Apply watermark to this page
    // ...
}
```

## Image Watermarks

### Using Image as Watermark Background

```go
import "github.com/georgepadayatti/gopdf/stamp"

// Load watermark image
imageData, _ := os.ReadFile("watermark.png")

// Create visual signature with image as background (watermark mode)
config := stamp.DefaultVisualSignatureConfig()
config.Image = imageData
config.ImagePosition = stamp.ImageTextPositionBackground
config.ImageOpacity = 0.2  // Semi-transparent

// Create visual signature (no text, just image)
config.ShowSignerName = false
config.ShowDate = false
config.ShowReason = false
config.ShowLocation = false

vs, _ := stamp.NewVisualSignature(pageWidth, pageHeight, config)
```

### Image Stamp as Watermark

```go
import "github.com/georgepadayatti/gopdf/stamp"

// Create image stamp with low opacity
style := stamp.DefaultImageStampStyle()
style.Opacity = 0.15  // Very subtle
style.ScaleMode = stamp.ImageScaleFit
style.Position = stamp.ImagePositionCenter

imageData, _ := os.ReadFile("logo.png")
imageStamp, _ := stamp.NewImageStamp(imageData, pageWidth, pageHeight, style)

// Apply to page
// ...
```

## Common Watermark Patterns

### Diagonal "CONFIDENTIAL"

```go
watermark := stamp.NewWatermark("CONFIDENTIAL")
watermark.Rotation = -45
watermark.Opacity = 0.1
watermark.Style.FontSize = 72
watermark.Style.TextColor = color.RGBA{255, 0, 0, 255}  // Red
```

### Horizontal "DRAFT" at Top

```go
watermark := stamp.NewWatermark("DRAFT")
watermark.Rotation = 0
watermark.Opacity = 0.3
watermark.Style.FontSize = 48

// Position at top of page (adjust y coordinate when applying)
```

### Date Stamp

```go
import "time"

dateText := time.Now().Format("2006-01-02")
watermark := stamp.NewWatermark(dateText)
watermark.Rotation = 0
watermark.Opacity = 0.4
watermark.Style.FontSize = 14
```

### Multi-Line Watermark

For multiple lines, use a text stamp instead:

```go
lines := []string{
    "CONFIDENTIAL",
    "For Internal Use Only",
    "Do Not Distribute",
}

textStamp := stamp.NewTextStamp(lines, nil)

// Apply with rotation and opacity as needed
```

## Best Practices

1. **Subtle Opacity**: Use 0.1-0.3 opacity to not obscure content
2. **Contrast**: Choose colors that are visible but not distracting
3. **Consistent Placement**: Apply watermarks consistently across pages
4. **Font Size**: Scale font size based on page dimensions
5. **Test Readability**: Ensure underlying content remains readable

## Complete Example

```go
package main

import (
    "bytes"
    "image/color"
    "log"
    "os"

    "github.com/georgepadayatti/gopdf/pdf/generic"
    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/pdf/writer"
    "github.com/georgepadayatti/gopdf/stamp"
)

// watermarkStamper implements the Stamper interface for watermarks
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

func main() {
    // Read input PDF
    pdfData, _ := os.ReadFile("document.pdf")
    pdfReader, _ := reader.NewPdfFileReaderFromBytes(pdfData)

    // Create watermark
    watermark := stamp.NewWatermark("CONFIDENTIAL")
    watermark.Rotation = -45
    watermark.Opacity = 0.15
    watermark.Style = &stamp.StampStyle{
        FontSize:  72,
        FontName:  "Helvetica-Bold",
        TextColor: color.RGBA{128, 128, 128, 255},
    }

    // Create incremental writer
    incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

    // Apply watermark to all pages
    pageCount := pdfReader.GetPageCount()
    for i := 0; i < pageCount; i++ {
        // Get page dimensions
        pageWidth, pageHeight := getPageDimensions(pdfReader, i)

        // Create stamper
        stamper := &watermarkStamper{
            watermark: watermark,
            width:     pageWidth,
            height:    pageHeight,
        }

        // Apply watermark
        if _, _, _, err := stamp.ApplyStampWithPageTransform(incWriter, pdfReader, stamper, i, 0, 0, nil); err != nil {
            log.Printf("Failed to watermark page %d: %v", i, err)
        }
    }

    // Write output
    var buf bytes.Buffer
    incWriter.Write(&buf)
    os.WriteFile("document_watermarked.pdf", buf.Bytes(), 0644)
}

func getPageDimensions(r *reader.PdfFileReader, pageNum int) (float64, float64) {
    page, err := r.GetPage(pageNum)
    if err != nil {
        return 612, 792
    }
    if arr, ok := page.Get("MediaBox").(generic.ArrayObject); ok && len(arr) >= 4 {
        llx := toFloat(arr[0])
        lly := toFloat(arr[1])
        urx := toFloat(arr[2])
        ury := toFloat(arr[3])
        return urx - llx, ury - lly
    }
    return 612, 792
}

func toFloat(obj generic.PdfObject) float64 {
    switch v := obj.(type) {
    case generic.IntegerObject:
        return float64(v)
    case generic.RealObject:
        return float64(v)
    }
    return 0
}
```
