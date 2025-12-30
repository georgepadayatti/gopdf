// Package writer provides PDF file writing and incremental update support.
package writer

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/filters"
	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// PdfFileWriter creates new PDF files.
type PdfFileWriter struct {
	Version    string
	Objects    map[int]*generic.IndirectObject
	nextObjNum int
	Root       *generic.DictionaryObject
	Info       *generic.DictionaryObject
	Pages      *generic.DictionaryObject
	pageList   []*generic.DictionaryObject
	AcroForm   *generic.DictionaryObject
	FileID     []byte
}

// NewPdfFileWriter creates a new PDF writer.
func NewPdfFileWriter(version string) *PdfFileWriter {
	if version == "" {
		version = "1.7"
	}

	w := &PdfFileWriter{
		Version:    version,
		Objects:    make(map[int]*generic.IndirectObject),
		nextObjNum: 1,
	}

	// Create document catalog
	w.Root = generic.NewDictionary()
	w.Root.Set("Type", generic.NameObject("Catalog"))

	// Create pages tree
	w.Pages = generic.NewDictionary()
	w.Pages.Set("Type", generic.NameObject("Pages"))
	w.Pages.Set("Kids", generic.ArrayObject{})
	w.Pages.Set("Count", generic.IntegerObject(0))

	pagesRef := w.AddObject(w.Pages)
	w.Root.Set("Pages", pagesRef)

	// Create info dictionary
	w.Info = generic.NewDictionary()
	w.Info.Set("Producer", generic.NewTextString("GoPDF"))
	w.Info.Set("CreationDate", generic.NewTextString(formatPdfDate(time.Now())))

	return w
}

// AddObject adds an object and returns its reference.
func (w *PdfFileWriter) AddObject(obj generic.PdfObject) generic.Reference {
	objNum := w.nextObjNum
	w.nextObjNum++

	w.Objects[objNum] = generic.NewIndirectObject(objNum, 0, obj)
	return generic.Reference{ObjectNumber: objNum, GenerationNumber: 0}
}

// AddPage adds a page to the document.
func (w *PdfFileWriter) AddPage(mediaBox *generic.Rectangle, contents []byte) generic.Reference {
	page := generic.NewDictionary()
	page.Set("Type", generic.NameObject("Page"))
	page.Set("Parent", w.getReference(w.Pages))
	page.Set("MediaBox", mediaBox.ToArray())

	if contents != nil {
		// Create content stream
		stream := generic.NewStream(nil, contents)
		stream.Dictionary.Set("Filter", generic.NameObject("FlateDecode"))

		// Compress contents
		encoded, err := filters.EncodeStream(contents, []string{"FlateDecode"}, nil)
		if err == nil {
			stream.EncodedData = encoded
		}

		contentsRef := w.AddObject(stream)
		page.Set("Contents", contentsRef)
	}

	pageRef := w.AddObject(page)
	w.pageList = append(w.pageList, page)

	// Update pages tree
	kids := w.Pages.GetArray("Kids")
	kids = append(kids, pageRef)
	w.Pages.Set("Kids", kids)
	w.Pages.Set("Count", generic.IntegerObject(len(w.pageList)))

	return pageRef
}

// AddAcroForm creates or returns the AcroForm dictionary.
func (w *PdfFileWriter) AddAcroForm() *generic.DictionaryObject {
	if w.AcroForm == nil {
		w.AcroForm = generic.NewDictionary()
		w.AcroForm.Set("Fields", generic.ArrayObject{})
		w.AcroForm.Set("SigFlags", generic.IntegerObject(0))

		acroFormRef := w.AddObject(w.AcroForm)
		w.Root.Set("AcroForm", acroFormRef)
	}
	return w.AcroForm
}

// AddSignatureField adds a signature field to the document.
func (w *PdfFileWriter) AddSignatureField(name string, pageIndex int, rect *generic.Rectangle) (generic.Reference, error) {
	if pageIndex < 0 || pageIndex >= len(w.pageList) {
		return generic.Reference{}, fmt.Errorf("page index out of bounds")
	}

	// Create signature field
	sigField := generic.NewDictionary()
	sigField.Set("Type", generic.NameObject("Annot"))
	sigField.Set("Subtype", generic.NameObject("Widget"))
	sigField.Set("FT", generic.NameObject("Sig"))
	sigField.Set("T", generic.NewTextString(name))
	sigField.Set("Rect", rect.ToArray())
	sigField.Set("F", generic.IntegerObject(132)) // Print + Locked
	sigField.Set("P", w.getReference(w.pageList[pageIndex]))

	sigFieldRef := w.AddObject(sigField)

	// Add to AcroForm
	acroForm := w.AddAcroForm()
	fields := acroForm.GetArray("Fields")
	fields = append(fields, sigFieldRef)
	acroForm.Set("Fields", fields)

	// Update SigFlags
	sigFlags, _ := acroForm.GetInt("SigFlags")
	sigFlags |= 3 // SignaturesExist | AppendOnly
	acroForm.Set("SigFlags", generic.IntegerObject(sigFlags))

	// Add annotation to page
	page := w.pageList[pageIndex]
	annots := page.GetArray("Annots")
	if annots == nil {
		annots = generic.ArrayObject{}
	}
	annots = append(annots, sigFieldRef)
	page.Set("Annots", annots)

	return sigFieldRef, nil
}

// Write writes the PDF to the given writer.
func (w *PdfFileWriter) Write(out io.Writer) error {
	var buf bytes.Buffer

	// Write header
	fmt.Fprintf(&buf, "%%PDF-%s\n", w.Version)
	// Binary comment (per PDF spec)
	buf.Write([]byte{0x25, 0xE2, 0xE3, 0xCF, 0xD3, 0x0A})

	// Track object offsets for xref
	offsets := make(map[int]int64)

	// Add root and info to objects
	rootRef := w.AddObject(w.Root)
	infoRef := w.AddObject(w.Info)

	// Write objects
	for objNum := 1; objNum < w.nextObjNum; objNum++ {
		obj := w.Objects[objNum]
		if obj == nil {
			continue
		}
		offsets[objNum] = int64(buf.Len())
		obj.Write(&buf)
		buf.WriteByte('\n')
	}

	// Generate file ID
	if w.FileID == nil {
		w.FileID = generic.ComputeFileID(map[string]string{
			"time":    time.Now().String(),
			"version": w.Version,
		})
	}

	// Write xref table
	xrefOffset := int64(buf.Len())
	fmt.Fprintf(&buf, "xref\n")
	fmt.Fprintf(&buf, "0 %d\n", w.nextObjNum)
	fmt.Fprintf(&buf, "0000000000 65535 f \n")

	for objNum := 1; objNum < w.nextObjNum; objNum++ {
		offset := offsets[objNum]
		fmt.Fprintf(&buf, "%010d %05d n \n", offset, 0)
	}

	// Write trailer
	trailer := generic.NewDictionary()
	trailer.Set("Size", generic.IntegerObject(w.nextObjNum))
	trailer.Set("Root", rootRef)
	trailer.Set("Info", infoRef)
	trailer.Set("ID", generic.ArrayObject{
		generic.NewHexString(w.FileID),
		generic.NewHexString(w.FileID),
	})

	fmt.Fprintf(&buf, "trailer\n")
	trailer.Write(&buf)
	fmt.Fprintf(&buf, "\nstartxref\n%d\n%%%%EOF\n", xrefOffset)

	_, err := out.Write(buf.Bytes())
	return err
}

// getReference returns a reference for an object in the writer.
func (w *PdfFileWriter) getReference(obj generic.PdfObject) generic.Reference {
	for objNum, indObj := range w.Objects {
		if indObj.Object == obj {
			return generic.Reference{ObjectNumber: objNum, GenerationNumber: 0}
		}
	}
	// Object not found, add it
	return w.AddObject(obj)
}

// formatPdfDate formats a time as a PDF date string.
func formatPdfDate(t time.Time) string {
	_, offset := t.Zone()
	offsetHours := offset / 3600
	offsetMinutes := (offset % 3600) / 60

	sign := "+"
	if offset < 0 {
		sign = "-"
		offsetHours = -offsetHours
		offsetMinutes = -offsetMinutes
	}

	return fmt.Sprintf("D:%04d%02d%02d%02d%02d%02d%s%02d'%02d'",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(),
		sign, offsetHours, offsetMinutes)
}
