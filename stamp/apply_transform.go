package stamp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/pdf/reader"
	"github.com/georgepadayatti/gopdf/pdf/writer"
)

// ApplyStampWithPageTransform applies a stamp while respecting page coordinate transforms.
func ApplyStampWithPageTransform(w *writer.IncrementalPdfFileWriter, r *reader.PdfFileReader, stamp Stamper, pageNum int, x, y float64, opts *ApplyOptions) (generic.Reference, float64, float64, error) {
	if opts == nil {
		opts = DefaultApplyOptions()
	}

	appearance := stamp.CreateAppearanceStream()
	stampRef := w.AddObject(appearance)

	randBytes := make([]byte, 8)
	rand.Read(randBytes)
	resourceName := "/Stamp" + hex.EncodeToString(randBytes)

	_, pageHeight, err := getPageDimensions(r, pageNum)
	if err != nil {
		return generic.Reference{}, 0, 0, err
	}

	flipY, err := pageHasYFlip(r, pageNum, pageHeight)
	if err != nil {
		return generic.Reference{}, 0, 0, err
	}

	width, height := stamp.GetDimensions()

	var stampPaint string
	if flipY {
		stampPaint = fmt.Sprintf("q 1 0 0 -1 %f %f cm %s Do Q", x, pageHeight-y, resourceName)
	} else {
		stampPaint = fmt.Sprintf("q 1 0 0 1 %f %f cm %s Do Q", x, y, resourceName)
	}
	stampWrapperStream := generic.NewStream(nil, []byte(stampPaint))

	resources := generic.NewDictionary()
	xobjects := generic.NewDictionary()
	xobjects.Set(resourceName[1:], stampRef)
	resources.Set("XObject", xobjects)

	if opts.WrapExistingContent {
		qStream := generic.NewStream(nil, []byte("q"))
		qRef := w.AddObject(qStream)
		if _, err := w.AddStreamToPage(pageNum, qRef, nil, true); err != nil {
			return generic.Reference{}, 0, 0, err
		}

		bigQStream := generic.NewStream(nil, []byte("Q"))
		bigQRef := w.AddObject(bigQStream)
		if _, err := w.AddStreamToPage(pageNum, bigQRef, nil, false); err != nil {
			return generic.Reference{}, 0, 0, err
		}
	}

	wrapperRef := w.AddObject(stampWrapperStream)
	pageRef, err := w.AddStreamToPage(pageNum, wrapperRef, resources, false)
	if err != nil {
		return generic.Reference{}, 0, 0, err
	}

	return pageRef, width, height, nil
}

func pageHasYFlip(r *reader.PdfFileReader, pageNum int, pageHeight float64) (bool, error) {
	page, err := r.GetPage(pageNum)
	if err != nil {
		return false, err
	}

	streams, err := getContentStreams(r, page)
	if err != nil || len(streams) == 0 {
		return false, err
	}

	data := streams[0].GetDecodedData()
	if len(data) == 0 {
		return false, nil
	}

	tokens := bytes.Fields(data)
	if len(tokens) < 7 {
		return false, nil
	}

	if string(tokens[0]) != "1" || string(tokens[1]) != "0" || string(tokens[2]) != "0" || string(tokens[3]) != "-1" || string(tokens[4]) != "0" || string(tokens[6]) != "cm" {
		return false, nil
	}

	heightVal, err := strconv.ParseFloat(string(tokens[5]), 64)
	if err != nil {
		return false, nil
	}

	const tol = 0.5
	if heightVal > pageHeight-tol && heightVal < pageHeight+tol {
		return true, nil
	}

	return false, nil
}

func getContentStreams(r *reader.PdfFileReader, page *generic.DictionaryObject) ([]*generic.StreamObject, error) {
	contents := page.Get("Contents")
	if contents == nil {
		return nil, nil
	}

	var refs []generic.Reference
	switch c := contents.(type) {
	case generic.Reference:
		refs = append(refs, c)
	case *generic.IndirectObject:
		if ref, ok := c.Object.(generic.Reference); ok {
			refs = append(refs, ref)
		}
	case generic.ArrayObject:
		for _, item := range c {
			if ref, ok := item.(generic.Reference); ok {
				refs = append(refs, ref)
			}
		}
	case *generic.ArrayObject:
		for _, item := range *c {
			if ref, ok := item.(generic.Reference); ok {
				refs = append(refs, ref)
			}
		}
	default:
		return nil, nil
	}

	var streams []*generic.StreamObject
	for _, ref := range refs {
		obj, err := r.GetObject(ref.ObjectNumber)
		if err != nil {
			return nil, err
		}
		stream, ok := obj.(*generic.StreamObject)
		if !ok {
			continue
		}
		streams = append(streams, stream)
	}

	return streams, nil
}

func getPageDimensions(r *reader.PdfFileReader, pageNum int) (width, height float64, err error) {
	page, err := r.GetPage(pageNum)
	if err != nil {
		return 0, 0, err
	}

	mediaBox := page.Get("MediaBox")
	if arr, ok := mediaBox.(generic.ArrayObject); ok && len(arr) >= 4 {
		llx := getFloat(arr[0])
		lly := getFloat(arr[1])
		urx := getFloat(arr[2])
		ury := getFloat(arr[3])
		return urx - llx, ury - lly, nil
	}

	return 612, 792, nil
}

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
