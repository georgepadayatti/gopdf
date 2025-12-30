package generic

import (
	"bytes"
	"crypto/md5"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRd(t *testing.T) {
	testCases := []struct {
		input    float64
		expected float64
	}{
		{1.23456789, 1.2346},
		{0.0, 0.0},
		{-1.5555, -1.5555},
		{100.00001, 100.0},
	}

	for _, tc := range testCases {
		result := Rd(tc.input)
		if result != tc.expected {
			t.Errorf("Rd(%f) = %f, want %f", tc.input, result, tc.expected)
		}
	}
}

func TestIsRegularCharacter(t *testing.T) {
	// Regular characters
	regulars := []byte("abcABC123")
	for _, b := range regulars {
		if !IsRegularCharacter(b) {
			t.Errorf("IsRegularCharacter(%c) should be true", b)
		}
	}

	// Whitespace
	whitespace := []byte(" \t\n\r")
	for _, b := range whitespace {
		if IsRegularCharacter(b) {
			t.Errorf("IsRegularCharacter(%c) should be false (whitespace)", b)
		}
	}

	// Delimiters
	delimiters := []byte("()[]<>{}/%")
	for _, b := range delimiters {
		if IsRegularCharacter(b) {
			t.Errorf("IsRegularCharacter(%c) should be false (delimiter)", b)
		}
	}
}

func TestIsWhitespace(t *testing.T) {
	for _, b := range PDFWhitespace {
		if !IsWhitespace(b) {
			t.Errorf("IsWhitespace(0x%02x) should be true", b)
		}
	}

	if IsWhitespace('a') {
		t.Error("IsWhitespace('a') should be false")
	}
}

func TestIsDelimiter(t *testing.T) {
	for _, b := range PDFDelimiters {
		if !IsDelimiter(b) {
			t.Errorf("IsDelimiter(%c) should be true", b)
		}
	}

	if IsDelimiter('a') {
		t.Error("IsDelimiter('a') should be false")
	}
}

func TestReadUntilWhitespace(t *testing.T) {
	r := strings.NewReader("hello world")
	result, err := ReadUntilWhitespace(r, 0)
	if err != nil {
		t.Fatalf("ReadUntilWhitespace failed: %v", err)
	}
	if string(result) != "hello" {
		t.Errorf("ReadUntilWhitespace = %q, want %q", result, "hello")
	}

	// With maxChars
	r = strings.NewReader("hello world")
	result, err = ReadUntilWhitespace(r, 3)
	if err != nil {
		t.Fatalf("ReadUntilWhitespace failed: %v", err)
	}
	if string(result) != "hel" {
		t.Errorf("ReadUntilWhitespace(maxChars=3) = %q, want %q", result, "hel")
	}
}

func TestReadUntilDelimiter(t *testing.T) {
	r := strings.NewReader("name/Value")
	result, err := ReadUntilDelimiter(r)
	if err != nil {
		t.Fatalf("ReadUntilDelimiter failed: %v", err)
	}
	if string(result) != "name" {
		t.Errorf("ReadUntilDelimiter = %q, want %q", result, "name")
	}
}

func TestReadNonWhitespace(t *testing.T) {
	t.Run("SkipsWhitespace", func(t *testing.T) {
		r := strings.NewReader("  \t\na")
		b, err := ReadNonWhitespace(r, false, false)
		if err != nil {
			t.Fatalf("ReadNonWhitespace failed: %v", err)
		}
		if b != 'a' {
			t.Errorf("ReadNonWhitespace = %c, want %c", b, 'a')
		}
	})

	t.Run("AllowEOF", func(t *testing.T) {
		r := strings.NewReader("   ")
		b, err := ReadNonWhitespace(r, false, true)
		if err != nil {
			t.Fatalf("ReadNonWhitespace failed: %v", err)
		}
		if b != 0 {
			t.Errorf("ReadNonWhitespace = %c, want 0", b)
		}
	})

	t.Run("ErrorOnEOF", func(t *testing.T) {
		r := strings.NewReader("   ")
		_, err := ReadNonWhitespace(r, false, false)
		if err != ErrStreamEndedPrematurely {
			t.Errorf("Expected ErrStreamEndedPrematurely, got %v", err)
		}
	})
}

func TestSkipOverWhitespace(t *testing.T) {
	t.Run("MultipleWhitespace", func(t *testing.T) {
		r := strings.NewReader("   a")
		multi, err := SkipOverWhitespace(r, false, true)
		if err != nil {
			t.Fatalf("SkipOverWhitespace failed: %v", err)
		}
		if !multi {
			t.Error("Expected multi=true for multiple whitespace")
		}
	})

	t.Run("StopAfterEOL", func(t *testing.T) {
		r := strings.NewReader("  \na")
		_, err := SkipOverWhitespace(r, true, true)
		if err != nil {
			t.Fatalf("SkipOverWhitespace failed: %v", err)
		}
		// Should stop after newline
		buf := make([]byte, 1)
		r.Read(buf)
		if buf[0] != 'a' {
			t.Errorf("Expected 'a' after EOL, got %c", buf[0])
		}
	})
}

func TestSkipOverComments(t *testing.T) {
	t.Run("SingleComment", func(t *testing.T) {
		r := strings.NewReader("% comment\na")
		seen, err := SkipOverComments(r, true)
		if err != nil {
			t.Fatalf("SkipOverComments failed: %v", err)
		}
		if !seen {
			t.Error("Expected seen=true")
		}
	})

	t.Run("NoComment", func(t *testing.T) {
		r := strings.NewReader("abc")
		seen, err := SkipOverComments(r, true)
		if err != nil {
			t.Fatalf("SkipOverComments failed: %v", err)
		}
		if seen {
			t.Error("Expected seen=false")
		}
	})
}

func TestPairIter(t *testing.T) {
	t.Run("ValidPairs", func(t *testing.T) {
		pairs, err := PairIter([]int{1, 2, 3, 4})
		if err != nil {
			t.Fatalf("PairIter failed: %v", err)
		}
		if len(pairs) != 2 {
			t.Errorf("len(pairs) = %d, want 2", len(pairs))
		}
		if pairs[0] != [2]int{1, 2} {
			t.Errorf("pairs[0] = %v, want [1, 2]", pairs[0])
		}
	})

	t.Run("OddLength", func(t *testing.T) {
		_, err := PairIter([]int{1, 2, 3})
		if err == nil {
			t.Error("Expected error for odd length")
		}
	})
}

func TestChunkedDigest(t *testing.T) {
	data := []byte("Hello, World!")
	r := bytes.NewReader(data)
	h := md5.New()

	err := ChunkedDigest(r, h, 4, 0)
	if err != nil {
		t.Fatalf("ChunkedDigest failed: %v", err)
	}

	// Compare with direct hash
	expected := md5.Sum(data)
	if !bytes.Equal(h.Sum(nil), expected[:]) {
		t.Error("ChunkedDigest hash mismatch")
	}
}

func TestChunkedWrite(t *testing.T) {
	data := []byte("Hello, World!")
	r := bytes.NewReader(data)
	var w bytes.Buffer

	err := ChunkedWrite(r, &w, 4, 0)
	if err != nil {
		t.Fatalf("ChunkedWrite failed: %v", err)
	}

	if !bytes.Equal(w.Bytes(), data) {
		t.Error("ChunkedWrite output mismatch")
	}
}

func TestChunkedWriteWithMaxRead(t *testing.T) {
	data := []byte("Hello, World!")
	r := bytes.NewReader(data)
	var w bytes.Buffer

	err := ChunkedWrite(r, &w, 4, 5)
	if err != nil {
		t.Fatalf("ChunkedWrite failed: %v", err)
	}

	if w.Len() != 5 {
		t.Errorf("ChunkedWrite with maxRead=5, len = %d, want 5", w.Len())
	}
}

func TestSeekableBuffer(t *testing.T) {
	buf := NewSeekableBuffer()

	t.Run("Write", func(t *testing.T) {
		n, err := buf.Write([]byte("Hello"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if n != 5 {
			t.Errorf("Write returned %d, want 5", n)
		}
	})

	t.Run("SeekStart", func(t *testing.T) {
		pos, err := buf.Seek(0, io.SeekStart)
		if err != nil {
			t.Fatalf("Seek failed: %v", err)
		}
		if pos != 0 {
			t.Errorf("Seek returned %d, want 0", pos)
		}
	})

	t.Run("Read", func(t *testing.T) {
		data := make([]byte, 5)
		n, err := buf.Read(data)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		if n != 5 || string(data) != "Hello" {
			t.Errorf("Read returned %d bytes: %q, want 5: %q", n, data, "Hello")
		}
	})

	t.Run("SeekEnd", func(t *testing.T) {
		pos, err := buf.Seek(-2, io.SeekEnd)
		if err != nil {
			t.Fatalf("Seek failed: %v", err)
		}
		if pos != 3 {
			t.Errorf("Seek returned %d, want 3", pos)
		}
	})

	t.Run("Bytes", func(t *testing.T) {
		if string(buf.Bytes()) != "Hello" {
			t.Errorf("Bytes = %q, want %q", buf.Bytes(), "Hello")
		}
	})
}

func TestISOParse(t *testing.T) {
	testCases := []struct {
		input    string
		hasError bool
	}{
		{"2023-01-15T10:30:00Z", false},
		{"2023-01-15T10:30:00+05:00", false},
		{"2023-01-15", false},
		{"invalid", true},
	}

	for _, tc := range testCases {
		_, err := ISOParse(tc.input)
		if tc.hasError && err == nil {
			t.Errorf("ISOParse(%q) expected error", tc.input)
		}
		if !tc.hasError && err != nil {
			t.Errorf("ISOParse(%q) failed: %v", tc.input, err)
		}
	}
}

func TestCoalesceString(t *testing.T) {
	if CoalesceString("", "", "value") != "value" {
		t.Error("CoalesceString failed")
	}
	if CoalesceString("first", "second") != "first" {
		t.Error("CoalesceString should return first non-empty")
	}
	if CoalesceString("", "") != "" {
		t.Error("CoalesceString should return empty if all empty")
	}
}

func TestPeek(t *testing.T) {
	slice := []int{1, 2, 3}
	first, all, ok := Peek(slice)
	if !ok {
		t.Error("Peek should return ok=true")
	}
	if first != 1 {
		t.Errorf("first = %d, want 1", first)
	}
	if len(all) != 3 {
		t.Errorf("len(all) = %d, want 3", len(all))
	}

	_, _, ok = Peek([]int{})
	if ok {
		t.Error("Peek should return ok=false for empty slice")
	}
}

func TestLazyJoin(t *testing.T) {
	lj := &LazyJoin{Sep: ", ", Items: []string{"a", "b", "c"}}
	if lj.String() != "a, b, c" {
		t.Errorf("LazyJoin = %q, want %q", lj.String(), "a, b, c")
	}
}

func TestConsList(t *testing.T) {
	list := NewConsList(3)
	list = list.Prepend(2)
	list = list.Prepend(1)

	if list.Len() != 3 {
		t.Errorf("Len = %d, want 3", list.Len())
	}

	slice := list.ToSlice()
	expected := []int{1, 2, 3}
	for i, v := range slice {
		if v != expected[i] {
			t.Errorf("slice[%d] = %d, want %d", i, v, expected[i])
		}
	}
}

func TestStringWithLanguage(t *testing.T) {
	s := NewStringWithLanguage("Hello", "en", "US")
	if s.String() != "Hello" {
		t.Errorf("String() = %q, want %q", s.String(), "Hello")
	}
	if s.LangCode != "en" {
		t.Errorf("LangCode = %q, want %q", s.LangCode, "en")
	}
	if s.CountryCode != "US" {
		t.Errorf("CountryCode = %q, want %q", s.CountryCode, "US")
	}
}

func TestPdfError(t *testing.T) {
	err := NewPdfError("test error")
	if err.Error() != "test error" {
		t.Errorf("Error() = %q, want %q", err.Error(), "test error")
	}

	readErr := NewPdfReadError("read error")
	if readErr.Error() != "read error" {
		t.Errorf("Error() = %q, want %q", readErr.Error(), "read error")
	}

	writeErr := NewPdfWriteError("write error")
	if writeErr.Error() != "write error" {
		t.Errorf("Error() = %q, want %q", writeErr.Error(), "write error")
	}

	streamErr := NewPdfStreamError("stream error")
	if streamErr.Error() != "stream error" {
		t.Errorf("Error() = %q, want %q", streamErr.Error(), "stream error")
	}
}

func TestFormFillingError(t *testing.T) {
	err := NewFormFillingError("form error")
	if err.Error() != "form error" {
		t.Errorf("Error() = %q, want %q", err.Error(), "form error")
	}
}

func TestIndirectObjectExpectedError(t *testing.T) {
	err := NewIndirectObjectExpectedError("")
	if err.Error() != "indirect object expected" {
		t.Errorf("Error() = %q, want default message", err.Error())
	}

	err = NewIndirectObjectExpectedError("custom message")
	if err.Error() != "custom message" {
		t.Errorf("Error() = %q, want %q", err.Error(), "custom message")
	}
}

func TestGetAndApply(t *testing.T) {
	m := map[string]int{"a": 1, "b": 2}

	result := GetAndApply(m, "a", func(v int) int { return v * 2 }, 0)
	if result != 2 {
		t.Errorf("GetAndApply = %d, want 2", result)
	}

	result = GetAndApply(m, "c", func(v int) int { return v * 2 }, -1)
	if result != -1 {
		t.Errorf("GetAndApply for missing key = %d, want -1", result)
	}
}

func TestPrepareRWOutputStream(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		rws := PrepareRWOutputStream(nil)
		if rws == nil {
			t.Error("Should return non-nil for nil input")
		}
	})

	t.Run("NonSeekable", func(t *testing.T) {
		var buf bytes.Buffer
		rws := PrepareRWOutputStream(&buf)
		// Should return a SeekableBuffer since bytes.Buffer isn't seekable
		if _, ok := rws.(*SeekableBuffer); !ok {
			t.Error("Should return SeekableBuffer for non-seekable writer")
		}
	})
}

func TestFinaliseOutput(t *testing.T) {
	t.Run("NilOriginal", func(t *testing.T) {
		buf := NewSeekableBuffer()
		err := FinaliseOutput(nil, buf)
		if err != nil {
			t.Errorf("FinaliseOutput failed: %v", err)
		}
	})

	t.Run("SameBuffer", func(t *testing.T) {
		buf := NewSeekableBuffer()
		err := FinaliseOutput(buf, buf)
		if err != nil {
			t.Errorf("FinaliseOutput failed: %v", err)
		}
	})

	t.Run("DifferentBuffers", func(t *testing.T) {
		orig := &bytes.Buffer{}
		ret := NewSeekableBuffer()
		ret.Write([]byte("data"))

		err := FinaliseOutput(orig, ret)
		if err != nil {
			t.Errorf("FinaliseOutput failed: %v", err)
		}
		if orig.String() != "data" {
			t.Errorf("orig = %q, want %q", orig.String(), "data")
		}
	})
}

func TestChunkStream(t *testing.T) {
	data := []byte("Hello, World!")
	r := bytes.NewReader(data)

	var result []byte
	for chunk := range ChunkStream(r, 4, 0) {
		result = append(result, chunk...)
	}

	if !bytes.Equal(result, data) {
		t.Errorf("ChunkStream result = %q, want %q", result, data)
	}
}

func TestPdfDateParsing(t *testing.T) {
	// Test parsing a known date
	dt, err := ISOParse("2023-12-25T10:30:00Z")
	if err != nil {
		t.Fatalf("ISOParse failed: %v", err)
	}

	if dt.Year() != 2023 || dt.Month() != time.December || dt.Day() != 25 {
		t.Errorf("Date = %v, want 2023-12-25", dt)
	}
}
