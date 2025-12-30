// Package generic provides misc utility functions for PDF processing.
package generic

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"regexp"
	"time"
)

// DefaultChunkSize is the default chunk size for stream I/O.
const DefaultChunkSize = 4096

// PDF character classes
var (
	// PDFWhitespace contains all PDF whitespace characters.
	PDFWhitespace = []byte(" \n\r\t\f\x00")

	// PDFDelimiters contains all PDF delimiter characters.
	PDFDelimiters = []byte("()<>[]{}/%")
)

// Error types for PDF processing

// PdfError is the base error type for PDF operations.
type PdfError struct {
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *PdfError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying error.
func (e *PdfError) Unwrap() error {
	return e.Cause
}

// NewPdfError creates a new PdfError.
func NewPdfError(msg string) *PdfError {
	return &PdfError{Message: msg}
}

// PdfReadError represents an error during PDF reading.
type PdfReadError struct {
	PdfError
}

// NewPdfReadError creates a new PdfReadError.
func NewPdfReadError(msg string) *PdfReadError {
	return &PdfReadError{PdfError: PdfError{Message: msg}}
}

// PdfStrictReadError represents a strict mode reading error.
type PdfStrictReadError struct {
	PdfReadError
}

// NewPdfStrictReadError creates a new PdfStrictReadError.
func NewPdfStrictReadError(msg string) *PdfStrictReadError {
	return &PdfStrictReadError{PdfReadError: PdfReadError{PdfError: PdfError{Message: msg}}}
}

// PdfStreamError represents a stream processing error.
type PdfStreamError struct {
	PdfReadError
}

// NewPdfStreamError creates a new PdfStreamError.
func NewPdfStreamError(msg string) *PdfStreamError {
	return &PdfStreamError{PdfReadError: PdfReadError{PdfError: PdfError{Message: msg}}}
}

// PdfWriteError represents an error during PDF writing.
type PdfWriteError struct {
	PdfError
}

// NewPdfWriteError creates a new PdfWriteError.
func NewPdfWriteError(msg string) *PdfWriteError {
	return &PdfWriteError{PdfError: PdfError{Message: msg}}
}

// IndirectObjectExpectedError is raised when an indirect object was expected.
type IndirectObjectExpectedError struct {
	PdfReadError
}

// NewIndirectObjectExpectedError creates a new IndirectObjectExpectedError.
func NewIndirectObjectExpectedError(msg string) *IndirectObjectExpectedError {
	if msg == "" {
		msg = "indirect object expected"
	}
	return &IndirectObjectExpectedError{PdfReadError: PdfReadError{PdfError: PdfError{Message: msg}}}
}

// FormFillingError represents a form filling error.
type FormFillingError struct {
	Message string
}

// Error implements the error interface.
func (e *FormFillingError) Error() string {
	return e.Message
}

// NewFormFillingError creates a new FormFillingError.
func NewFormFillingError(msg string) *FormFillingError {
	return &FormFillingError{Message: msg}
}

// Common sentinel errors
var (
	ErrStreamEndedPrematurely = errors.New("stream ended prematurely")
	ErrOutputNotWritable      = errors.New("output buffer is not writable")
)

// StringWithLanguage represents a string with language information.
type StringWithLanguage struct {
	Value       string
	LangCode    string
	CountryCode string
}

// String returns the string value.
func (s *StringWithLanguage) String() string {
	return s.Value
}

// NewStringWithLanguage creates a new StringWithLanguage.
func NewStringWithLanguage(value string, langCode string, countryCode string) *StringWithLanguage {
	return &StringWithLanguage{
		Value:       value,
		LangCode:    langCode,
		CountryCode: countryCode,
	}
}

// Rd rounds a float to 4 decimal places.
func Rd(x float64) float64 {
	return math.Round(x*10000) / 10000
}

// IsRegularCharacter returns true if the byte is a regular PDF character.
func IsRegularCharacter(b byte) bool {
	return !bytes.ContainsAny([]byte{b}, string(PDFWhitespace)) &&
		!bytes.ContainsAny([]byte{b}, string(PDFDelimiters))
}

// IsWhitespace returns true if the byte is a PDF whitespace character.
func IsWhitespace(b byte) bool {
	return bytes.ContainsAny([]byte{b}, string(PDFWhitespace))
}

// IsDelimiter returns true if the byte is a PDF delimiter character.
func IsDelimiter(b byte) bool {
	return bytes.ContainsAny([]byte{b}, string(PDFDelimiters))
}

// ReadUntilWhitespace reads non-whitespace characters until whitespace is encountered.
func ReadUntilWhitespace(r io.Reader, maxChars int) ([]byte, error) {
	result, _, err := readUntilClass(PDFWhitespace, r, maxChars)
	return result, err
}

// ReadUntilDelimiter reads until a delimiter or whitespace is encountered.
func ReadUntilDelimiter(r io.ReadSeeker) ([]byte, error) {
	class := append(PDFWhitespace, PDFDelimiters...)
	result, atEnd, err := readUntilClass(class, r, 0)
	if err != nil {
		return result, err
	}
	if !atEnd {
		r.Seek(-1, io.SeekCurrent)
	}
	return result, nil
}

// readUntilClass reads bytes until a character in the given class is encountered.
func readUntilClass(class []byte, r io.Reader, maxChars int) ([]byte, bool, error) {
	var result []byte
	buf := make([]byte, 1)
	count := 0

	for {
		if maxChars > 0 && count >= maxChars {
			break
		}

		n, err := r.Read(buf)
		if err == io.EOF || n == 0 {
			return result, true, nil
		}
		if err != nil {
			return result, false, err
		}

		if bytes.ContainsAny(buf, string(class)) {
			break
		}

		result = append(result, buf[0])
		count++
	}

	return result, false, nil
}

// ReadNonWhitespace finds and reads the next non-whitespace character.
func ReadNonWhitespace(r io.ReadSeeker, seekBack bool, allowEOF bool) (byte, error) {
	buf := make([]byte, 1)

	for {
		n, err := r.Read(buf)
		if err == io.EOF || n == 0 {
			if allowEOF {
				return 0, nil
			}
			return 0, ErrStreamEndedPrematurely
		}
		if err != nil {
			return 0, err
		}

		// Skip whitespace
		if IsWhitespace(buf[0]) {
			continue
		}

		// Handle comments
		if buf[0] == '%' {
			r.Seek(-1, io.SeekCurrent)
			SkipOverComments(r, true)
			continue
		}

		// Found non-whitespace, non-comment
		if seekBack {
			r.Seek(-1, io.SeekCurrent)
		}
		return buf[0], nil
	}
}

// SkipOverWhitespace skips whitespace and optionally stops after EOL.
func SkipOverWhitespace(r io.ReadSeeker, stopAfterEOL bool, errorOnEOS bool) (bool, error) {
	buf := make([]byte, 1)
	count := 0

	for {
		n, err := r.Read(buf)
		if err == io.EOF || n == 0 {
			if errorOnEOS {
				return false, ErrStreamEndedPrematurely
			}
			return true, nil
		}
		if err != nil {
			return false, err
		}

		if !IsWhitespace(buf[0]) {
			r.Seek(-1, io.SeekCurrent)
			return count > 1, nil
		}

		count++

		if stopAfterEOL {
			if buf[0] == '\n' {
				return count > 1, nil
			}
			if buf[0] == '\r' {
				// Check for CRLF
				n, err = r.Read(buf)
				if err == io.EOF || n == 0 {
					return count > 1, nil
				}
				if buf[0] != '\n' {
					r.Seek(-1, io.SeekCurrent)
				}
				return count > 1, nil
			}
		}
	}
}

// SkipOverComments skips over PDF comments.
func SkipOverComments(r io.ReadSeeker, errorOnEOS bool) (bool, error) {
	buf := make([]byte, 1)
	seen := false

	n, err := r.Read(buf)
	if err != nil || n == 0 {
		return false, err
	}

	for buf[0] == '%' {
		seen = true
		// Read until end of line
		for {
			n, err = r.Read(buf)
			if err == io.EOF || n == 0 {
				return seen, nil
			}
			if err != nil {
				return seen, err
			}
			if buf[0] == '\n' || buf[0] == '\r' {
				break
			}
		}

		// Skip whitespace after comment
		SkipOverWhitespace(r, false, errorOnEOS)

		// Check for another comment
		n, err = r.Read(buf)
		if err != nil || n == 0 {
			return seen, nil
		}
	}

	// Seek back to before non-comment character
	if n > 0 {
		r.Seek(-1, io.SeekCurrent)
	}

	return seen, nil
}

// ReadUntilRegex reads until a regex pattern is matched.
func ReadUntilRegex(r io.ReadSeeker, pattern *regexp.Regexp, ignoreEOF bool) ([]byte, error) {
	var result []byte
	buf := make([]byte, 16)

	for {
		n, err := r.Read(buf)
		if err == io.EOF || n == 0 {
			if ignoreEOF {
				return result, nil
			}
			return result, NewPdfStreamError("stream has ended unexpectedly")
		}
		if err != nil {
			return result, err
		}

		chunk := buf[:n]
		loc := pattern.FindIndex(chunk)
		if loc != nil {
			result = append(result, chunk[:loc[0]]...)
			// Seek back to match start
			r.Seek(int64(loc[0]-n), io.SeekCurrent)
			break
		}
		result = append(result, chunk...)
	}

	return result, nil
}

// PairIter iterates over pairs of elements.
func PairIter[T any](slice []T) ([][2]T, error) {
	if len(slice)%2 != 0 {
		return nil, errors.New("list has odd number of elements")
	}

	pairs := make([][2]T, len(slice)/2)
	for i := 0; i < len(slice); i += 2 {
		pairs[i/2] = [2]T{slice[i], slice[i+1]}
	}
	return pairs, nil
}

// ChunkStream yields chunks from a stream.
func ChunkStream(r io.Reader, chunkSize int, maxRead int) <-chan []byte {
	ch := make(chan []byte)
	go func() {
		defer close(ch)
		buf := make([]byte, chunkSize)
		totalRead := 0

		for maxRead <= 0 || totalRead < maxRead {
			toRead := chunkSize
			if maxRead > 0 && totalRead+toRead > maxRead {
				toRead = maxRead - totalRead
			}

			n, err := r.Read(buf[:toRead])
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				ch <- chunk
				totalRead += n
			}
			if err != nil {
				break
			}
		}
	}()
	return ch
}

// ChunkedDigest updates a hash with chunked data from a stream.
func ChunkedDigest(r io.Reader, h hash.Hash, chunkSize int, maxRead int) error {
	buf := make([]byte, chunkSize)
	totalRead := 0

	for maxRead <= 0 || totalRead < maxRead {
		toRead := chunkSize
		if maxRead > 0 && totalRead+toRead > maxRead {
			toRead = maxRead - totalRead
		}

		n, err := r.Read(buf[:toRead])
		if n > 0 {
			h.Write(buf[:n])
			totalRead += n
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ChunkedWrite writes data from a reader to a writer in chunks.
func ChunkedWrite(r io.Reader, w io.Writer, chunkSize int, maxRead int) error {
	buf := make([]byte, chunkSize)
	totalRead := 0

	for maxRead <= 0 || totalRead < maxRead {
		toRead := chunkSize
		if maxRead > 0 && totalRead+toRead > maxRead {
			toRead = maxRead - totalRead
		}

		n, err := r.Read(buf[:toRead])
		if n > 0 {
			_, writeErr := w.Write(buf[:n])
			if writeErr != nil {
				return writeErr
			}
			totalRead += n
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// SeekableBuffer is a bytes.Buffer wrapper that supports seeking.
type SeekableBuffer struct {
	buf    []byte
	pos    int
	length int
}

// NewSeekableBuffer creates a new seekable buffer.
func NewSeekableBuffer() *SeekableBuffer {
	return &SeekableBuffer{
		buf: make([]byte, 0, 4096),
	}
}

// Read implements io.Reader.
func (s *SeekableBuffer) Read(p []byte) (int, error) {
	if s.pos >= s.length {
		return 0, io.EOF
	}
	n := copy(p, s.buf[s.pos:s.length])
	s.pos += n
	return n, nil
}

// Write implements io.Writer.
func (s *SeekableBuffer) Write(p []byte) (int, error) {
	// Expand buffer if needed
	needed := s.pos + len(p)
	if needed > len(s.buf) {
		newBuf := make([]byte, needed*2)
		copy(newBuf, s.buf)
		s.buf = newBuf
	}
	n := copy(s.buf[s.pos:], p)
	s.pos += n
	if s.pos > s.length {
		s.length = s.pos
	}
	return n, nil
}

// Seek implements io.Seeker.
func (s *SeekableBuffer) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = int64(s.pos) + offset
	case io.SeekEnd:
		newPos = int64(s.length) + offset
	default:
		return 0, errors.New("invalid whence")
	}
	if newPos < 0 {
		return 0, errors.New("negative position")
	}
	s.pos = int(newPos)
	return newPos, nil
}

// Bytes returns the buffer contents.
func (s *SeekableBuffer) Bytes() []byte {
	return s.buf[:s.length]
}

// Len returns the length of the data.
func (s *SeekableBuffer) Len() int {
	return s.length
}

// PrepareRWOutputStream prepares an output stream that supports reading and writing.
func PrepareRWOutputStream(output io.Writer) io.ReadWriteSeeker {
	if output == nil {
		return NewSeekableBuffer()
	}

	if rws, ok := output.(io.ReadWriteSeeker); ok {
		return rws
	}

	// Fall back to seekable buffer
	return NewSeekableBuffer()
}

// FinaliseOutput handles unwrapping of internal buffers.
func FinaliseOutput(origOutput io.Writer, returnedOutput io.ReadWriteSeeker) error {
	if origOutput == nil {
		return nil
	}

	if origOutput == returnedOutput {
		return nil
	}

	// Copy from returned buffer to original
	if buf, ok := returnedOutput.(*SeekableBuffer); ok {
		_, err := origOutput.Write(buf.Bytes())
		return err
	}

	// For other types, seek to start and copy
	if seeker, ok := returnedOutput.(io.Seeker); ok {
		seeker.Seek(0, io.SeekStart)
	}
	if reader, ok := returnedOutput.(io.Reader); ok {
		_, err := io.Copy(origOutput, reader)
		return err
	}

	return nil
}

// ISOParse parses an ISO 8601 date string.
func ISOParse(dtStr string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02",
		"20060102T150405Z",
		"20060102T150405",
	}

	var lastErr error
	for _, format := range formats {
		t, err := time.Parse(format, dtStr)
		if err == nil {
			// Assume UTC if no timezone
			if t.Location() == time.Local {
				t = t.UTC()
			}
			return t, nil
		}
		lastErr = err
	}

	return time.Time{}, fmt.Errorf("cannot parse date: %s: %v", dtStr, lastErr)
}

// GetAndApply gets a value from a map and applies a function to it.
func GetAndApply[K comparable, V any, R any](m map[K]V, key K, fn func(V) R, defaultVal R) R {
	if val, ok := m[key]; ok {
		return fn(val)
	}
	return defaultVal
}

// Coalesce returns the first non-nil value.
func Coalesce[T any](values ...*T) *T {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

// CoalesceString returns the first non-empty string.
func CoalesceString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Peek returns the first element and an iterator over all elements.
func Peek[T any](slice []T) (T, []T, bool) {
	var zero T
	if len(slice) == 0 {
		return zero, nil, false
	}
	return slice[0], slice, true
}

// LazyJoin lazily joins strings.
type LazyJoin struct {
	Sep   string
	Items []string
}

// String performs the join.
func (lj *LazyJoin) String() string {
	result := ""
	for i, item := range lj.Items {
		if i > 0 {
			result += lj.Sep
		}
		result += item
	}
	return result
}

// ConsList is a cons-style linked list for efficient prepending.
type ConsList[T any] struct {
	Head T
	Tail *ConsList[T]
}

// NewConsList creates a new cons list with a single element.
func NewConsList[T any](head T) *ConsList[T] {
	return &ConsList[T]{Head: head}
}

// Prepend adds an element to the front.
func (c *ConsList[T]) Prepend(head T) *ConsList[T] {
	return &ConsList[T]{Head: head, Tail: c}
}

// ToSlice converts the cons list to a slice.
func (c *ConsList[T]) ToSlice() []T {
	var result []T
	current := c
	for current != nil {
		result = append(result, current.Head)
		current = current.Tail
	}
	return result
}

// Len returns the length of the cons list.
func (c *ConsList[T]) Len() int {
	count := 0
	current := c
	for current != nil {
		count++
		current = current.Tail
	}
	return count
}
