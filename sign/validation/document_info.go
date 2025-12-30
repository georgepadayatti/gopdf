package validation

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/pdf/reader"
)

// DocumentInfo contains PDF document metadata extracted from the Info dictionary.
// These fields provide information about the document's origin and history.
type DocumentInfo struct {
	// Title is the document's title.
	Title string `json:"title,omitempty"`

	// Author is the name of the person who created the document.
	Author string `json:"author,omitempty"`

	// Subject is the subject of the document.
	Subject string `json:"subject,omitempty"`

	// Keywords contains keywords associated with the document.
	Keywords []string `json:"keywords,omitempty"`

	// Creator is the name of the application that created the original document
	// (if it was converted to PDF from another format).
	Creator string `json:"creator,omitempty"`

	// Producer is the name of the application that produced the PDF.
	Producer string `json:"producer,omitempty"`

	// CreationDate is the date and time the document was created.
	CreationDate *time.Time `json:"creation_date,omitempty"`

	// ModDate is the date and time the document was last modified.
	ModDate *time.Time `json:"mod_date,omitempty"`

	// Pages is the number of pages in the document.
	Pages int `json:"pages"`

	// Trapped indicates whether the document has been trapped.
	// Values: "True", "False", "Unknown", or empty.
	Trapped string `json:"trapped,omitempty"`
}

// pdfDateRegex matches PDF date format: D:YYYYMMDDHHmmSSOHH'mm'
// The format is defined in PDF Reference 1.7, Section 3.8.3
// Examples:
//   - D:19990209153925-08'00'
//   - D:20230615120000Z
//   - D:20230615
var pdfDateRegex = regexp.MustCompile(
	`^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([-+Z])?(\d{2})?'?(\d{2})?'?$`,
)

// ParsePDFDate parses a PDF date string into a time.Time.
// PDF dates have the format: D:YYYYMMDDHHmmSSOHH'mm'
// where:
//   - YYYY = 4-digit year
//   - MM = 2-digit month (01-12)
//   - DD = 2-digit day (01-31)
//   - HH = 2-digit hour (00-23)
//   - mm = 2-digit minute (00-59)
//   - SS = 2-digit second (00-59)
//   - O = timezone indicator ('+', '-', or 'Z')
//   - HH'mm' = timezone offset hours and minutes
//
// All fields after YYYY are optional.
func ParsePDFDate(dateStr string) (*time.Time, error) {
	if dateStr == "" {
		return nil, nil
	}

	// Trim whitespace
	dateStr = strings.TrimSpace(dateStr)

	// Check for D: prefix
	if !strings.HasPrefix(dateStr, "D:") {
		// Try without prefix
		dateStr = "D:" + dateStr
	}

	matches := pdfDateRegex.FindStringSubmatch(dateStr)
	if matches == nil {
		return nil, nil // Not a valid PDF date, return nil without error
	}

	// Parse year (required)
	year, _ := strconv.Atoi(matches[1])

	// Parse optional fields with defaults
	month := 1
	if matches[2] != "" {
		month, _ = strconv.Atoi(matches[2])
	}

	day := 1
	if matches[3] != "" {
		day, _ = strconv.Atoi(matches[3])
	}

	hour := 0
	if matches[4] != "" {
		hour, _ = strconv.Atoi(matches[4])
	}

	minute := 0
	if matches[5] != "" {
		minute, _ = strconv.Atoi(matches[5])
	}

	second := 0
	if matches[6] != "" {
		second, _ = strconv.Atoi(matches[6])
	}

	// Parse timezone
	var loc *time.Location
	tzSign := matches[7]
	tzHour := matches[8]
	tzMin := matches[9]

	if tzSign == "" || tzSign == "Z" {
		loc = time.UTC
	} else {
		offsetHours := 0
		offsetMins := 0
		if tzHour != "" {
			offsetHours, _ = strconv.Atoi(tzHour)
		}
		if tzMin != "" {
			offsetMins, _ = strconv.Atoi(tzMin)
		}

		totalOffset := (offsetHours*60 + offsetMins) * 60
		if tzSign == "-" {
			totalOffset = -totalOffset
		}

		loc = time.FixedZone("", totalOffset)
	}

	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, loc)
	return &t, nil
}

// ExtractDocumentInfo extracts document metadata from a PDF reader.
// It reads the Info dictionary and page count to populate DocumentInfo.
func ExtractDocumentInfo(pdfReader *reader.PdfFileReader) *DocumentInfo {
	if pdfReader == nil {
		return nil
	}

	info := &DocumentInfo{
		Pages: pdfReader.GetPageCount(),
	}

	// Get the Info dictionary
	infoDict := pdfReader.Info
	if infoDict == nil {
		return info
	}

	// Extract string fields
	info.Title = getStringValue(infoDict, "Title")
	info.Author = getStringValue(infoDict, "Author")
	info.Subject = getStringValue(infoDict, "Subject")
	info.Creator = getStringValue(infoDict, "Creator")
	info.Producer = getStringValue(infoDict, "Producer")
	info.Trapped = infoDict.GetName("Trapped")

	// Extract keywords (may be a single string with comma/semicolon separation)
	keywordsStr := getStringValue(infoDict, "Keywords")
	if keywordsStr != "" {
		info.Keywords = parseKeywords(keywordsStr)
	}

	// Extract dates
	creationDateStr := getStringValue(infoDict, "CreationDate")
	if creationDateStr != "" {
		info.CreationDate, _ = ParsePDFDate(creationDateStr)
	}

	modDateStr := getStringValue(infoDict, "ModDate")
	if modDateStr != "" {
		info.ModDate, _ = ParsePDFDate(modDateStr)
	}

	return info
}

// getStringValue extracts a string value from a dictionary.
// It handles both StringObject and NameObject types.
func getStringValue(dict *generic.DictionaryObject, key string) string {
	if dict == nil {
		return ""
	}

	val := dict.Get(key)
	if val == nil {
		return ""
	}

	// Try StringObject first (most common for Info dictionary)
	if strObj, ok := val.(*generic.StringObject); ok {
		return strObj.Text()
	}

	// Try NameObject (less common but valid)
	if nameObj, ok := val.(generic.NameObject); ok {
		return string(nameObj)
	}

	return ""
}

// parseKeywords splits a keywords string into individual keywords.
// Keywords can be separated by commas, semicolons, or newlines.
func parseKeywords(keywordsStr string) []string {
	if keywordsStr == "" {
		return nil
	}

	// Replace common separators with comma
	keywordsStr = strings.ReplaceAll(keywordsStr, ";", ",")
	keywordsStr = strings.ReplaceAll(keywordsStr, "\n", ",")
	keywordsStr = strings.ReplaceAll(keywordsStr, "\r", ",")

	parts := strings.Split(keywordsStr, ",")
	var keywords []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			keywords = append(keywords, trimmed)
		}
	}

	return keywords
}
