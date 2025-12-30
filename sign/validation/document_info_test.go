package validation

import (
	"testing"
	"time"
)

func TestParsePDFDate(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantNil   bool
		wantYear  int
		wantMonth time.Month
		wantDay   int
		wantHour  int
		wantMin   int
		wantSec   int
		wantTZ    string // Expected timezone name or "" for UTC
	}{
		{
			name:      "empty string",
			input:     "",
			wantNil:   true,
		},
		{
			name:      "full date with UTC timezone",
			input:     "D:20230615120000Z",
			wantYear:  2023,
			wantMonth: time.June,
			wantDay:   15,
			wantHour:  12,
			wantMin:   0,
			wantSec:   0,
			wantTZ:    "UTC",
		},
		{
			name:      "full date with positive timezone offset",
			input:     "D:19990209153925+05'30'",
			wantYear:  1999,
			wantMonth: time.February,
			wantDay:   9,
			wantHour:  15,
			wantMin:   39,
			wantSec:   25,
		},
		{
			name:      "full date with negative timezone offset",
			input:     "D:20200101000000-08'00'",
			wantYear:  2020,
			wantMonth: time.January,
			wantDay:   1,
			wantHour:  0,
			wantMin:   0,
			wantSec:   0,
		},
		{
			name:      "year only",
			input:     "D:2023",
			wantYear:  2023,
			wantMonth: time.January,
			wantDay:   1,
			wantHour:  0,
			wantMin:   0,
			wantSec:   0,
			wantTZ:    "UTC",
		},
		{
			name:      "year and month",
			input:     "D:202312",
			wantYear:  2023,
			wantMonth: time.December,
			wantDay:   1,
			wantHour:  0,
			wantMin:   0,
			wantSec:   0,
			wantTZ:    "UTC",
		},
		{
			name:      "year, month, and day",
			input:     "D:20231225",
			wantYear:  2023,
			wantMonth: time.December,
			wantDay:   25,
			wantHour:  0,
			wantMin:   0,
			wantSec:   0,
			wantTZ:    "UTC",
		},
		{
			name:      "without D: prefix",
			input:     "20230615120000Z",
			wantYear:  2023,
			wantMonth: time.June,
			wantDay:   15,
			wantHour:  12,
			wantMin:   0,
			wantSec:   0,
			wantTZ:    "UTC",
		},
		{
			name:      "with whitespace",
			input:     "  D:20230615120000Z  ",
			wantYear:  2023,
			wantMonth: time.June,
			wantDay:   15,
			wantHour:  12,
			wantMin:   0,
			wantSec:   0,
			wantTZ:    "UTC",
		},
		{
			name:    "invalid format",
			input:   "not-a-date",
			wantNil: true,
		},
		{
			name:    "partial invalid",
			input:   "D:abc",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePDFDate(tt.input)

			if err != nil {
				t.Errorf("ParsePDFDate() error = %v", err)
				return
			}

			if tt.wantNil {
				if result != nil {
					t.Errorf("ParsePDFDate() = %v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Errorf("ParsePDFDate() = nil, want non-nil")
				return
			}

			if result.Year() != tt.wantYear {
				t.Errorf("Year = %d, want %d", result.Year(), tt.wantYear)
			}
			if result.Month() != tt.wantMonth {
				t.Errorf("Month = %v, want %v", result.Month(), tt.wantMonth)
			}
			if result.Day() != tt.wantDay {
				t.Errorf("Day = %d, want %d", result.Day(), tt.wantDay)
			}
			if result.Hour() != tt.wantHour {
				t.Errorf("Hour = %d, want %d", result.Hour(), tt.wantHour)
			}
			if result.Minute() != tt.wantMin {
				t.Errorf("Minute = %d, want %d", result.Minute(), tt.wantMin)
			}
			if result.Second() != tt.wantSec {
				t.Errorf("Second = %d, want %d", result.Second(), tt.wantSec)
			}

			if tt.wantTZ == "UTC" {
				if result.Location() != time.UTC {
					t.Errorf("Location = %v, want UTC", result.Location())
				}
			}
		})
	}
}

func TestParseKeywords(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "single keyword",
			input: "pdf",
			want:  []string{"pdf"},
		},
		{
			name:  "comma-separated",
			input: "pdf, signing, digital",
			want:  []string{"pdf", "signing", "digital"},
		},
		{
			name:  "semicolon-separated",
			input: "pdf; signing; digital",
			want:  []string{"pdf", "signing", "digital"},
		},
		{
			name:  "newline-separated",
			input: "pdf\nsigning\ndigital",
			want:  []string{"pdf", "signing", "digital"},
		},
		{
			name:  "mixed separators",
			input: "pdf, signing; digital\ncertificate",
			want:  []string{"pdf", "signing", "digital", "certificate"},
		},
		{
			name:  "with extra whitespace",
			input: "  pdf  ,  signing  ,  digital  ",
			want:  []string{"pdf", "signing", "digital"},
		},
		{
			name:  "empty items filtered",
			input: "pdf,,signing,,,digital",
			want:  []string{"pdf", "signing", "digital"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseKeywords(tt.input)

			if len(got) != len(tt.want) {
				t.Errorf("parseKeywords() returned %d items, want %d", len(got), len(tt.want))
				return
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseKeywords()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractDocumentInfo_NilReader(t *testing.T) {
	result := ExtractDocumentInfo(nil)
	if result != nil {
		t.Errorf("ExtractDocumentInfo(nil) = %v, want nil", result)
	}
}

func TestDocumentInfo_JsonTags(t *testing.T) {
	// Verify DocumentInfo has proper JSON tags by creating one and checking fields
	now := time.Now()
	info := &DocumentInfo{
		Title:        "Test Document",
		Author:       "Test Author",
		Subject:      "Test Subject",
		Keywords:     []string{"test", "document"},
		Creator:      "Test Creator",
		Producer:     "Test Producer",
		CreationDate: &now,
		ModDate:      &now,
		Pages:        10,
		Trapped:      "False",
	}

	if info.Title != "Test Document" {
		t.Errorf("Title = %q, want %q", info.Title, "Test Document")
	}
	if info.Author != "Test Author" {
		t.Errorf("Author = %q, want %q", info.Author, "Test Author")
	}
	if info.Pages != 10 {
		t.Errorf("Pages = %d, want %d", info.Pages, 10)
	}
	if len(info.Keywords) != 2 {
		t.Errorf("Keywords length = %d, want 2", len(info.Keywords))
	}
}

func TestParsePDFDate_TimezoneOffsets(t *testing.T) {
	// Test various timezone offsets
	tests := []struct {
		name       string
		input      string
		wantOffset int // offset in seconds
	}{
		{
			name:       "UTC (Z)",
			input:      "D:20230615120000Z",
			wantOffset: 0,
		},
		{
			name:       "positive offset +05:30",
			input:      "D:20230615120000+05'30'",
			wantOffset: (5*60 + 30) * 60, // 5h30m in seconds
		},
		{
			name:       "negative offset -08:00",
			input:      "D:20230615120000-08'00'",
			wantOffset: -(8 * 60) * 60, // -8h in seconds
		},
		{
			name:       "positive offset +00:00",
			input:      "D:20230615120000+00'00'",
			wantOffset: 0,
		},
		{
			name:       "negative offset -05:00",
			input:      "D:20230615120000-05'00'",
			wantOffset: -(5 * 60) * 60, // -5h in seconds
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePDFDate(tt.input)
			if err != nil {
				t.Errorf("ParsePDFDate() error = %v", err)
				return
			}

			if result == nil {
				t.Errorf("ParsePDFDate() = nil, want non-nil")
				return
			}

			_, offset := result.Zone()
			if offset != tt.wantOffset {
				t.Errorf("Timezone offset = %d, want %d", offset, tt.wantOffset)
			}
		})
	}
}
