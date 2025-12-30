// Package report provides validation report tools.
package report

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/georgepadayatti/gopdf/sign/ades"
)

// DiagnosticLevel indicates the level of diagnostic detail.
type DiagnosticLevel int

const (
	DiagnosticMinimal DiagnosticLevel = iota
	DiagnosticNormal
	DiagnosticVerbose
	DiagnosticDebug
)

// String returns the string representation of the diagnostic level.
func (d DiagnosticLevel) String() string {
	switch d {
	case DiagnosticMinimal:
		return "minimal"
	case DiagnosticNormal:
		return "normal"
	case DiagnosticVerbose:
		return "verbose"
	case DiagnosticDebug:
		return "debug"
	default:
		return "unknown"
	}
}

// DiagnosticItem represents a single diagnostic entry.
type DiagnosticItem struct {
	Timestamp time.Time
	Level     DiagnosticLevel
	Category  string
	Message   string
	Details   map[string]interface{}
}

// DiagnosticReport collects diagnostic information during validation.
type DiagnosticReport struct {
	mu        sync.RWMutex
	items     []*DiagnosticItem
	startTime time.Time
	endTime   time.Time
	minLevel  DiagnosticLevel
}

// NewDiagnosticReport creates a new diagnostic report.
func NewDiagnosticReport(minLevel DiagnosticLevel) *DiagnosticReport {
	return &DiagnosticReport{
		items:     make([]*DiagnosticItem, 0),
		startTime: time.Now(),
		minLevel:  minLevel,
	}
}

// Add adds a diagnostic item.
func (r *DiagnosticReport) Add(level DiagnosticLevel, category, message string) {
	if level < r.minLevel {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.items = append(r.items, &DiagnosticItem{
		Timestamp: time.Now(),
		Level:     level,
		Category:  category,
		Message:   message,
	})
}

// AddWithDetails adds a diagnostic item with additional details.
func (r *DiagnosticReport) AddWithDetails(level DiagnosticLevel, category, message string, details map[string]interface{}) {
	if level < r.minLevel {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.items = append(r.items, &DiagnosticItem{
		Timestamp: time.Now(),
		Level:     level,
		Category:  category,
		Message:   message,
		Details:   details,
	})
}

// Complete marks the diagnostic report as complete.
func (r *DiagnosticReport) Complete() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endTime = time.Now()
}

// Duration returns the duration of the diagnostic collection.
func (r *DiagnosticReport) Duration() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	end := r.endTime
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(r.startTime)
}

// Items returns all diagnostic items.
func (r *DiagnosticReport) Items() []*DiagnosticItem {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*DiagnosticItem, len(r.items))
	copy(result, r.items)
	return result
}

// ItemsByCategory returns items filtered by category.
func (r *DiagnosticReport) ItemsByCategory(category string) []*DiagnosticItem {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*DiagnosticItem
	for _, item := range r.items {
		if item.Category == category {
			result = append(result, item)
		}
	}
	return result
}

// ItemsByLevel returns items filtered by minimum level.
func (r *DiagnosticReport) ItemsByLevel(minLevel DiagnosticLevel) []*DiagnosticItem {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*DiagnosticItem
	for _, item := range r.items {
		if item.Level >= minLevel {
			result = append(result, item)
		}
	}
	return result
}

// Categories returns all unique categories.
func (r *DiagnosticReport) Categories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]struct{})
	for _, item := range r.items {
		seen[item.Category] = struct{}{}
	}

	result := make([]string, 0, len(seen))
	for cat := range seen {
		result = append(result, cat)
	}
	sort.Strings(result)
	return result
}

// Format formats the diagnostic report as text.
func (r *DiagnosticReport) Format() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("=== DIAGNOSTIC REPORT ===\n")
	sb.WriteString(fmt.Sprintf("Start: %s\n", r.startTime.Format(time.RFC3339)))
	if !r.endTime.IsZero() {
		sb.WriteString(fmt.Sprintf("End: %s\n", r.endTime.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Duration: %v\n", r.endTime.Sub(r.startTime)))
	}
	sb.WriteString(fmt.Sprintf("Items: %d\n\n", len(r.items)))

	for i, item := range r.items {
		sb.WriteString(fmt.Sprintf("[%d] %s [%s] %s: %s\n",
			i+1,
			item.Timestamp.Format("15:04:05.000"),
			item.Level.String(),
			item.Category,
			item.Message,
		))
		if len(item.Details) > 0 {
			for k, v := range item.Details {
				sb.WriteString(fmt.Sprintf("    %s: %v\n", k, v))
			}
		}
	}

	return sb.String()
}

// ValidationSummary provides a summary of validation results.
type ValidationSummary struct {
	TotalSignatures         int
	PassedSignatures        int
	FailedSignatures        int
	IndeterminateSignatures int

	TotalCertificates   int
	ValidCertificates   int
	ExpiredCertificates int
	RevokedCertificates int

	TotalTimestamps   int
	ValidTimestamps   int
	InvalidTimestamps int

	SignatureLevels map[string]int
	ErrorCounts     map[string]int
	WarningCounts   map[string]int

	ValidationTime    time.Duration
	OverallConclusion string
}

// NewValidationSummary creates a new validation summary.
func NewValidationSummary() *ValidationSummary {
	return &ValidationSummary{
		SignatureLevels: make(map[string]int),
		ErrorCounts:     make(map[string]int),
		WarningCounts:   make(map[string]int),
	}
}

// FromReport generates a summary from a validation report.
func (s *ValidationSummary) FromReport(report *ades.ValidationReport) {
	s.TotalSignatures = report.SignatureCount()
	s.PassedSignatures = report.PassedCount()
	s.FailedSignatures = report.FailedCount()
	s.IndeterminateSignatures = s.TotalSignatures - s.PassedSignatures - s.FailedSignatures

	if report.Conclusion != nil {
		s.OverallConclusion = report.Conclusion.Indication
	}

	for _, sig := range report.SignatureValidation {
		// Count signature levels
		if sig.SignatureLevel != "" {
			s.SignatureLevels[sig.SignatureLevel]++
		}

		// Count certificates
		if sig.SignerCertificate != nil {
			s.TotalCertificates++
			if sig.SignerCertificate.IsValidAt(report.ValidationTime) {
				s.ValidCertificates++
			} else if report.ValidationTime.After(sig.SignerCertificate.NotAfter) {
				s.ExpiredCertificates++
			}
		}
		s.TotalCertificates += len(sig.CertificateChain)
		for _, cert := range sig.CertificateChain {
			if cert.IsValidAt(report.ValidationTime) {
				s.ValidCertificates++
			} else if report.ValidationTime.After(cert.NotAfter) {
				s.ExpiredCertificates++
			}
		}

		// Count timestamps
		s.TotalTimestamps += len(sig.Timestamps)
		for _, ts := range sig.Timestamps {
			if ts.Conclusion != nil && ts.Conclusion.IsPassed() {
				s.ValidTimestamps++
			} else {
				s.InvalidTimestamps++
			}
		}

		// Count errors and warnings
		if sig.Conclusion != nil {
			for _, err := range sig.Conclusion.Errors {
				s.ErrorCounts[err.Key]++
			}
			for _, warn := range sig.Conclusion.Warnings {
				s.WarningCounts[warn.Key]++
			}
		}
	}
}

// Format formats the summary as text.
func (s *ValidationSummary) Format() string {
	var sb strings.Builder

	sb.WriteString("=== VALIDATION SUMMARY ===\n\n")

	sb.WriteString(fmt.Sprintf("Overall Result: %s\n\n", s.OverallConclusion))

	sb.WriteString("Signatures:\n")
	sb.WriteString(fmt.Sprintf("  Total: %d\n", s.TotalSignatures))
	sb.WriteString(fmt.Sprintf("  Passed: %d\n", s.PassedSignatures))
	sb.WriteString(fmt.Sprintf("  Failed: %d\n", s.FailedSignatures))
	sb.WriteString(fmt.Sprintf("  Indeterminate: %d\n\n", s.IndeterminateSignatures))

	if len(s.SignatureLevels) > 0 {
		sb.WriteString("Signature Levels:\n")
		for level, count := range s.SignatureLevels {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", level, count))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Certificates:\n")
	sb.WriteString(fmt.Sprintf("  Total: %d\n", s.TotalCertificates))
	sb.WriteString(fmt.Sprintf("  Valid: %d\n", s.ValidCertificates))
	sb.WriteString(fmt.Sprintf("  Expired: %d\n", s.ExpiredCertificates))
	sb.WriteString(fmt.Sprintf("  Revoked: %d\n\n", s.RevokedCertificates))

	if s.TotalTimestamps > 0 {
		sb.WriteString("Timestamps:\n")
		sb.WriteString(fmt.Sprintf("  Total: %d\n", s.TotalTimestamps))
		sb.WriteString(fmt.Sprintf("  Valid: %d\n", s.ValidTimestamps))
		sb.WriteString(fmt.Sprintf("  Invalid: %d\n\n", s.InvalidTimestamps))
	}

	if len(s.ErrorCounts) > 0 {
		sb.WriteString("Errors:\n")
		for key, count := range s.ErrorCounts {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", key, count))
		}
		sb.WriteString("\n")
	}

	if len(s.WarningCounts) > 0 {
		sb.WriteString("Warnings:\n")
		for key, count := range s.WarningCounts {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", key, count))
		}
	}

	if s.ValidationTime > 0 {
		sb.WriteString(fmt.Sprintf("\nValidation Time: %v\n", s.ValidationTime))
	}

	return sb.String()
}

// ReportFormatter provides different output formats for validation reports.
type ReportFormatter struct {
	// Options
	IncludeDiagnostics bool
	IncludeCertChain   bool
	IncludeTimestamps  bool
	IncludeRevocation  bool
	MaxChainDepth      int
	DateFormat         string
}

// NewReportFormatter creates a new report formatter with defaults.
func NewReportFormatter() *ReportFormatter {
	return &ReportFormatter{
		IncludeDiagnostics: false,
		IncludeCertChain:   true,
		IncludeTimestamps:  true,
		IncludeRevocation:  true,
		MaxChainDepth:      10,
		DateFormat:         time.RFC3339,
	}
}

// FormatAsText formats the report as plain text.
func (f *ReportFormatter) FormatAsText(report *ades.ValidationReport) string {
	return report.ToSimpleText(&ades.SimpleReportFormat{
		IncludeDetails:    true,
		IncludeChain:      f.IncludeCertChain,
		IncludeTimestamps: f.IncludeTimestamps,
	})
}

// FormatAsHTML formats the report as HTML.
func (f *ReportFormatter) FormatAsHTML(report *ades.ValidationReport) string {
	var sb strings.Builder

	sb.WriteString("<!DOCTYPE html>\n<html>\n<head>\n")
	sb.WriteString("<title>Validation Report</title>\n")
	sb.WriteString("<style>\n")
	sb.WriteString("body { font-family: Arial, sans-serif; margin: 20px; }\n")
	sb.WriteString(".passed { color: green; }\n")
	sb.WriteString(".failed { color: red; }\n")
	sb.WriteString(".indeterminate { color: orange; }\n")
	sb.WriteString("table { border-collapse: collapse; width: 100%; margin: 10px 0; }\n")
	sb.WriteString("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n")
	sb.WriteString("th { background-color: #4CAF50; color: white; }\n")
	sb.WriteString(".section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }\n")
	sb.WriteString("h1, h2, h3 { color: #333; }\n")
	sb.WriteString("</style>\n")
	sb.WriteString("</head>\n<body>\n")

	sb.WriteString("<h1>Validation Report</h1>\n")

	// Document info
	if report.DocumentInfo != nil {
		sb.WriteString("<div class=\"section\">\n")
		sb.WriteString("<h2>Document Information</h2>\n")
		sb.WriteString(fmt.Sprintf("<p><strong>Filename:</strong> %s</p>\n", report.DocumentInfo.Filename))
		sb.WriteString(fmt.Sprintf("<p><strong>MIME Type:</strong> %s</p>\n", report.DocumentInfo.MimeType))
		if report.DocumentInfo.Size > 0 {
			sb.WriteString(fmt.Sprintf("<p><strong>Size:</strong> %d bytes</p>\n", report.DocumentInfo.Size))
		}
		sb.WriteString("</div>\n")
	}

	// Overall conclusion
	conclusionClass := "indeterminate"
	if report.Conclusion != nil {
		if report.Conclusion.IsPassed() {
			conclusionClass = "passed"
		} else if report.Conclusion.IsFailed() {
			conclusionClass = "failed"
		}
	}
	sb.WriteString("<div class=\"section\">\n")
	sb.WriteString("<h2>Overall Result</h2>\n")
	sb.WriteString(fmt.Sprintf("<p class=\"%s\"><strong>%s</strong>", conclusionClass, report.Conclusion.Indication))
	if report.Conclusion.SubIndication != "" {
		sb.WriteString(fmt.Sprintf(" (%s)", report.Conclusion.SubIndication))
	}
	sb.WriteString("</p>\n")
	sb.WriteString(fmt.Sprintf("<p>Validation Time: %s</p>\n", report.ValidationTime.Format(f.DateFormat)))
	sb.WriteString("</div>\n")

	// Signatures
	if len(report.SignatureValidation) > 0 {
		sb.WriteString("<div class=\"section\">\n")
		sb.WriteString("<h2>Signatures</h2>\n")
		sb.WriteString("<table>\n")
		sb.WriteString("<tr><th>#</th><th>ID</th><th>Format</th><th>Level</th><th>Signer</th><th>Result</th></tr>\n")

		for i, sig := range report.SignatureValidation {
			sigClass := "indeterminate"
			result := "UNKNOWN"
			if sig.Conclusion != nil {
				result = sig.Conclusion.Indication
				if sig.Conclusion.IsPassed() {
					sigClass = "passed"
				} else if sig.Conclusion.IsFailed() {
					sigClass = "failed"
				}
			}

			signer := ""
			if sig.SignerCertificate != nil {
				signer = sig.SignerCertificate.Subject
			}

			sb.WriteString(fmt.Sprintf("<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td></tr>\n",
				i+1, sig.ID, sig.SignatureFormat, sig.SignatureLevel, signer, sigClass, result))
		}
		sb.WriteString("</table>\n")
		sb.WriteString("</div>\n")
	}

	sb.WriteString("</body>\n</html>")
	return sb.String()
}

// FormatAsMarkdown formats the report as Markdown.
func (f *ReportFormatter) FormatAsMarkdown(report *ades.ValidationReport) string {
	var sb strings.Builder

	sb.WriteString("# Validation Report\n\n")

	sb.WriteString(fmt.Sprintf("**Report ID:** %s\n\n", report.ID))
	sb.WriteString(fmt.Sprintf("**Validation Time:** %s\n\n", report.ValidationTime.Format(f.DateFormat)))

	// Document info
	if report.DocumentInfo != nil {
		sb.WriteString("## Document Information\n\n")
		sb.WriteString(fmt.Sprintf("- **Filename:** %s\n", report.DocumentInfo.Filename))
		sb.WriteString(fmt.Sprintf("- **MIME Type:** %s\n", report.DocumentInfo.MimeType))
		if report.DocumentInfo.Size > 0 {
			sb.WriteString(fmt.Sprintf("- **Size:** %d bytes\n", report.DocumentInfo.Size))
		}
		sb.WriteString("\n")
	}

	// Overall result
	sb.WriteString("## Overall Result\n\n")
	indicator := ""
	if report.Conclusion != nil {
		switch {
		case report.Conclusion.IsPassed():
			indicator = " :white_check_mark:"
		case report.Conclusion.IsFailed():
			indicator = " :x:"
		default:
			indicator = " :warning:"
		}
		sb.WriteString(fmt.Sprintf("**%s**%s\n\n", report.Conclusion.Indication, indicator))
		if report.Conclusion.SubIndication != "" {
			sb.WriteString(fmt.Sprintf("*Sub-indication:* %s\n\n", report.Conclusion.SubIndication))
		}
	}

	// Signatures
	if len(report.SignatureValidation) > 0 {
		sb.WriteString("## Signatures\n\n")
		sb.WriteString("| # | ID | Format | Level | Signer | Result |\n")
		sb.WriteString("|---|-----|--------|-------|--------|--------|\n")

		for i, sig := range report.SignatureValidation {
			result := "UNKNOWN"
			if sig.Conclusion != nil {
				result = sig.Conclusion.Indication
			}

			signer := ""
			if sig.SignerCertificate != nil {
				signer = sig.SignerCertificate.Subject
				// Truncate long subjects
				if len(signer) > 40 {
					signer = signer[:37] + "..."
				}
			}

			sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s | %s |\n",
				i+1, sig.ID, sig.SignatureFormat, sig.SignatureLevel, signer, result))
		}
		sb.WriteString("\n")

		// Detailed signature info
		for i, sig := range report.SignatureValidation {
			sb.WriteString(fmt.Sprintf("### Signature %d\n\n", i+1))
			sb.WriteString(fmt.Sprintf("- **ID:** %s\n", sig.ID))
			sb.WriteString(fmt.Sprintf("- **Format:** %s\n", sig.SignatureFormat))
			if sig.SignatureLevel != "" {
				sb.WriteString(fmt.Sprintf("- **Level:** %s\n", sig.SignatureLevel))
			}
			if sig.SigningTime != nil {
				sb.WriteString(fmt.Sprintf("- **Signing Time:** %s\n", sig.SigningTime.Format(f.DateFormat)))
			}

			if sig.SignerCertificate != nil {
				sb.WriteString(fmt.Sprintf("\n**Signer Certificate:**\n"))
				sb.WriteString(fmt.Sprintf("- Subject: `%s`\n", sig.SignerCertificate.Subject))
				sb.WriteString(fmt.Sprintf("- Issuer: `%s`\n", sig.SignerCertificate.Issuer))
				sb.WriteString(fmt.Sprintf("- Valid: %s to %s\n",
					sig.SignerCertificate.NotBefore.Format("2006-01-02"),
					sig.SignerCertificate.NotAfter.Format("2006-01-02")))
			}

			if f.IncludeTimestamps && len(sig.Timestamps) > 0 {
				sb.WriteString("\n**Timestamps:**\n")
				for _, ts := range sig.Timestamps {
					sb.WriteString(fmt.Sprintf("- %s: %s\n", ts.Type, ts.ProductionTime.Format(f.DateFormat)))
				}
			}

			if sig.Conclusion != nil {
				sb.WriteString(fmt.Sprintf("\n**Result:** %s\n", sig.Conclusion.Indication))
				if len(sig.Conclusion.Errors) > 0 {
					sb.WriteString("\n*Errors:*\n")
					for _, err := range sig.Conclusion.Errors {
						sb.WriteString(fmt.Sprintf("- %s: %s\n", err.Key, err.Value))
					}
				}
				if len(sig.Conclusion.Warnings) > 0 {
					sb.WriteString("\n*Warnings:*\n")
					for _, warn := range sig.Conclusion.Warnings {
						sb.WriteString(fmt.Sprintf("- %s: %s\n", warn.Key, warn.Value))
					}
				}
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// WriteTo writes the formatted report to the given writer.
func (f *ReportFormatter) WriteTo(w io.Writer, report *ades.ValidationReport, format string) error {
	var output string
	switch strings.ToLower(format) {
	case "html":
		output = f.FormatAsHTML(report)
	case "markdown", "md":
		output = f.FormatAsMarkdown(report)
	case "json":
		data, err := report.ToJSON()
		if err != nil {
			return err
		}
		output = string(data)
	case "xml":
		data, err := report.ToXML()
		if err != nil {
			return err
		}
		output = string(data)
	default:
		output = f.FormatAsText(report)
	}

	_, err := w.Write([]byte(output))
	return err
}

// ChainVisualizer creates visual representations of certificate chains.
type ChainVisualizer struct {
	ShowDates     bool
	ShowKeyUsage  bool
	ShowSerialNum bool
	IndentWidth   int
}

// NewChainVisualizer creates a new chain visualizer.
func NewChainVisualizer() *ChainVisualizer {
	return &ChainVisualizer{
		ShowDates:     true,
		ShowKeyUsage:  false,
		ShowSerialNum: false,
		IndentWidth:   4,
	}
}

// Visualize creates a text visualization of a certificate chain.
func (v *ChainVisualizer) Visualize(chain []*ades.CertificateInfo) string {
	if len(chain) == 0 {
		return "(empty chain)"
	}

	var sb strings.Builder
	indent := strings.Repeat(" ", v.IndentWidth)

	for i, cert := range chain {
		prefix := strings.Repeat(indent, i)
		if i == 0 {
			sb.WriteString(prefix + "[Root/Issuer]\n")
		} else if i == len(chain)-1 {
			sb.WriteString(prefix + "[End Entity]\n")
		} else {
			sb.WriteString(prefix + "[Intermediate]\n")
		}

		sb.WriteString(prefix + "  Subject: " + cert.Subject + "\n")
		if cert.Issuer != cert.Subject {
			sb.WriteString(prefix + "  Issuer: " + cert.Issuer + "\n")
		}

		if v.ShowDates {
			sb.WriteString(prefix + fmt.Sprintf("  Valid: %s to %s\n",
				cert.NotBefore.Format("2006-01-02"),
				cert.NotAfter.Format("2006-01-02")))
		}

		if v.ShowSerialNum {
			sb.WriteString(prefix + "  Serial: " + cert.SerialNumber + "\n")
		}

		if v.ShowKeyUsage && len(cert.KeyUsage) > 0 {
			sb.WriteString(prefix + "  Key Usage: " + strings.Join(cert.KeyUsage, ", ") + "\n")
		}

		if cert.IsCA {
			sb.WriteString(prefix + "  [CA]\n")
		}
		if cert.IsSelfSigned {
			sb.WriteString(prefix + "  [Self-Signed]\n")
		}

		if i < len(chain)-1 {
			sb.WriteString(prefix + "  |\n")
			sb.WriteString(prefix + "  v\n")
		}
	}

	return sb.String()
}

// VisualizeFromX509 creates a visualization from x509 certificates.
func (v *ChainVisualizer) VisualizeFromX509(chain []*x509.Certificate) string {
	infoChain := make([]*ades.CertificateInfo, len(chain))
	for i, cert := range chain {
		infoChain[i] = ades.NewCertificateInfo(cert, fmt.Sprintf("cert-%d", i))
	}
	return v.Visualize(infoChain)
}

// ReportComparator compares two validation reports.
type ReportComparator struct{}

// Difference represents a difference between reports.
type Difference struct {
	Path     string
	OldValue interface{}
	NewValue interface{}
	Type     DifferenceType
}

// DifferenceType indicates the type of difference.
type DifferenceType int

const (
	DiffAdded DifferenceType = iota
	DiffRemoved
	DiffChanged
)

// String returns the string representation.
func (d DifferenceType) String() string {
	switch d {
	case DiffAdded:
		return "ADDED"
	case DiffRemoved:
		return "REMOVED"
	case DiffChanged:
		return "CHANGED"
	default:
		return "UNKNOWN"
	}
}

// ComparisonResult contains the comparison results.
type ComparisonResult struct {
	AreEqual    bool
	Differences []*Difference
	Report1ID   string
	Report2ID   string
}

// NewReportComparator creates a new comparator.
func NewReportComparator() *ReportComparator {
	return &ReportComparator{}
}

// Compare compares two validation reports.
func (c *ReportComparator) Compare(report1, report2 *ades.ValidationReport) *ComparisonResult {
	result := &ComparisonResult{
		AreEqual:  true,
		Report1ID: report1.ID,
		Report2ID: report2.ID,
	}

	// Compare overall conclusions
	if report1.Conclusion != nil && report2.Conclusion != nil {
		if report1.Conclusion.Indication != report2.Conclusion.Indication {
			result.AreEqual = false
			result.Differences = append(result.Differences, &Difference{
				Path:     "Conclusion.Indication",
				OldValue: report1.Conclusion.Indication,
				NewValue: report2.Conclusion.Indication,
				Type:     DiffChanged,
			})
		}
		if report1.Conclusion.SubIndication != report2.Conclusion.SubIndication {
			result.AreEqual = false
			result.Differences = append(result.Differences, &Difference{
				Path:     "Conclusion.SubIndication",
				OldValue: report1.Conclusion.SubIndication,
				NewValue: report2.Conclusion.SubIndication,
				Type:     DiffChanged,
			})
		}
	}

	// Compare signature counts
	if report1.SignatureCount() != report2.SignatureCount() {
		result.AreEqual = false
		result.Differences = append(result.Differences, &Difference{
			Path:     "SignatureCount",
			OldValue: report1.SignatureCount(),
			NewValue: report2.SignatureCount(),
			Type:     DiffChanged,
		})
	}

	// Compare individual signatures
	sigMap1 := make(map[string]*ades.SignatureInfo)
	for _, sig := range report1.SignatureValidation {
		sigMap1[sig.ID] = sig
	}

	sigMap2 := make(map[string]*ades.SignatureInfo)
	for _, sig := range report2.SignatureValidation {
		sigMap2[sig.ID] = sig
	}

	// Find added/removed signatures
	for id := range sigMap1 {
		if _, exists := sigMap2[id]; !exists {
			result.AreEqual = false
			result.Differences = append(result.Differences, &Difference{
				Path:     fmt.Sprintf("Signature[%s]", id),
				OldValue: sigMap1[id],
				NewValue: nil,
				Type:     DiffRemoved,
			})
		}
	}

	for id := range sigMap2 {
		if _, exists := sigMap1[id]; !exists {
			result.AreEqual = false
			result.Differences = append(result.Differences, &Difference{
				Path:     fmt.Sprintf("Signature[%s]", id),
				OldValue: nil,
				NewValue: sigMap2[id],
				Type:     DiffAdded,
			})
		}
	}

	// Compare matching signatures
	for id, sig1 := range sigMap1 {
		if sig2, exists := sigMap2[id]; exists {
			c.compareSignatures(sig1, sig2, id, result)
		}
	}

	return result
}

// compareSignatures compares two signature infos.
func (c *ReportComparator) compareSignatures(sig1, sig2 *ades.SignatureInfo, id string, result *ComparisonResult) {
	prefix := fmt.Sprintf("Signature[%s]", id)

	if sig1.SignatureFormat != sig2.SignatureFormat {
		result.AreEqual = false
		result.Differences = append(result.Differences, &Difference{
			Path:     prefix + ".Format",
			OldValue: sig1.SignatureFormat,
			NewValue: sig2.SignatureFormat,
			Type:     DiffChanged,
		})
	}

	if sig1.SignatureLevel != sig2.SignatureLevel {
		result.AreEqual = false
		result.Differences = append(result.Differences, &Difference{
			Path:     prefix + ".Level",
			OldValue: sig1.SignatureLevel,
			NewValue: sig2.SignatureLevel,
			Type:     DiffChanged,
		})
	}

	if sig1.Conclusion != nil && sig2.Conclusion != nil {
		if sig1.Conclusion.Indication != sig2.Conclusion.Indication {
			result.AreEqual = false
			result.Differences = append(result.Differences, &Difference{
				Path:     prefix + ".Conclusion.Indication",
				OldValue: sig1.Conclusion.Indication,
				NewValue: sig2.Conclusion.Indication,
				Type:     DiffChanged,
			})
		}
	}
}

// Format formats the comparison result.
func (r *ComparisonResult) Format() string {
	var sb strings.Builder

	sb.WriteString("=== REPORT COMPARISON ===\n\n")
	sb.WriteString(fmt.Sprintf("Report 1: %s\n", r.Report1ID))
	sb.WriteString(fmt.Sprintf("Report 2: %s\n\n", r.Report2ID))

	if r.AreEqual {
		sb.WriteString("Result: IDENTICAL\n")
	} else {
		sb.WriteString(fmt.Sprintf("Result: DIFFERENT (%d differences)\n\n", len(r.Differences)))

		for _, diff := range r.Differences {
			sb.WriteString(fmt.Sprintf("[%s] %s\n", diff.Type.String(), diff.Path))
			if diff.OldValue != nil {
				sb.WriteString(fmt.Sprintf("  Old: %v\n", diff.OldValue))
			}
			if diff.NewValue != nil {
				sb.WriteString(fmt.Sprintf("  New: %v\n", diff.NewValue))
			}
		}
	}

	return sb.String()
}

// PolicyComplianceChecker checks report compliance against policies.
type PolicyComplianceChecker struct {
	RequiredLevel      string
	AllowExpired       bool
	AllowIndeterminate bool
	RequireTimestamp   bool
	RequireRevocation  bool
	MinSignatures      int
}

// NewPolicyComplianceChecker creates a new compliance checker.
func NewPolicyComplianceChecker() *PolicyComplianceChecker {
	return &PolicyComplianceChecker{
		RequiredLevel:      "",
		AllowExpired:       false,
		AllowIndeterminate: false,
		RequireTimestamp:   false,
		RequireRevocation:  false,
		MinSignatures:      1,
	}
}

// ComplianceResult contains compliance check results.
type ComplianceResult struct {
	IsCompliant bool
	Violations  []string
	Warnings    []string
}

// CheckCompliance checks if the report complies with the policy.
func (p *PolicyComplianceChecker) CheckCompliance(report *ades.ValidationReport) *ComplianceResult {
	result := &ComplianceResult{
		IsCompliant: true,
	}

	// Check minimum signatures
	if report.SignatureCount() < p.MinSignatures {
		result.IsCompliant = false
		result.Violations = append(result.Violations,
			fmt.Sprintf("Minimum %d signature(s) required, found %d",
				p.MinSignatures, report.SignatureCount()))
	}

	// Check overall result
	if report.Conclusion != nil {
		if report.Conclusion.IsFailed() {
			result.IsCompliant = false
			result.Violations = append(result.Violations,
				fmt.Sprintf("Validation failed: %s", report.Conclusion.SubIndication))
		} else if report.Conclusion.IsIndeterminate() && !p.AllowIndeterminate {
			result.IsCompliant = false
			result.Violations = append(result.Violations,
				"Indeterminate results not allowed by policy")
		}
	}

	// Check individual signatures
	for i, sig := range report.SignatureValidation {
		// Check required level
		if p.RequiredLevel != "" && sig.SignatureLevel != p.RequiredLevel {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Signature %d: level %s does not match required %s",
					i+1, sig.SignatureLevel, p.RequiredLevel))
		}

		// Check timestamp requirement
		if p.RequireTimestamp && len(sig.Timestamps) == 0 {
			result.IsCompliant = false
			result.Violations = append(result.Violations,
				fmt.Sprintf("Signature %d: timestamp required but not found", i+1))
		}

		// Check revocation data requirement
		if p.RequireRevocation && len(sig.RevocationData) == 0 {
			result.IsCompliant = false
			result.Violations = append(result.Violations,
				fmt.Sprintf("Signature %d: revocation data required but not found", i+1))
		}

		// Check certificate validity
		if sig.SignerCertificate != nil && !p.AllowExpired {
			if !sig.SignerCertificate.IsValidAt(report.ValidationTime) {
				result.IsCompliant = false
				result.Violations = append(result.Violations,
					fmt.Sprintf("Signature %d: certificate not valid at validation time", i+1))
			}
		}
	}

	return result
}

// Format formats the compliance result.
func (r *ComplianceResult) Format() string {
	var sb strings.Builder

	sb.WriteString("=== POLICY COMPLIANCE ===\n\n")

	if r.IsCompliant {
		sb.WriteString("Status: COMPLIANT\n")
	} else {
		sb.WriteString("Status: NON-COMPLIANT\n")
	}

	if len(r.Violations) > 0 {
		sb.WriteString("\nViolations:\n")
		for _, v := range r.Violations {
			sb.WriteString("  - " + v + "\n")
		}
	}

	if len(r.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range r.Warnings {
			sb.WriteString("  - " + w + "\n")
		}
	}

	return sb.String()
}

// CertificateDetails provides detailed certificate information.
type CertificateDetails struct {
	Subject        string
	Issuer         string
	SerialNumber   string
	NotBefore      time.Time
	NotAfter       time.Time
	SignatureAlgo  string
	PublicKeyAlgo  string
	KeySize        int
	Fingerprint    string
	SubjectKeyID   string
	AuthorityKeyID string
	KeyUsages      []string
	ExtKeyUsages   []string
	PolicyOIDs     []string
	IsCA           bool
	IsSelfSigned   bool
	CRLDistPoints  []string
	OCSPServers    []string
	IssuingCertURL []string
}

// ExtractCertificateDetails extracts detailed information from an x509 certificate.
func ExtractCertificateDetails(cert *x509.Certificate) *CertificateDetails {
	details := &CertificateDetails{
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		SerialNumber:   cert.SerialNumber.String(),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		SignatureAlgo:  cert.SignatureAlgorithm.String(),
		PublicKeyAlgo:  cert.PublicKeyAlgorithm.String(),
		IsCA:           cert.IsCA,
		IsSelfSigned:   cert.CheckSignatureFrom(cert) == nil,
		CRLDistPoints:  cert.CRLDistributionPoints,
		OCSPServers:    cert.OCSPServer,
		IssuingCertURL: cert.IssuingCertificateURL,
	}

	// Subject/Authority Key IDs
	if len(cert.SubjectKeyId) > 0 {
		details.SubjectKeyID = hex.EncodeToString(cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		details.AuthorityKeyID = hex.EncodeToString(cert.AuthorityKeyId)
	}

	// Key usages
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		details.KeyUsages = append(details.KeyUsages, "digitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		details.KeyUsages = append(details.KeyUsages, "contentCommitment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		details.KeyUsages = append(details.KeyUsages, "keyEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		details.KeyUsages = append(details.KeyUsages, "dataEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		details.KeyUsages = append(details.KeyUsages, "keyAgreement")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		details.KeyUsages = append(details.KeyUsages, "keyCertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		details.KeyUsages = append(details.KeyUsages, "cRLSign")
	}

	// Extended key usages
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			details.ExtKeyUsages = append(details.ExtKeyUsages, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			details.ExtKeyUsages = append(details.ExtKeyUsages, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			details.ExtKeyUsages = append(details.ExtKeyUsages, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			details.ExtKeyUsages = append(details.ExtKeyUsages, "emailProtection")
		case x509.ExtKeyUsageTimeStamping:
			details.ExtKeyUsages = append(details.ExtKeyUsages, "timeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			details.ExtKeyUsages = append(details.ExtKeyUsages, "OCSPSigning")
		}
	}

	// Policy OIDs
	for _, policy := range cert.PolicyIdentifiers {
		details.PolicyOIDs = append(details.PolicyOIDs, policy.String())
	}

	return details
}

// Format formats the certificate details.
func (d *CertificateDetails) Format() string {
	var sb strings.Builder

	sb.WriteString("Certificate Details:\n")
	sb.WriteString(fmt.Sprintf("  Subject: %s\n", d.Subject))
	sb.WriteString(fmt.Sprintf("  Issuer: %s\n", d.Issuer))
	sb.WriteString(fmt.Sprintf("  Serial Number: %s\n", d.SerialNumber))
	sb.WriteString(fmt.Sprintf("  Valid From: %s\n", d.NotBefore.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("  Valid To: %s\n", d.NotAfter.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("  Signature Algorithm: %s\n", d.SignatureAlgo))
	sb.WriteString(fmt.Sprintf("  Public Key Algorithm: %s\n", d.PublicKeyAlgo))

	if d.SubjectKeyID != "" {
		sb.WriteString(fmt.Sprintf("  Subject Key ID: %s\n", d.SubjectKeyID))
	}
	if d.AuthorityKeyID != "" {
		sb.WriteString(fmt.Sprintf("  Authority Key ID: %s\n", d.AuthorityKeyID))
	}

	if len(d.KeyUsages) > 0 {
		sb.WriteString(fmt.Sprintf("  Key Usage: %s\n", strings.Join(d.KeyUsages, ", ")))
	}
	if len(d.ExtKeyUsages) > 0 {
		sb.WriteString(fmt.Sprintf("  Extended Key Usage: %s\n", strings.Join(d.ExtKeyUsages, ", ")))
	}
	if len(d.PolicyOIDs) > 0 {
		sb.WriteString(fmt.Sprintf("  Policy OIDs: %s\n", strings.Join(d.PolicyOIDs, ", ")))
	}

	sb.WriteString(fmt.Sprintf("  Is CA: %v\n", d.IsCA))
	sb.WriteString(fmt.Sprintf("  Is Self-Signed: %v\n", d.IsSelfSigned))

	if len(d.CRLDistPoints) > 0 {
		sb.WriteString("  CRL Distribution Points:\n")
		for _, url := range d.CRLDistPoints {
			sb.WriteString(fmt.Sprintf("    - %s\n", url))
		}
	}
	if len(d.OCSPServers) > 0 {
		sb.WriteString("  OCSP Servers:\n")
		for _, url := range d.OCSPServers {
			sb.WriteString(fmt.Sprintf("    - %s\n", url))
		}
	}

	return sb.String()
}

// ReportAggregator aggregates multiple reports.
type ReportAggregator struct {
	reports []*ades.ValidationReport
}

// NewReportAggregator creates a new aggregator.
func NewReportAggregator() *ReportAggregator {
	return &ReportAggregator{
		reports: make([]*ades.ValidationReport, 0),
	}
}

// Add adds a report to the aggregator.
func (a *ReportAggregator) Add(report *ades.ValidationReport) {
	a.reports = append(a.reports, report)
}

// Count returns the number of reports.
func (a *ReportAggregator) Count() int {
	return len(a.reports)
}

// GetSummary returns an aggregated summary.
func (a *ReportAggregator) GetSummary() *ValidationSummary {
	summary := NewValidationSummary()

	for _, report := range a.reports {
		reportSummary := NewValidationSummary()
		reportSummary.FromReport(report)

		summary.TotalSignatures += reportSummary.TotalSignatures
		summary.PassedSignatures += reportSummary.PassedSignatures
		summary.FailedSignatures += reportSummary.FailedSignatures
		summary.IndeterminateSignatures += reportSummary.IndeterminateSignatures
		summary.TotalCertificates += reportSummary.TotalCertificates
		summary.ValidCertificates += reportSummary.ValidCertificates
		summary.ExpiredCertificates += reportSummary.ExpiredCertificates
		summary.RevokedCertificates += reportSummary.RevokedCertificates
		summary.TotalTimestamps += reportSummary.TotalTimestamps
		summary.ValidTimestamps += reportSummary.ValidTimestamps
		summary.InvalidTimestamps += reportSummary.InvalidTimestamps

		for level, count := range reportSummary.SignatureLevels {
			summary.SignatureLevels[level] += count
		}
		for key, count := range reportSummary.ErrorCounts {
			summary.ErrorCounts[key] += count
		}
		for key, count := range reportSummary.WarningCounts {
			summary.WarningCounts[key] += count
		}
	}

	// Determine overall conclusion
	allPassed := true
	anyFailed := false
	for _, report := range a.reports {
		if report.Conclusion != nil {
			if report.Conclusion.IsFailed() {
				anyFailed = true
			}
			if !report.Conclusion.IsPassed() {
				allPassed = false
			}
		}
	}

	if allPassed && len(a.reports) > 0 {
		summary.OverallConclusion = ades.IndicationPassed
	} else if anyFailed {
		summary.OverallConclusion = ades.IndicationFailed
	} else {
		summary.OverallConclusion = ades.IndicationIndeterminate
	}

	return summary
}

// GetPassedReports returns reports with PASSED conclusion.
func (a *ReportAggregator) GetPassedReports() []*ades.ValidationReport {
	var result []*ades.ValidationReport
	for _, report := range a.reports {
		if report.Conclusion != nil && report.Conclusion.IsPassed() {
			result = append(result, report)
		}
	}
	return result
}

// GetFailedReports returns reports with FAILED conclusion.
func (a *ReportAggregator) GetFailedReports() []*ades.ValidationReport {
	var result []*ades.ValidationReport
	for _, report := range a.reports {
		if report.Conclusion != nil && report.Conclusion.IsFailed() {
			result = append(result, report)
		}
	}
	return result
}
