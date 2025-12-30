// Package qr provides QR code generation for PDF content streams.
package qr

import (
	"bytes"
	"fmt"
	"math"
)

// ErrorCorrectionLevel represents the error correction level for QR codes.
type ErrorCorrectionLevel int

const (
	// ECLevelL provides ~7% error correction
	ECLevelL ErrorCorrectionLevel = iota
	// ECLevelM provides ~15% error correction
	ECLevelM
	// ECLevelQ provides ~25% error correction
	ECLevelQ
	// ECLevelH provides ~30% error correction
	ECLevelH
)

// QRCode represents a QR code.
type QRCode struct {
	Version int
	ECLevel ErrorCorrectionLevel
	Modules [][]bool
	Size    int
	BoxSize float64
	Border  int
	QRColor [3]float64 // RGB color for QR modules
}

// NewQRCode creates a new QR code from data.
func NewQRCode(data string, ecLevel ErrorCorrectionLevel) *QRCode {
	// Determine minimum version needed for the data
	version := determineVersion(data, ecLevel)

	// Generate the QR code
	qr := &QRCode{
		Version: version,
		ECLevel: ecLevel,
		BoxSize: 1.0,
		Border:  4,
		QRColor: [3]float64{0, 0, 0}, // Default black
	}

	qr.Size = 4*version + 17
	qr.Modules = make([][]bool, qr.Size)
	for i := range qr.Modules {
		qr.Modules[i] = make([]bool, qr.Size)
	}

	// Generate QR code modules
	qr.generate(data)

	return qr
}

// determineVersion determines the minimum QR version for the given data and EC level.
func determineVersion(data string, ecLevel ErrorCorrectionLevel) int {
	dataLen := len(data)

	// Simplified version selection based on data length
	// Using byte mode capacity
	capacities := map[ErrorCorrectionLevel][]int{
		ECLevelL: {17, 32, 53, 78, 106, 134, 154, 192, 230, 271, 321, 367, 425, 458, 520, 586, 644, 718, 792, 858},
		ECLevelM: {14, 26, 42, 62, 84, 106, 122, 152, 180, 213, 251, 287, 331, 362, 412, 450, 504, 560, 624, 666},
		ECLevelQ: {11, 20, 32, 46, 60, 74, 86, 108, 130, 151, 177, 203, 241, 258, 292, 322, 364, 394, 442, 482},
		ECLevelH: {7, 14, 24, 34, 44, 58, 64, 84, 98, 119, 137, 155, 177, 194, 220, 250, 280, 310, 338, 382},
	}

	caps := capacities[ecLevel]
	for v, cap := range caps {
		if dataLen <= cap {
			return v + 1
		}
	}

	// Default to version 20 if data is too long
	return 20
}

// generate creates the QR code modules.
func (qr *QRCode) generate(data string) {
	// Add finder patterns
	qr.addFinderPattern(0, 0)
	qr.addFinderPattern(qr.Size-7, 0)
	qr.addFinderPattern(0, qr.Size-7)

	// Add separators
	qr.addSeparators()

	// Add timing patterns
	qr.addTimingPatterns()

	// Add alignment patterns (for version >= 2)
	if qr.Version >= 2 {
		qr.addAlignmentPatterns()
	}

	// Add dark module
	qr.Modules[4*qr.Version+9][8] = true

	// Reserve format information area
	qr.reserveFormatArea()

	// Reserve version information area (for version >= 7)
	if qr.Version >= 7 {
		qr.reserveVersionArea()
	}

	// Encode data and place in matrix
	qr.encodeAndPlaceData(data)

	// Apply best mask pattern
	qr.applyMask()

	// Add format information
	qr.addFormatInfo()

	// Add version information (for version >= 7)
	if qr.Version >= 7 {
		qr.addVersionInfo()
	}
}

// addFinderPattern adds a finder pattern at the specified position.
func (qr *QRCode) addFinderPattern(row, col int) {
	for r := 0; r < 7; r++ {
		for c := 0; c < 7; c++ {
			if r == 0 || r == 6 || c == 0 || c == 6 ||
				(r >= 2 && r <= 4 && c >= 2 && c <= 4) {
				qr.Modules[row+r][col+c] = true
			}
		}
	}
}

// addSeparators adds separator patterns around finder patterns.
func (qr *QRCode) addSeparators() {
	// Top-left
	for i := 0; i < 8; i++ {
		qr.Modules[7][i] = false
		qr.Modules[i][7] = false
	}

	// Top-right
	for i := 0; i < 8; i++ {
		qr.Modules[7][qr.Size-8+i] = false
		qr.Modules[i][qr.Size-8] = false
	}

	// Bottom-left
	for i := 0; i < 8; i++ {
		qr.Modules[qr.Size-8][i] = false
		qr.Modules[qr.Size-8+i][7] = false
	}
}

// addTimingPatterns adds timing patterns.
func (qr *QRCode) addTimingPatterns() {
	for i := 8; i < qr.Size-8; i++ {
		val := i%2 == 0
		qr.Modules[6][i] = val
		qr.Modules[i][6] = val
	}
}

// getAlignmentPatternPositions returns alignment pattern positions for the version.
func (qr *QRCode) getAlignmentPatternPositions() []int {
	if qr.Version == 1 {
		return nil
	}

	// Alignment pattern positions by version
	positions := [][]int{
		nil,             // version 1
		{6, 18},         // version 2
		{6, 22},         // version 3
		{6, 26},         // version 4
		{6, 30},         // version 5
		{6, 34},         // version 6
		{6, 22, 38},     // version 7
		{6, 24, 42},     // version 8
		{6, 26, 46},     // version 9
		{6, 28, 50},     // version 10
		{6, 30, 54},     // version 11
		{6, 32, 58},     // version 12
		{6, 34, 62},     // version 13
		{6, 26, 46, 66}, // version 14
		{6, 26, 48, 70}, // version 15
		{6, 26, 50, 74}, // version 16
		{6, 30, 54, 78}, // version 17
		{6, 30, 56, 82}, // version 18
		{6, 30, 58, 86}, // version 19
		{6, 34, 62, 90}, // version 20
	}

	if qr.Version > len(positions) {
		return positions[len(positions)-1]
	}
	return positions[qr.Version-1]
}

// addAlignmentPatterns adds alignment patterns.
func (qr *QRCode) addAlignmentPatterns() {
	positions := qr.getAlignmentPatternPositions()
	if positions == nil {
		return
	}

	for _, row := range positions {
		for _, col := range positions {
			// Skip if overlapping with finder patterns
			if (row < 9 && col < 9) ||
				(row < 9 && col > qr.Size-10) ||
				(row > qr.Size-10 && col < 9) {
				continue
			}

			qr.addAlignmentPattern(row, col)
		}
	}
}

// addAlignmentPattern adds a single alignment pattern.
func (qr *QRCode) addAlignmentPattern(centerRow, centerCol int) {
	for r := -2; r <= 2; r++ {
		for c := -2; c <= 2; c++ {
			row := centerRow + r
			col := centerCol + c
			if row >= 0 && row < qr.Size && col >= 0 && col < qr.Size {
				if r == -2 || r == 2 || c == -2 || c == 2 || (r == 0 && c == 0) {
					qr.Modules[row][col] = true
				} else {
					qr.Modules[row][col] = false
				}
			}
		}
	}
}

// reserveFormatArea reserves areas for format information.
func (qr *QRCode) reserveFormatArea() {
	// Around top-left finder pattern
	for i := 0; i < 9; i++ {
		if i != 6 {
			qr.Modules[8][i] = false
			qr.Modules[i][8] = false
		}
	}

	// Around top-right finder pattern
	for i := qr.Size - 8; i < qr.Size; i++ {
		qr.Modules[8][i] = false
	}

	// Around bottom-left finder pattern
	for i := qr.Size - 8; i < qr.Size; i++ {
		qr.Modules[i][8] = false
	}
}

// reserveVersionArea reserves areas for version information.
func (qr *QRCode) reserveVersionArea() {
	// Near bottom-left finder pattern
	for i := 0; i < 6; i++ {
		for j := qr.Size - 11; j < qr.Size-8; j++ {
			qr.Modules[i][j] = false
		}
	}

	// Near top-right finder pattern
	for i := qr.Size - 11; i < qr.Size-8; i++ {
		for j := 0; j < 6; j++ {
			qr.Modules[i][j] = false
		}
	}
}

// encodeAndPlaceData encodes data and places it in the matrix.
func (qr *QRCode) encodeAndPlaceData(data string) {
	// Create data bits (simplified byte mode encoding)
	bits := qr.encodeDataBits(data)

	// Place bits in matrix
	qr.placeBits(bits)
}

// encodeDataBits encodes data as bits.
func (qr *QRCode) encodeDataBits(data string) []bool {
	var bits []bool

	// Mode indicator for byte mode (0100)
	bits = append(bits, false, true, false, false)

	// Character count indicator (8 bits for version 1-9, 16 for 10-26, etc.)
	countBits := 8
	if qr.Version >= 10 {
		countBits = 16
	}

	count := len(data)
	for i := countBits - 1; i >= 0; i-- {
		bits = append(bits, (count>>i)&1 == 1)
	}

	// Data bytes
	for _, b := range []byte(data) {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>i)&1 == 1)
		}
	}

	// Terminator (up to 4 zeros)
	for i := 0; i < 4 && len(bits) < qr.getDataCapacity(); i++ {
		bits = append(bits, false)
	}

	// Pad to byte boundary
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}

	// Add padding bytes
	padBytes := []byte{0xEC, 0x11}
	padIdx := 0
	for len(bits) < qr.getDataCapacity() {
		b := padBytes[padIdx%2]
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>i)&1 == 1)
		}
		padIdx++
	}

	return bits
}

// getDataCapacity returns the data capacity in bits.
func (qr *QRCode) getDataCapacity() int {
	// Simplified capacity calculation
	capacities := map[ErrorCorrectionLevel][]int{
		ECLevelL: {152, 272, 440, 640, 864, 1088, 1248, 1552, 1856, 2192},
		ECLevelM: {128, 224, 352, 512, 688, 864, 992, 1232, 1456, 1728},
		ECLevelQ: {104, 176, 272, 384, 496, 608, 704, 880, 1056, 1232},
		ECLevelH: {72, 128, 208, 288, 368, 480, 528, 688, 800, 976},
	}

	caps := capacities[qr.ECLevel]
	if qr.Version <= len(caps) {
		return caps[qr.Version-1]
	}
	return caps[len(caps)-1]
}

// placeBits places data bits in the matrix.
func (qr *QRCode) placeBits(bits []bool) {
	bitIdx := 0
	upward := true
	col := qr.Size - 1

	for col > 0 {
		// Skip timing pattern column
		if col == 6 {
			col--
		}

		for row := 0; row < qr.Size; row++ {
			actualRow := row
			if upward {
				actualRow = qr.Size - 1 - row
			}

			// Check both columns
			for c := 0; c < 2 && bitIdx < len(bits); c++ {
				actualCol := col - c
				if !qr.isReserved(actualRow, actualCol) {
					qr.Modules[actualRow][actualCol] = bits[bitIdx]
					bitIdx++
				}
			}
		}

		upward = !upward
		col -= 2
	}
}

// isReserved checks if a cell is reserved for function patterns.
func (qr *QRCode) isReserved(row, col int) bool {
	// Finder patterns + separators
	if (row < 9 && col < 9) ||
		(row < 9 && col > qr.Size-9) ||
		(row > qr.Size-9 && col < 9) {
		return true
	}

	// Timing patterns
	if row == 6 || col == 6 {
		return true
	}

	// Alignment patterns
	if qr.isInAlignmentPattern(row, col) {
		return true
	}

	// Version info areas
	if qr.Version >= 7 {
		if (row < 6 && col >= qr.Size-11 && col < qr.Size-8) ||
			(col < 6 && row >= qr.Size-11 && row < qr.Size-8) {
			return true
		}
	}

	return false
}

// isInAlignmentPattern checks if a position is in an alignment pattern.
func (qr *QRCode) isInAlignmentPattern(row, col int) bool {
	positions := qr.getAlignmentPatternPositions()
	if positions == nil {
		return false
	}

	for _, pr := range positions {
		for _, pc := range positions {
			// Skip if overlapping with finder patterns
			if (pr < 9 && pc < 9) ||
				(pr < 9 && pc > qr.Size-10) ||
				(pr > qr.Size-10 && pc < 9) {
				continue
			}

			if row >= pr-2 && row <= pr+2 && col >= pc-2 && col <= pc+2 {
				return true
			}
		}
	}

	return false
}

// applyMask applies a mask pattern to the data modules.
func (qr *QRCode) applyMask() {
	// Use mask pattern 0: (row + col) % 2 == 0
	for row := 0; row < qr.Size; row++ {
		for col := 0; col < qr.Size; col++ {
			if !qr.isReserved(row, col) {
				if (row+col)%2 == 0 {
					qr.Modules[row][col] = !qr.Modules[row][col]
				}
			}
		}
	}
}

// addFormatInfo adds format information to the QR code.
func (qr *QRCode) addFormatInfo() {
	// Format info bits for mask 0
	formatBits := []bool{
		true, false, true, false, true, false, false, false, false, false, true, false, false, true, false,
	}

	// Place around top-left finder pattern
	for i := 0; i < 6; i++ {
		qr.Modules[8][i] = formatBits[i]
	}
	qr.Modules[8][7] = formatBits[6]
	qr.Modules[8][8] = formatBits[7]
	qr.Modules[7][8] = formatBits[8]
	for i := 0; i < 6; i++ {
		qr.Modules[5-i][8] = formatBits[9+i]
	}

	// Place around other finder patterns
	for i := 0; i < 8; i++ {
		qr.Modules[8][qr.Size-8+i] = formatBits[i]
	}
	for i := 0; i < 7; i++ {
		qr.Modules[qr.Size-1-i][8] = formatBits[8+i]
	}
}

// addVersionInfo adds version information for version 7+.
func (qr *QRCode) addVersionInfo() {
	if qr.Version < 7 {
		return
	}

	// Simplified version info
	versionBits := make([]bool, 18)
	v := qr.Version
	for i := 0; i < 6; i++ {
		versionBits[i] = (v>>i)&1 == 1
	}

	// Place near bottom-left finder pattern
	for i := 0; i < 6; i++ {
		for j := 0; j < 3; j++ {
			qr.Modules[i][qr.Size-11+j] = versionBits[i*3+j]
		}
	}

	// Place near top-right finder pattern
	for i := 0; i < 6; i++ {
		for j := 0; j < 3; j++ {
			qr.Modules[qr.Size-11+j][i] = versionBits[i*3+j]
		}
	}
}

// TotalWidth returns the total width including border.
func (qr *QRCode) TotalWidth() float64 {
	return float64(qr.Size+qr.Border*2) * qr.BoxSize
}

// RenderPDF renders the QR code to PDF content stream commands.
func (qr *QRCode) RenderPDF() []byte {
	var buf bytes.Buffer

	// Set up coordinate transformation
	brd := float64(qr.Border) * qr.BoxSize
	ydiff := float64(qr.Size) * qr.BoxSize

	// Set fill color and transform coordinates
	fmt.Fprintf(&buf, "%g %g %g rg\n", qr.QRColor[0], qr.QRColor[1], qr.QRColor[2])
	fmt.Fprintf(&buf, "%g %g %g RG\n", qr.QRColor[0], qr.QRColor[1], qr.QRColor[2])
	fmt.Fprintf(&buf, "%g 0 0 %g %g %g cm\n", qr.BoxSize, -qr.BoxSize, brd, brd+ydiff)

	// Draw modules
	for row := 0; row < qr.Size; row++ {
		for col := 0; col < qr.Size; col++ {
			if qr.Modules[row][col] {
				fmt.Fprintf(&buf, "%d %d 1 1 re\n", col, row)
			}
		}
	}

	buf.WriteString("f\n")

	return buf.Bytes()
}

// FancyQRCode provides enhanced QR code rendering with rounded corners.
type FancyQRCode struct {
	*QRCode
	CenterpieceCornerRadius float64
	Centerpiece             *PdfContent
}

// PdfContent represents PDF content that can be embedded in the QR code.
type PdfContent struct {
	Box    BoxConstraints
	Data   []byte
	Width  float64
	Height float64
}

// BoxConstraints represents dimensions.
type BoxConstraints struct {
	Width  float64
	Height float64
}

// NewFancyQRCode creates a new fancy QR code.
func NewFancyQRCode(data string, ecLevel ErrorCorrectionLevel, centerpiece *PdfContent) *FancyQRCode {
	qr := NewQRCode(data, ecLevel)
	return &FancyQRCode{
		QRCode:                  qr,
		CenterpieceCornerRadius: 0.2,
		Centerpiece:             centerpiece,
	}
}

// IsPositionPattern checks if a position is part of a finder or alignment pattern.
func (fqr *FancyQRCode) IsPositionPattern(row, col int) bool {
	// Check major position patterns (finder patterns)
	if (row < 7 && col < 7) ||
		(row > fqr.Size-8 && col < 7) ||
		(row < 7 && col > fqr.Size-8) {
		return true
	}

	// Check alignment patterns
	return fqr.isInAlignmentPattern(row, col)
}

// RenderPDF renders the fancy QR code to PDF content stream commands.
func (fqr *FancyQRCode) RenderPDF() []byte {
	var buf bytes.Buffer

	// Set up coordinate transformation
	brd := float64(fqr.Border) * fqr.BoxSize
	ydiff := float64(fqr.Size) * fqr.BoxSize

	// Set fill color and transform coordinates
	fmt.Fprintf(&buf, "%g %g %g rg\n", fqr.QRColor[0], fqr.QRColor[1], fqr.QRColor[2])
	fmt.Fprintf(&buf, "%g %g %g RG\n", fqr.QRColor[0], fqr.QRColor[1], fqr.QRColor[2])
	fmt.Fprintf(&buf, "%g 0 0 %g %g %g cm\n", fqr.BoxSize, -fqr.BoxSize, brd, brd+ydiff)

	// Set up clipping for centerpiece if present
	if fqr.Centerpiece != nil {
		buf.WriteString("q\n")
		buf.WriteString("0.2 w\n")

		// Clockwise outer rectangle
		w := float64(fqr.Size)
		fmt.Fprintf(&buf, "0 0 m 0 %g l %g %g l %g 0 l h\n", w, w, w, w)

		// Counterclockwise inner rectangle for centerpiece area
		cx, cy, csz := fqr.measureCenterpiece()
		buf.Write(roundedSquare(cx, cy, csz, fqr.CenterpieceCornerRadius*csz))
		buf.WriteString("W n\n")
	}

	// Draw data modules with rounded corners (skip position patterns)
	for row := 0; row < fqr.Size; row++ {
		for col := 0; col < fqr.Size; col++ {
			if fqr.Modules[row][col] && !fqr.IsPositionPattern(row, col) {
				buf.Write(roundedSquare(float64(col), float64(row), 0.9, 0.3))
			}
		}
	}
	buf.WriteString("f\n")

	// Draw position patterns
	buf.Write(fqr.drawPositionPatterns())

	// Close clipping and draw centerpiece
	if fqr.Centerpiece != nil {
		buf.WriteString("Q\n")
		buf.Write(fqr.drawCenterpiece())
	}

	return buf.Bytes()
}

// measureCenterpiece calculates centerpiece dimensions.
func (fqr *FancyQRCode) measureCenterpiece() (x, y, size float64) {
	// Centerpiece takes up about 28% of QR code
	size = 0.28 * float64(fqr.Size)
	x = (float64(fqr.Size) - size) / 2
	y = (float64(fqr.Size) - size) / 2
	return x, y, size
}

// drawPositionPatterns draws the finder and alignment patterns with rounded corners.
func (fqr *FancyQRCode) drawPositionPatterns() []byte {
	var buf bytes.Buffer
	sz := float64(fqr.Size)

	// Outer stroked squares
	buf.WriteString("q\n1 0 0 1 0.5 0.5 cm\n0.7 w\n")
	buf.Write(roundedSquare(0, 0, 6, 1))
	buf.Write(roundedSquare(0, sz-7, 6, 1))
	buf.Write(roundedSquare(sz-7, 0, 6, 1))

	// Alignment patterns outer
	positions := fqr.getAlignmentPatternPositions()
	if positions != nil {
		for _, pr := range positions {
			for _, pc := range positions {
				if (pr < 9 && pc < 9) || (pr < 9 && pc > fqr.Size-10) || (pr > fqr.Size-10 && pc < 9) {
					continue
				}
				buf.Write(roundedSquare(float64(pr-2), float64(pc-2), 4, 0.7))
			}
		}
	}
	buf.WriteString("S\nQ\n")

	// Inner filled squares
	buf.Write(roundedSquare(2, 2, 3, 0.6))
	buf.Write(roundedSquare(2, sz-7+2, 3, 0.6))
	buf.Write(roundedSquare(sz-7+2, 2, 3, 0.6))

	// Alignment pattern centers
	if positions != nil {
		for _, pr := range positions {
			for _, pc := range positions {
				if (pr < 9 && pc < 9) || (pr < 9 && pc > fqr.Size-10) || (pr > fqr.Size-10 && pc < 9) {
					continue
				}
				buf.Write(roundedSquare(float64(pr), float64(pc), 1, 0.1))
			}
		}
	}
	buf.WriteString("f\n")

	return buf.Bytes()
}

// drawCenterpiece renders the centerpiece image.
func (fqr *FancyQRCode) drawCenterpiece() []byte {
	if fqr.Centerpiece == nil {
		return nil
	}

	var buf bytes.Buffer
	cx, cy, csz := fqr.measureCenterpiece()

	cw := fqr.Centerpiece.Width
	ch := fqr.Centerpiece.Height
	if cw == 0 {
		cw = fqr.Centerpiece.Box.Width
	}
	if ch == 0 {
		ch = fqr.Centerpiece.Box.Height
	}

	// Draw border
	buf.WriteString("q\n0.2 w\n")
	buf.Write(roundedSquare(cx, cy, csz, fqr.CenterpieceCornerRadius*csz))
	buf.WriteString("S\nQ\nq\n")

	// Transform and shrink centerpiece
	xScale := csz / cw
	yScale := csz / ch
	shrink := 0.85
	xShift := (1 - shrink) * cw / 2
	yShift := (1 - shrink) * ch / 2

	fmt.Fprintf(&buf, "%g 0 0 %g %g %g cm\n",
		xScale*shrink, -yScale*shrink,
		cx+xShift*xScale, cy+csz-yShift*yScale)

	buf.Write(fqr.Centerpiece.Data)
	buf.WriteString("\nQ\n")

	return buf.Bytes()
}

// roundedSquare generates PDF commands for a rounded square.
func roundedSquare(x, y, sz, rad float64) []byte {
	var buf bytes.Buffer

	// Bezier curve control point offset for circular arcs
	cOff := (4 * (math.Sqrt(2) - 1) / 3) * rad

	// Move to starting point
	fmt.Fprintf(&buf, "%g %g m\n", x+rad, y)

	// Bottom edge to bottom-right corner
	fmt.Fprintf(&buf, "%g %g l\n", x+sz-rad, y)
	fmt.Fprintf(&buf, "%g %g %g %g %g %g c\n",
		x+sz-cOff, y, x+sz, y+cOff, x+sz, y+rad)

	// Right edge to top-right corner
	fmt.Fprintf(&buf, "%g %g l\n", x+sz, y+sz-rad)
	fmt.Fprintf(&buf, "%g %g %g %g %g %g c\n",
		x+sz, y+sz-cOff, x+sz-cOff, y+sz, x+sz-rad, y+sz)

	// Top edge to top-left corner
	fmt.Fprintf(&buf, "%g %g l\n", x+rad, y+sz)
	fmt.Fprintf(&buf, "%g %g %g %g %g %g c\n",
		x+cOff, y+sz, x, y+sz-cOff, x, y+sz-rad)

	// Left edge to bottom-left corner
	fmt.Fprintf(&buf, "%g %g l\n", x, y+rad)
	fmt.Fprintf(&buf, "%g %g %g %g %g %g c\n",
		x, y+cOff, x+cOff, y, x+rad, y)

	buf.WriteString("h\n")

	return buf.Bytes()
}
