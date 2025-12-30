// Package layout provides PDF page layout and positioning utilities.
package layout

import (
	"fmt"
	"math"
)

// Unit represents a measurement unit.
type Unit float64

const (
	// Points - the base PDF unit (1/72 inch)
	Pt Unit = 1
	// Inches
	In Unit = 72
	// Centimeters
	Cm Unit = 72 / 2.54
	// Millimeters
	Mm Unit = 72 / 25.4
	// Pixels at 96 DPI
	Px Unit = 72 / 96
)

// ToPoints converts a value in the given unit to points.
func ToPoints(value float64, unit Unit) float64 {
	return value * float64(unit)
}

// FromPoints converts points to the given unit.
func FromPoints(points float64, unit Unit) float64 {
	return points / float64(unit)
}

// PageSize represents standard page dimensions.
type PageSize struct {
	Width  float64
	Height float64
}

// Standard page sizes in points
var (
	// ISO A series
	A0 = PageSize{2384, 3370}
	A1 = PageSize{1684, 2384}
	A2 = PageSize{1191, 1684}
	A3 = PageSize{842, 1191}
	A4 = PageSize{595, 842}
	A5 = PageSize{420, 595}
	A6 = PageSize{298, 420}
	A7 = PageSize{210, 298}
	A8 = PageSize{148, 210}

	// ISO B series
	B0 = PageSize{2835, 4008}
	B1 = PageSize{2004, 2835}
	B2 = PageSize{1417, 2004}
	B3 = PageSize{1001, 1417}
	B4 = PageSize{709, 1001}
	B5 = PageSize{499, 709}

	// US sizes
	Letter     = PageSize{612, 792}
	Legal      = PageSize{612, 1008}
	Tabloid    = PageSize{792, 1224}
	Ledger     = PageSize{1224, 792}
	Executive  = PageSize{522, 756}
	Statement  = PageSize{396, 612}
	HalfLetter = PageSize{396, 612}
)

// Landscape returns the page size in landscape orientation.
func (p PageSize) Landscape() PageSize {
	if p.Width < p.Height {
		return PageSize{p.Height, p.Width}
	}
	return p
}

// Portrait returns the page size in portrait orientation.
func (p PageSize) Portrait() PageSize {
	if p.Width > p.Height {
		return PageSize{p.Height, p.Width}
	}
	return p
}

// IsLandscape returns true if width > height.
func (p PageSize) IsLandscape() bool {
	return p.Width > p.Height
}

// IsPortrait returns true if height > width.
func (p PageSize) IsPortrait() bool {
	return p.Height > p.Width
}

// AspectRatio returns width/height.
func (p PageSize) AspectRatio() float64 {
	if p.Height == 0 {
		return 0
	}
	return p.Width / p.Height
}

// Scale returns a scaled page size.
func (p PageSize) Scale(factor float64) PageSize {
	return PageSize{
		Width:  p.Width * factor,
		Height: p.Height * factor,
	}
}

// Point represents a 2D point.
type Point struct {
	X, Y float64
}

// NewPoint creates a new point.
func NewPoint(x, y float64) Point {
	return Point{X: x, Y: y}
}

// Origin returns the origin point (0, 0).
func Origin() Point {
	return Point{0, 0}
}

// Add returns p + other.
func (p Point) Add(other Point) Point {
	return Point{p.X + other.X, p.Y + other.Y}
}

// Sub returns p - other.
func (p Point) Sub(other Point) Point {
	return Point{p.X - other.X, p.Y - other.Y}
}

// Scale returns p * factor.
func (p Point) Scale(factor float64) Point {
	return Point{p.X * factor, p.Y * factor}
}

// Distance returns the distance to another point.
func (p Point) Distance(other Point) float64 {
	dx := p.X - other.X
	dy := p.Y - other.Y
	return math.Sqrt(dx*dx + dy*dy)
}

// Rotate rotates the point around the origin by angle (in radians).
func (p Point) Rotate(angle float64) Point {
	cos := math.Cos(angle)
	sin := math.Sin(angle)
	return Point{
		X: p.X*cos - p.Y*sin,
		Y: p.X*sin + p.Y*cos,
	}
}

// RotateAround rotates the point around a center point.
func (p Point) RotateAround(center Point, angle float64) Point {
	translated := p.Sub(center)
	rotated := translated.Rotate(angle)
	return rotated.Add(center)
}

// Lerp performs linear interpolation between two points.
func (p Point) Lerp(other Point, t float64) Point {
	return Point{
		X: p.X + (other.X-p.X)*t,
		Y: p.Y + (other.Y-p.Y)*t,
	}
}

// Rectangle represents a rectangle with origin at bottom-left (PDF coordinates).
type Rectangle struct {
	X, Y          float64 // Bottom-left corner
	Width, Height float64
}

// NewRectangle creates a new rectangle.
func NewRectangle(x, y, width, height float64) Rectangle {
	return Rectangle{X: x, Y: y, Width: width, Height: height}
}

// RectFromPoints creates a rectangle from two corner points.
func RectFromPoints(p1, p2 Point) Rectangle {
	x := math.Min(p1.X, p2.X)
	y := math.Min(p1.Y, p2.Y)
	w := math.Abs(p2.X - p1.X)
	h := math.Abs(p2.Y - p1.Y)
	return Rectangle{X: x, Y: y, Width: w, Height: h}
}

// FromMediaBox creates a rectangle from a PDF media box array [x1, y1, x2, y2].
func FromMediaBox(box [4]float64) Rectangle {
	return Rectangle{
		X:      box[0],
		Y:      box[1],
		Width:  box[2] - box[0],
		Height: box[3] - box[1],
	}
}

// Left returns the left edge X coordinate.
func (r Rectangle) Left() float64 {
	return r.X
}

// Right returns the right edge X coordinate.
func (r Rectangle) Right() float64 {
	return r.X + r.Width
}

// Bottom returns the bottom edge Y coordinate.
func (r Rectangle) Bottom() float64 {
	return r.Y
}

// Top returns the top edge Y coordinate.
func (r Rectangle) Top() float64 {
	return r.Y + r.Height
}

// Center returns the center point.
func (r Rectangle) Center() Point {
	return Point{
		X: r.X + r.Width/2,
		Y: r.Y + r.Height/2,
	}
}

// TopLeft returns the top-left corner.
func (r Rectangle) TopLeft() Point {
	return Point{r.X, r.Y + r.Height}
}

// TopRight returns the top-right corner.
func (r Rectangle) TopRight() Point {
	return Point{r.X + r.Width, r.Y + r.Height}
}

// BottomLeft returns the bottom-left corner.
func (r Rectangle) BottomLeft() Point {
	return Point{r.X, r.Y}
}

// BottomRight returns the bottom-right corner.
func (r Rectangle) BottomRight() Point {
	return Point{r.X + r.Width, r.Y}
}

// Area returns the area.
func (r Rectangle) Area() float64 {
	return r.Width * r.Height
}

// AspectRatio returns width/height.
func (r Rectangle) AspectRatio() float64 {
	if r.Height == 0 {
		return 0
	}
	return r.Width / r.Height
}

// Contains returns true if the point is inside the rectangle.
func (r Rectangle) Contains(p Point) bool {
	return p.X >= r.X && p.X <= r.Right() &&
		p.Y >= r.Y && p.Y <= r.Top()
}

// ContainsRect returns true if the other rectangle is inside this one.
func (r Rectangle) ContainsRect(other Rectangle) bool {
	return other.X >= r.X && other.Right() <= r.Right() &&
		other.Y >= r.Y && other.Top() <= r.Top()
}

// Intersects returns true if the rectangles overlap.
func (r Rectangle) Intersects(other Rectangle) bool {
	return r.X < other.Right() && r.Right() > other.X &&
		r.Y < other.Top() && r.Top() > other.Y
}

// Intersection returns the intersection of two rectangles.
func (r Rectangle) Intersection(other Rectangle) (Rectangle, bool) {
	if !r.Intersects(other) {
		return Rectangle{}, false
	}

	x := math.Max(r.X, other.X)
	y := math.Max(r.Y, other.Y)
	right := math.Min(r.Right(), other.Right())
	top := math.Min(r.Top(), other.Top())

	return Rectangle{
		X:      x,
		Y:      y,
		Width:  right - x,
		Height: top - y,
	}, true
}

// Union returns the bounding rectangle containing both rectangles.
func (r Rectangle) Union(other Rectangle) Rectangle {
	x := math.Min(r.X, other.X)
	y := math.Min(r.Y, other.Y)
	right := math.Max(r.Right(), other.Right())
	top := math.Max(r.Top(), other.Top())

	return Rectangle{
		X:      x,
		Y:      y,
		Width:  right - x,
		Height: top - y,
	}
}

// Inset returns a rectangle inset by the given amounts.
func (r Rectangle) Inset(top, right, bottom, left float64) Rectangle {
	return Rectangle{
		X:      r.X + left,
		Y:      r.Y + bottom,
		Width:  r.Width - left - right,
		Height: r.Height - top - bottom,
	}
}

// InsetAll returns a rectangle inset by the same amount on all sides.
func (r Rectangle) InsetAll(amount float64) Rectangle {
	return r.Inset(amount, amount, amount, amount)
}

// Expand returns a rectangle expanded by the given amounts.
func (r Rectangle) Expand(top, right, bottom, left float64) Rectangle {
	return r.Inset(-top, -right, -bottom, -left)
}

// ExpandAll returns a rectangle expanded by the same amount on all sides.
func (r Rectangle) ExpandAll(amount float64) Rectangle {
	return r.InsetAll(-amount)
}

// Translate moves the rectangle.
func (r Rectangle) Translate(dx, dy float64) Rectangle {
	return Rectangle{
		X:      r.X + dx,
		Y:      r.Y + dy,
		Width:  r.Width,
		Height: r.Height,
	}
}

// Scale scales the rectangle around its center.
func (r Rectangle) Scale(factor float64) Rectangle {
	center := r.Center()
	newWidth := r.Width * factor
	newHeight := r.Height * factor
	return Rectangle{
		X:      center.X - newWidth/2,
		Y:      center.Y - newHeight/2,
		Width:  newWidth,
		Height: newHeight,
	}
}

// ScaleToFit scales the rectangle to fit within maxWidth and maxHeight while preserving aspect ratio.
func (r Rectangle) ScaleToFit(maxWidth, maxHeight float64) Rectangle {
	if r.Width == 0 || r.Height == 0 {
		return r
	}

	scaleX := maxWidth / r.Width
	scaleY := maxHeight / r.Height
	scale := math.Min(scaleX, scaleY)

	return r.Scale(scale)
}

// ScaleToFill scales the rectangle to fill maxWidth and maxHeight while preserving aspect ratio.
func (r Rectangle) ScaleToFill(maxWidth, maxHeight float64) Rectangle {
	if r.Width == 0 || r.Height == 0 {
		return r
	}

	scaleX := maxWidth / r.Width
	scaleY := maxHeight / r.Height
	scale := math.Max(scaleX, scaleY)

	return r.Scale(scale)
}

// ToMediaBox returns the rectangle as a PDF media box array [x1, y1, x2, y2].
func (r Rectangle) ToMediaBox() [4]float64 {
	return [4]float64{r.X, r.Y, r.Right(), r.Top()}
}

// Margins represents margins (spacing around content).
type Margins struct {
	Top, Right, Bottom, Left float64
}

// NewMargins creates new margins.
func NewMargins(top, right, bottom, left float64) Margins {
	return Margins{Top: top, Right: right, Bottom: bottom, Left: left}
}

// UniformMargins creates margins with the same value on all sides.
func UniformMargins(value float64) Margins {
	return Margins{value, value, value, value}
}

// SymmetricMargins creates margins with horizontal and vertical values.
func SymmetricMargins(vertical, horizontal float64) Margins {
	return Margins{vertical, horizontal, vertical, horizontal}
}

// Horizontal returns left + right.
func (m Margins) Horizontal() float64 {
	return m.Left + m.Right
}

// Vertical returns top + bottom.
func (m Margins) Vertical() float64 {
	return m.Top + m.Bottom
}

// Apply applies margins to a rectangle (shrinks it).
func (m Margins) Apply(r Rectangle) Rectangle {
	return r.Inset(m.Top, m.Right, m.Bottom, m.Left)
}

// BoxModel represents the CSS-like box model.
type BoxModel struct {
	Content Rectangle
	Padding Margins
	Border  Margins
	Margin  Margins
}

// NewBoxModel creates a new box model with the given content area.
func NewBoxModel(content Rectangle) *BoxModel {
	return &BoxModel{
		Content: content,
	}
}

// SetPadding sets uniform padding.
func (b *BoxModel) SetPadding(value float64) *BoxModel {
	b.Padding = UniformMargins(value)
	return b
}

// SetPaddingAll sets individual padding values.
func (b *BoxModel) SetPaddingAll(top, right, bottom, left float64) *BoxModel {
	b.Padding = NewMargins(top, right, bottom, left)
	return b
}

// SetBorder sets uniform border.
func (b *BoxModel) SetBorder(value float64) *BoxModel {
	b.Border = UniformMargins(value)
	return b
}

// SetMargin sets uniform margin.
func (b *BoxModel) SetMargin(value float64) *BoxModel {
	b.Margin = UniformMargins(value)
	return b
}

// PaddingBox returns the content plus padding area.
func (b *BoxModel) PaddingBox() Rectangle {
	return b.Content.Expand(b.Padding.Top, b.Padding.Right, b.Padding.Bottom, b.Padding.Left)
}

// BorderBox returns the content plus padding plus border area.
func (b *BoxModel) BorderBox() Rectangle {
	pb := b.PaddingBox()
	return pb.Expand(b.Border.Top, b.Border.Right, b.Border.Bottom, b.Border.Left)
}

// MarginBox returns the full box including margin.
func (b *BoxModel) MarginBox() Rectangle {
	bb := b.BorderBox()
	return bb.Expand(b.Margin.Top, b.Margin.Right, b.Margin.Bottom, b.Margin.Left)
}

// TotalWidth returns the total width including all boxes.
func (b *BoxModel) TotalWidth() float64 {
	return b.Content.Width + b.Padding.Horizontal() + b.Border.Horizontal() + b.Margin.Horizontal()
}

// TotalHeight returns the total height including all boxes.
func (b *BoxModel) TotalHeight() float64 {
	return b.Content.Height + b.Padding.Vertical() + b.Border.Vertical() + b.Margin.Vertical()
}

// Alignment represents alignment options.
type Alignment int

const (
	AlignStart Alignment = iota
	AlignCenter
	AlignEnd
)

// LayoutDirection represents layout direction.
type LayoutDirection int

const (
	Horizontal LayoutDirection = iota
	Vertical
)

// Position calculates position based on alignment.
func Position(containerSize, itemSize float64, align Alignment) float64 {
	switch align {
	case AlignCenter:
		return (containerSize - itemSize) / 2
	case AlignEnd:
		return containerSize - itemSize
	default:
		return 0
	}
}

// LayoutContainer manages layout of child items.
type LayoutContainer struct {
	Bounds    Rectangle
	Direction LayoutDirection
	HAlign    Alignment
	VAlign    Alignment
	Spacing   float64
	items     []Rectangle
}

// NewLayoutContainer creates a new layout container.
func NewLayoutContainer(bounds Rectangle, direction LayoutDirection) *LayoutContainer {
	return &LayoutContainer{
		Bounds:    bounds,
		Direction: direction,
		HAlign:    AlignStart,
		VAlign:    AlignStart,
		items:     make([]Rectangle, 0),
	}
}

// SetAlignment sets horizontal and vertical alignment.
func (c *LayoutContainer) SetAlignment(hAlign, vAlign Alignment) {
	c.HAlign = hAlign
	c.VAlign = vAlign
}

// SetSpacing sets spacing between items.
func (c *LayoutContainer) SetSpacing(spacing float64) {
	c.Spacing = spacing
}

// AddItem adds an item and returns its positioned rectangle.
func (c *LayoutContainer) AddItem(width, height float64) Rectangle {
	var x, y float64

	if c.Direction == Horizontal {
		// Calculate X based on previous items
		x = c.Bounds.X
		for i, item := range c.items {
			x = item.Right()
			if i < len(c.items) {
				x += c.Spacing
			}
		}

		// Calculate Y based on vertical alignment
		y = c.Bounds.Y + Position(c.Bounds.Height, height, c.VAlign)
	} else {
		// Calculate Y based on previous items (from top)
		y = c.Bounds.Top() - height
		for i, item := range c.items {
			y = item.Bottom() - height
			if i < len(c.items) {
				y -= c.Spacing
			}
		}

		// Calculate X based on horizontal alignment
		x = c.Bounds.X + Position(c.Bounds.Width, width, c.HAlign)
	}

	rect := Rectangle{X: x, Y: y, Width: width, Height: height}
	c.items = append(c.items, rect)
	return rect
}

// Items returns all positioned items.
func (c *LayoutContainer) Items() []Rectangle {
	return c.items
}

// Clear removes all items.
func (c *LayoutContainer) Clear() {
	c.items = c.items[:0]
}

// UsedSpace returns the space used by all items.
func (c *LayoutContainer) UsedSpace() float64 {
	if len(c.items) == 0 {
		return 0
	}

	var total float64
	for _, item := range c.items {
		if c.Direction == Horizontal {
			total += item.Width
		} else {
			total += item.Height
		}
	}

	// Add spacing
	total += float64(len(c.items)-1) * c.Spacing

	return total
}

// RemainingSpace returns the remaining space.
func (c *LayoutContainer) RemainingSpace() float64 {
	if c.Direction == Horizontal {
		return c.Bounds.Width - c.UsedSpace()
	}
	return c.Bounds.Height - c.UsedSpace()
}

// Grid represents a grid layout.
type Grid struct {
	Bounds     Rectangle
	Rows       int
	Cols       int
	HSpacing   float64
	VSpacing   float64
	cellWidth  float64
	cellHeight float64
}

// NewGrid creates a new grid layout.
func NewGrid(bounds Rectangle, rows, cols int) *Grid {
	g := &Grid{
		Bounds: bounds,
		Rows:   rows,
		Cols:   cols,
	}
	g.calculateCellSize()
	return g
}

// SetSpacing sets horizontal and vertical spacing.
func (g *Grid) SetSpacing(hSpacing, vSpacing float64) {
	g.HSpacing = hSpacing
	g.VSpacing = vSpacing
	g.calculateCellSize()
}

// calculateCellSize calculates cell dimensions.
func (g *Grid) calculateCellSize() {
	totalHSpacing := float64(g.Cols-1) * g.HSpacing
	totalVSpacing := float64(g.Rows-1) * g.VSpacing

	g.cellWidth = (g.Bounds.Width - totalHSpacing) / float64(g.Cols)
	g.cellHeight = (g.Bounds.Height - totalVSpacing) / float64(g.Rows)
}

// CellSize returns the cell dimensions.
func (g *Grid) CellSize() (width, height float64) {
	return g.cellWidth, g.cellHeight
}

// Cell returns the rectangle for a cell at row, col (0-indexed, from top-left).
func (g *Grid) Cell(row, col int) Rectangle {
	if row < 0 || row >= g.Rows || col < 0 || col >= g.Cols {
		return Rectangle{}
	}

	x := g.Bounds.X + float64(col)*(g.cellWidth+g.HSpacing)
	// Y is from bottom in PDF, so we calculate from top
	y := g.Bounds.Top() - float64(row+1)*g.cellHeight - float64(row)*g.VSpacing

	return Rectangle{
		X:      x,
		Y:      y,
		Width:  g.cellWidth,
		Height: g.cellHeight,
	}
}

// CellSpan returns the rectangle for a span of cells.
func (g *Grid) CellSpan(startRow, startCol, rowSpan, colSpan int) Rectangle {
	if startRow < 0 || startCol < 0 || rowSpan < 1 || colSpan < 1 {
		return Rectangle{}
	}

	endRow := startRow + rowSpan - 1
	endCol := startCol + colSpan - 1

	if endRow >= g.Rows || endCol >= g.Cols {
		return Rectangle{}
	}

	topLeft := g.Cell(startRow, startCol)
	bottomRight := g.Cell(endRow, endCol)

	return Rectangle{
		X:      topLeft.X,
		Y:      bottomRight.Y,
		Width:  bottomRight.Right() - topLeft.X,
		Height: topLeft.Top() - bottomRight.Y,
	}
}

// AllCells returns all cell rectangles in row-major order.
func (g *Grid) AllCells() []Rectangle {
	cells := make([]Rectangle, 0, g.Rows*g.Cols)
	for row := 0; row < g.Rows; row++ {
		for col := 0; col < g.Cols; col++ {
			cells = append(cells, g.Cell(row, col))
		}
	}
	return cells
}

// Transform represents a 2D affine transformation matrix.
type Transform struct {
	A, B, C, D, E, F float64
}

// Identity returns the identity transform.
func Identity() Transform {
	return Transform{1, 0, 0, 1, 0, 0}
}

// Translate creates a translation transform.
func Translate(dx, dy float64) Transform {
	return Transform{1, 0, 0, 1, dx, dy}
}

// Scale creates a scale transform.
func ScaleTransform(sx, sy float64) Transform {
	return Transform{sx, 0, 0, sy, 0, 0}
}

// Rotate creates a rotation transform (angle in radians).
func Rotate(angle float64) Transform {
	cos := math.Cos(angle)
	sin := math.Sin(angle)
	return Transform{cos, sin, -sin, cos, 0, 0}
}

// RotateDeg creates a rotation transform (angle in degrees).
func RotateDeg(angle float64) Transform {
	return Rotate(angle * math.Pi / 180)
}

// Skew creates a skew transform (angles in radians).
func Skew(angleX, angleY float64) Transform {
	return Transform{1, math.Tan(angleY), math.Tan(angleX), 1, 0, 0}
}

// Multiply multiplies two transforms.
func (t Transform) Multiply(other Transform) Transform {
	return Transform{
		A: t.A*other.A + t.C*other.B,
		B: t.B*other.A + t.D*other.B,
		C: t.A*other.C + t.C*other.D,
		D: t.B*other.C + t.D*other.D,
		E: t.A*other.E + t.C*other.F + t.E,
		F: t.B*other.E + t.D*other.F + t.F,
	}
}

// Apply applies the transform to a point.
func (t Transform) Apply(p Point) Point {
	return Point{
		X: t.A*p.X + t.C*p.Y + t.E,
		Y: t.B*p.X + t.D*p.Y + t.F,
	}
}

// ApplyRect applies the transform to a rectangle (returns bounding box).
func (t Transform) ApplyRect(r Rectangle) Rectangle {
	corners := []Point{
		r.BottomLeft(),
		r.BottomRight(),
		r.TopLeft(),
		r.TopRight(),
	}

	minX, minY := math.MaxFloat64, math.MaxFloat64
	maxX, maxY := -math.MaxFloat64, -math.MaxFloat64

	for _, corner := range corners {
		transformed := t.Apply(corner)
		minX = math.Min(minX, transformed.X)
		minY = math.Min(minY, transformed.Y)
		maxX = math.Max(maxX, transformed.X)
		maxY = math.Max(maxY, transformed.Y)
	}

	return Rectangle{
		X:      minX,
		Y:      minY,
		Width:  maxX - minX,
		Height: maxY - minY,
	}
}

// Inverse returns the inverse transform.
func (t Transform) Inverse() Transform {
	det := t.A*t.D - t.B*t.C
	if det == 0 {
		return Identity()
	}

	return Transform{
		A: t.D / det,
		B: -t.B / det,
		C: -t.C / det,
		D: t.A / det,
		E: (t.C*t.F - t.D*t.E) / det,
		F: (t.B*t.E - t.A*t.F) / det,
	}
}

// ToPDFOperator returns the PDF content stream operator.
func (t Transform) ToPDFOperator() string {
	return fmt.Sprintf("%.4f %.4f %.4f %.4f %.4f %.4f cm", t.A, t.B, t.C, t.D, t.E, t.F)
}

// PageLayout represents a page with margins.
type PageLayout struct {
	Size    PageSize
	Margins Margins
}

// NewPageLayout creates a new page layout.
func NewPageLayout(size PageSize) *PageLayout {
	return &PageLayout{
		Size:    size,
		Margins: UniformMargins(72), // 1 inch default
	}
}

// SetMargins sets the margins.
func (p *PageLayout) SetMargins(margins Margins) *PageLayout {
	p.Margins = margins
	return p
}

// ContentArea returns the content area rectangle.
func (p *PageLayout) ContentArea() Rectangle {
	return Rectangle{
		X:      p.Margins.Left,
		Y:      p.Margins.Bottom,
		Width:  p.Size.Width - p.Margins.Horizontal(),
		Height: p.Size.Height - p.Margins.Vertical(),
	}
}

// MediaBox returns the media box.
func (p *PageLayout) MediaBox() Rectangle {
	return Rectangle{
		X:      0,
		Y:      0,
		Width:  p.Size.Width,
		Height: p.Size.Height,
	}
}

// Columns divides the content area into columns.
func (p *PageLayout) Columns(count int, gutter float64) []Rectangle {
	content := p.ContentArea()
	totalGutter := float64(count-1) * gutter
	colWidth := (content.Width - totalGutter) / float64(count)

	columns := make([]Rectangle, count)
	for i := 0; i < count; i++ {
		columns[i] = Rectangle{
			X:      content.X + float64(i)*(colWidth+gutter),
			Y:      content.Y,
			Width:  colWidth,
			Height: content.Height,
		}
	}
	return columns
}

// FlowLayout positions items that flow like text.
type FlowLayout struct {
	Bounds     Rectangle
	HSpacing   float64
	VSpacing   float64
	currentX   float64
	currentY   float64
	lineHeight float64
	items      []Rectangle
}

// NewFlowLayout creates a new flow layout.
func NewFlowLayout(bounds Rectangle) *FlowLayout {
	return &FlowLayout{
		Bounds:   bounds,
		currentX: bounds.X,
		currentY: bounds.Top(),
		items:    make([]Rectangle, 0),
	}
}

// SetSpacing sets horizontal and vertical spacing.
func (f *FlowLayout) SetSpacing(hSpacing, vSpacing float64) {
	f.HSpacing = hSpacing
	f.VSpacing = vSpacing
}

// AddItem adds an item and returns its position.
func (f *FlowLayout) AddItem(width, height float64) (Rectangle, bool) {
	// Check if item fits on current line
	if f.currentX+width > f.Bounds.Right() && f.currentX > f.Bounds.X {
		// Move to next line
		f.currentX = f.Bounds.X
		f.currentY -= f.lineHeight + f.VSpacing
		f.lineHeight = 0
	}

	// Check if item fits vertically
	if f.currentY-height < f.Bounds.Y {
		return Rectangle{}, false // No more room
	}

	rect := Rectangle{
		X:      f.currentX,
		Y:      f.currentY - height,
		Width:  width,
		Height: height,
	}

	f.items = append(f.items, rect)
	f.currentX += width + f.HSpacing
	if height > f.lineHeight {
		f.lineHeight = height
	}

	return rect, true
}

// Items returns all positioned items.
func (f *FlowLayout) Items() []Rectangle {
	return f.items
}

// NewLine moves to the next line.
func (f *FlowLayout) NewLine() {
	if f.lineHeight > 0 {
		f.currentX = f.Bounds.X
		f.currentY -= f.lineHeight + f.VSpacing
		f.lineHeight = 0
	}
}

// RemainingHeight returns the remaining vertical space.
func (f *FlowLayout) RemainingHeight() float64 {
	return f.currentY - f.Bounds.Y
}

// Anchor represents anchor positions.
type Anchor int

const (
	AnchorTopLeft Anchor = iota
	AnchorTopCenter
	AnchorTopRight
	AnchorMiddleLeft
	AnchorMiddleCenter
	AnchorMiddleRight
	AnchorBottomLeft
	AnchorBottomCenter
	AnchorBottomRight
)

// AnchorPoint returns the point for an anchor position in a rectangle.
func AnchorPoint(r Rectangle, anchor Anchor) Point {
	var x, y float64

	switch anchor {
	case AnchorTopLeft, AnchorMiddleLeft, AnchorBottomLeft:
		x = r.X
	case AnchorTopCenter, AnchorMiddleCenter, AnchorBottomCenter:
		x = r.X + r.Width/2
	case AnchorTopRight, AnchorMiddleRight, AnchorBottomRight:
		x = r.Right()
	}

	switch anchor {
	case AnchorTopLeft, AnchorTopCenter, AnchorTopRight:
		y = r.Top()
	case AnchorMiddleLeft, AnchorMiddleCenter, AnchorMiddleRight:
		y = r.Y + r.Height/2
	case AnchorBottomLeft, AnchorBottomCenter, AnchorBottomRight:
		y = r.Y
	}

	return Point{x, y}
}

// PositionAt positions a rectangle at a point using an anchor.
func PositionAt(width, height float64, point Point, anchor Anchor) Rectangle {
	var x, y float64

	switch anchor {
	case AnchorTopLeft, AnchorMiddleLeft, AnchorBottomLeft:
		x = point.X
	case AnchorTopCenter, AnchorMiddleCenter, AnchorBottomCenter:
		x = point.X - width/2
	case AnchorTopRight, AnchorMiddleRight, AnchorBottomRight:
		x = point.X - width
	}

	switch anchor {
	case AnchorTopLeft, AnchorTopCenter, AnchorTopRight:
		y = point.Y - height
	case AnchorMiddleLeft, AnchorMiddleCenter, AnchorMiddleRight:
		y = point.Y - height/2
	case AnchorBottomLeft, AnchorBottomCenter, AnchorBottomRight:
		y = point.Y
	}

	return Rectangle{X: x, Y: y, Width: width, Height: height}
}

// FitInto fits a rectangle into a container while preserving aspect ratio.
func FitInto(item, container Rectangle, hAlign, vAlign Alignment) Rectangle {
	if item.Width == 0 || item.Height == 0 {
		return item
	}

	// Calculate scale to fit
	scaleX := container.Width / item.Width
	scaleY := container.Height / item.Height
	scale := math.Min(scaleX, scaleY)

	newWidth := item.Width * scale
	newHeight := item.Height * scale

	// Calculate position based on alignment
	x := container.X + Position(container.Width, newWidth, hAlign)
	y := container.Y + Position(container.Height, newHeight, vAlign)

	return Rectangle{X: x, Y: y, Width: newWidth, Height: newHeight}
}

// CenterIn centers a rectangle inside a container.
func CenterIn(item, container Rectangle) Rectangle {
	return Rectangle{
		X:      container.X + (container.Width-item.Width)/2,
		Y:      container.Y + (container.Height-item.Height)/2,
		Width:  item.Width,
		Height: item.Height,
	}
}
