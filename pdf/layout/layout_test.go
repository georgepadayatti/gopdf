package layout

import (
	"math"
	"strings"
	"testing"
)

const tolerance = 0.0001

func floatEqual(a, b float64) bool {
	return math.Abs(a-b) < tolerance
}

// Unit tests

func TestToPoints(t *testing.T) {
	tests := []struct {
		value    float64
		unit     Unit
		expected float64
	}{
		{1, Pt, 1},
		{1, In, 72},
		{2.54, Cm, 72},
		{25.4, Mm, 72},
	}

	for _, tt := range tests {
		result := ToPoints(tt.value, tt.unit)
		if !floatEqual(result, tt.expected) {
			t.Errorf("ToPoints(%v, %v) = %v, want %v", tt.value, tt.unit, result, tt.expected)
		}
	}
}

func TestFromPoints(t *testing.T) {
	tests := []struct {
		points   float64
		unit     Unit
		expected float64
	}{
		{72, Pt, 72},
		{72, In, 1},
		{72, Cm, 2.54},
		{72, Mm, 25.4},
	}

	for _, tt := range tests {
		result := FromPoints(tt.points, tt.unit)
		if !floatEqual(result, tt.expected) {
			t.Errorf("FromPoints(%v, %v) = %v, want %v", tt.points, tt.unit, result, tt.expected)
		}
	}
}

// PageSize tests

func TestPageSizeLandscape(t *testing.T) {
	portrait := A4
	landscape := portrait.Landscape()

	if landscape.Width <= landscape.Height {
		t.Error("Landscape should have width > height")
	}
	if landscape.Width != portrait.Height || landscape.Height != portrait.Width {
		t.Error("Landscape dimensions incorrect")
	}
}

func TestPageSizePortrait(t *testing.T) {
	landscape := Ledger
	portrait := landscape.Portrait()

	if portrait.Width >= portrait.Height {
		t.Error("Portrait should have width < height")
	}
}

func TestPageSizeIsLandscape(t *testing.T) {
	if A4.IsLandscape() {
		t.Error("A4 should not be landscape")
	}
	if !Ledger.IsLandscape() {
		t.Error("Ledger should be landscape")
	}
}

func TestPageSizeIsPortrait(t *testing.T) {
	if !A4.IsPortrait() {
		t.Error("A4 should be portrait")
	}
	if Ledger.IsPortrait() {
		t.Error("Ledger should not be portrait")
	}
}

func TestPageSizeAspectRatio(t *testing.T) {
	ratio := Letter.AspectRatio()
	expected := 612.0 / 792.0
	if !floatEqual(ratio, expected) {
		t.Errorf("Letter AspectRatio = %v, want %v", ratio, expected)
	}
}

func TestPageSizeScale(t *testing.T) {
	scaled := A4.Scale(2)
	if scaled.Width != A4.Width*2 || scaled.Height != A4.Height*2 {
		t.Error("Scale should double dimensions")
	}
}

// Point tests

func TestNewPoint(t *testing.T) {
	p := NewPoint(10, 20)
	if p.X != 10 || p.Y != 20 {
		t.Errorf("NewPoint = (%v, %v), want (10, 20)", p.X, p.Y)
	}
}

func TestOrigin(t *testing.T) {
	p := Origin()
	if p.X != 0 || p.Y != 0 {
		t.Error("Origin should be (0, 0)")
	}
}

func TestPointAdd(t *testing.T) {
	p1 := NewPoint(10, 20)
	p2 := NewPoint(5, 10)
	result := p1.Add(p2)

	if result.X != 15 || result.Y != 30 {
		t.Errorf("Add = (%v, %v), want (15, 30)", result.X, result.Y)
	}
}

func TestPointSub(t *testing.T) {
	p1 := NewPoint(10, 20)
	p2 := NewPoint(5, 10)
	result := p1.Sub(p2)

	if result.X != 5 || result.Y != 10 {
		t.Errorf("Sub = (%v, %v), want (5, 10)", result.X, result.Y)
	}
}

func TestPointScale(t *testing.T) {
	p := NewPoint(10, 20)
	result := p.Scale(2)

	if result.X != 20 || result.Y != 40 {
		t.Errorf("Scale = (%v, %v), want (20, 40)", result.X, result.Y)
	}
}

func TestPointDistance(t *testing.T) {
	p1 := NewPoint(0, 0)
	p2 := NewPoint(3, 4)
	dist := p1.Distance(p2)

	if !floatEqual(dist, 5) {
		t.Errorf("Distance = %v, want 5", dist)
	}
}

func TestPointRotate(t *testing.T) {
	p := NewPoint(1, 0)
	rotated := p.Rotate(math.Pi / 2) // 90 degrees

	if !floatEqual(rotated.X, 0) || !floatEqual(rotated.Y, 1) {
		t.Errorf("Rotate = (%v, %v), want (0, 1)", rotated.X, rotated.Y)
	}
}

func TestPointRotateAround(t *testing.T) {
	p := NewPoint(2, 0)
	center := NewPoint(1, 0)
	rotated := p.RotateAround(center, math.Pi) // 180 degrees

	if !floatEqual(rotated.X, 0) || !floatEqual(rotated.Y, 0) {
		t.Errorf("RotateAround = (%v, %v), want (0, 0)", rotated.X, rotated.Y)
	}
}

func TestPointLerp(t *testing.T) {
	p1 := NewPoint(0, 0)
	p2 := NewPoint(10, 20)
	mid := p1.Lerp(p2, 0.5)

	if mid.X != 5 || mid.Y != 10 {
		t.Errorf("Lerp(0.5) = (%v, %v), want (5, 10)", mid.X, mid.Y)
	}
}

// Rectangle tests

func TestNewRectangle(t *testing.T) {
	r := NewRectangle(10, 20, 100, 50)
	if r.X != 10 || r.Y != 20 || r.Width != 100 || r.Height != 50 {
		t.Error("Rectangle dimensions incorrect")
	}
}

func TestRectangleFromPoints(t *testing.T) {
	p1 := NewPoint(10, 20)
	p2 := NewPoint(110, 70)
	r := RectFromPoints(p1, p2)

	if r.X != 10 || r.Y != 20 || r.Width != 100 || r.Height != 50 {
		t.Error("FromPoints dimensions incorrect")
	}
}

func TestRectangleFromMediaBox(t *testing.T) {
	box := [4]float64{0, 0, 612, 792}
	r := FromMediaBox(box)

	if r.X != 0 || r.Y != 0 || r.Width != 612 || r.Height != 792 {
		t.Error("FromMediaBox dimensions incorrect")
	}
}

func TestRectangleEdges(t *testing.T) {
	r := NewRectangle(10, 20, 100, 50)

	if r.Left() != 10 {
		t.Errorf("Left = %v, want 10", r.Left())
	}
	if r.Right() != 110 {
		t.Errorf("Right = %v, want 110", r.Right())
	}
	if r.Bottom() != 20 {
		t.Errorf("Bottom = %v, want 20", r.Bottom())
	}
	if r.Top() != 70 {
		t.Errorf("Top = %v, want 70", r.Top())
	}
}

func TestRectangleCenter(t *testing.T) {
	r := NewRectangle(0, 0, 100, 50)
	center := r.Center()

	if center.X != 50 || center.Y != 25 {
		t.Errorf("Center = (%v, %v), want (50, 25)", center.X, center.Y)
	}
}

func TestRectangleCorners(t *testing.T) {
	r := NewRectangle(10, 20, 100, 50)

	bl := r.BottomLeft()
	if bl.X != 10 || bl.Y != 20 {
		t.Error("BottomLeft incorrect")
	}

	br := r.BottomRight()
	if br.X != 110 || br.Y != 20 {
		t.Error("BottomRight incorrect")
	}

	tl := r.TopLeft()
	if tl.X != 10 || tl.Y != 70 {
		t.Error("TopLeft incorrect")
	}

	tr := r.TopRight()
	if tr.X != 110 || tr.Y != 70 {
		t.Error("TopRight incorrect")
	}
}

func TestRectangleArea(t *testing.T) {
	r := NewRectangle(0, 0, 10, 5)
	if r.Area() != 50 {
		t.Errorf("Area = %v, want 50", r.Area())
	}
}

func TestRectangleContains(t *testing.T) {
	r := NewRectangle(0, 0, 100, 100)

	if !r.Contains(NewPoint(50, 50)) {
		t.Error("Should contain center point")
	}
	if r.Contains(NewPoint(150, 50)) {
		t.Error("Should not contain point outside")
	}
}

func TestRectangleContainsRect(t *testing.T) {
	outer := NewRectangle(0, 0, 100, 100)
	inner := NewRectangle(10, 10, 50, 50)
	outside := NewRectangle(80, 80, 50, 50)

	if !outer.ContainsRect(inner) {
		t.Error("Outer should contain inner")
	}
	if outer.ContainsRect(outside) {
		t.Error("Outer should not contain outside")
	}
}

func TestRectangleIntersects(t *testing.T) {
	r1 := NewRectangle(0, 0, 100, 100)
	r2 := NewRectangle(50, 50, 100, 100)
	r3 := NewRectangle(200, 200, 50, 50)

	if !r1.Intersects(r2) {
		t.Error("r1 and r2 should intersect")
	}
	if r1.Intersects(r3) {
		t.Error("r1 and r3 should not intersect")
	}
}

func TestRectangleIntersection(t *testing.T) {
	r1 := NewRectangle(0, 0, 100, 100)
	r2 := NewRectangle(50, 50, 100, 100)

	intersection, ok := r1.Intersection(r2)
	if !ok {
		t.Fatal("Should have intersection")
	}

	if intersection.X != 50 || intersection.Y != 50 ||
		intersection.Width != 50 || intersection.Height != 50 {
		t.Error("Intersection dimensions incorrect")
	}
}

func TestRectangleUnion(t *testing.T) {
	r1 := NewRectangle(0, 0, 50, 50)
	r2 := NewRectangle(25, 25, 50, 50)

	union := r1.Union(r2)

	if union.X != 0 || union.Y != 0 || union.Width != 75 || union.Height != 75 {
		t.Error("Union dimensions incorrect")
	}
}

func TestRectangleInset(t *testing.T) {
	r := NewRectangle(0, 0, 100, 100)
	inset := r.Inset(10, 10, 10, 10)

	if inset.X != 10 || inset.Y != 10 || inset.Width != 80 || inset.Height != 80 {
		t.Error("Inset dimensions incorrect")
	}
}

func TestRectangleExpand(t *testing.T) {
	r := NewRectangle(10, 10, 80, 80)
	expanded := r.ExpandAll(10)

	if expanded.X != 0 || expanded.Y != 0 || expanded.Width != 100 || expanded.Height != 100 {
		t.Error("Expand dimensions incorrect")
	}
}

func TestRectangleTranslate(t *testing.T) {
	r := NewRectangle(0, 0, 100, 100)
	translated := r.Translate(50, 50)

	if translated.X != 50 || translated.Y != 50 {
		t.Error("Translate position incorrect")
	}
	if translated.Width != 100 || translated.Height != 100 {
		t.Error("Translate should not change size")
	}
}

func TestRectangleScale(t *testing.T) {
	r := NewRectangle(0, 0, 100, 100)
	scaled := r.Scale(2)

	// Should scale around center
	if scaled.Width != 200 || scaled.Height != 200 {
		t.Error("Scale size incorrect")
	}
}

func TestRectangleScaleToFit(t *testing.T) {
	r := NewRectangle(0, 0, 200, 100) // 2:1 aspect ratio
	fitted := r.ScaleToFit(100, 100)

	// Should fit width, height scaled proportionally
	if !floatEqual(fitted.Width, 100) || !floatEqual(fitted.Height, 50) {
		t.Errorf("ScaleToFit = %vx%v, want 100x50", fitted.Width, fitted.Height)
	}
}

func TestRectangleToMediaBox(t *testing.T) {
	r := NewRectangle(0, 0, 612, 792)
	box := r.ToMediaBox()

	if box[0] != 0 || box[1] != 0 || box[2] != 612 || box[3] != 792 {
		t.Error("ToMediaBox values incorrect")
	}
}

// Margins tests

func TestNewMargins(t *testing.T) {
	m := NewMargins(10, 20, 30, 40)
	if m.Top != 10 || m.Right != 20 || m.Bottom != 30 || m.Left != 40 {
		t.Error("Margins values incorrect")
	}
}

func TestUniformMargins(t *testing.T) {
	m := UniformMargins(10)
	if m.Top != 10 || m.Right != 10 || m.Bottom != 10 || m.Left != 10 {
		t.Error("UniformMargins should have same value on all sides")
	}
}

func TestSymmetricMargins(t *testing.T) {
	m := SymmetricMargins(10, 20)
	if m.Top != 10 || m.Bottom != 10 || m.Left != 20 || m.Right != 20 {
		t.Error("SymmetricMargins values incorrect")
	}
}

func TestMarginsHorizontalVertical(t *testing.T) {
	m := NewMargins(10, 20, 30, 40)
	if m.Horizontal() != 60 {
		t.Errorf("Horizontal = %v, want 60", m.Horizontal())
	}
	if m.Vertical() != 40 {
		t.Errorf("Vertical = %v, want 40", m.Vertical())
	}
}

func TestMarginsApply(t *testing.T) {
	m := UniformMargins(10)
	r := NewRectangle(0, 0, 100, 100)
	result := m.Apply(r)

	if result.X != 10 || result.Y != 10 || result.Width != 80 || result.Height != 80 {
		t.Error("Margins.Apply incorrect")
	}
}

// BoxModel tests

func TestNewBoxModel(t *testing.T) {
	content := NewRectangle(0, 0, 100, 100)
	box := NewBoxModel(content)

	if box.Content != content {
		t.Error("Content not set")
	}
}

func TestBoxModelSetPadding(t *testing.T) {
	box := NewBoxModel(NewRectangle(0, 0, 100, 100)).SetPadding(10)
	if box.Padding.Top != 10 {
		t.Error("SetPadding not applied")
	}
}

func TestBoxModelPaddingBox(t *testing.T) {
	box := NewBoxModel(NewRectangle(10, 10, 80, 80)).SetPadding(5)
	paddingBox := box.PaddingBox()

	if paddingBox.X != 5 || paddingBox.Y != 5 || paddingBox.Width != 90 || paddingBox.Height != 90 {
		t.Error("PaddingBox dimensions incorrect")
	}
}

func TestBoxModelBorderBox(t *testing.T) {
	box := NewBoxModel(NewRectangle(10, 10, 80, 80)).SetPadding(5).SetBorder(2)
	borderBox := box.BorderBox()

	if borderBox.Width != 94 || borderBox.Height != 94 {
		t.Error("BorderBox dimensions incorrect")
	}
}

func TestBoxModelMarginBox(t *testing.T) {
	box := NewBoxModel(NewRectangle(10, 10, 80, 80)).
		SetPadding(5).
		SetBorder(2).
		SetMargin(3)
	marginBox := box.MarginBox()

	if marginBox.Width != 100 || marginBox.Height != 100 {
		t.Error("MarginBox dimensions incorrect")
	}
}

func TestBoxModelTotalDimensions(t *testing.T) {
	box := NewBoxModel(NewRectangle(0, 0, 80, 80)).
		SetPadding(5).
		SetBorder(2).
		SetMargin(3)

	if box.TotalWidth() != 100 {
		t.Errorf("TotalWidth = %v, want 100", box.TotalWidth())
	}
	if box.TotalHeight() != 100 {
		t.Errorf("TotalHeight = %v, want 100", box.TotalHeight())
	}
}

// Alignment tests

func TestPosition(t *testing.T) {
	containerSize := 100.0
	itemSize := 40.0

	if Position(containerSize, itemSize, AlignStart) != 0 {
		t.Error("AlignStart should be 0")
	}
	if Position(containerSize, itemSize, AlignCenter) != 30 {
		t.Error("AlignCenter should be 30")
	}
	if Position(containerSize, itemSize, AlignEnd) != 60 {
		t.Error("AlignEnd should be 60")
	}
}

// LayoutContainer tests

func TestNewLayoutContainer(t *testing.T) {
	bounds := NewRectangle(0, 0, 200, 100)
	container := NewLayoutContainer(bounds, Horizontal)

	if container.Bounds != bounds {
		t.Error("Bounds not set")
	}
	if container.Direction != Horizontal {
		t.Error("Direction not set")
	}
}

func TestLayoutContainerAddItem(t *testing.T) {
	bounds := NewRectangle(0, 0, 200, 100)
	container := NewLayoutContainer(bounds, Horizontal)
	container.SetSpacing(10)

	item1 := container.AddItem(50, 30)
	if item1.X != 0 {
		t.Errorf("First item X = %v, want 0", item1.X)
	}

	item2 := container.AddItem(50, 30)
	if item2.X != 60 { // 50 + 10 spacing
		t.Errorf("Second item X = %v, want 60", item2.X)
	}
}

func TestLayoutContainerItems(t *testing.T) {
	container := NewLayoutContainer(NewRectangle(0, 0, 200, 100), Horizontal)
	container.AddItem(50, 30)
	container.AddItem(50, 30)

	if len(container.Items()) != 2 {
		t.Errorf("Items count = %d, want 2", len(container.Items()))
	}
}

func TestLayoutContainerClear(t *testing.T) {
	container := NewLayoutContainer(NewRectangle(0, 0, 200, 100), Horizontal)
	container.AddItem(50, 30)
	container.Clear()

	if len(container.Items()) != 0 {
		t.Error("Clear should remove all items")
	}
}

func TestLayoutContainerUsedSpace(t *testing.T) {
	container := NewLayoutContainer(NewRectangle(0, 0, 200, 100), Horizontal)
	container.SetSpacing(10)
	container.AddItem(50, 30)
	container.AddItem(50, 30)

	used := container.UsedSpace()
	if used != 110 { // 50 + 10 + 50
		t.Errorf("UsedSpace = %v, want 110", used)
	}
}

func TestLayoutContainerRemainingSpace(t *testing.T) {
	container := NewLayoutContainer(NewRectangle(0, 0, 200, 100), Horizontal)
	container.AddItem(50, 30)

	remaining := container.RemainingSpace()
	if remaining != 150 {
		t.Errorf("RemainingSpace = %v, want 150", remaining)
	}
}

// Grid tests

func TestNewGrid(t *testing.T) {
	bounds := NewRectangle(0, 0, 200, 100)
	grid := NewGrid(bounds, 2, 4)

	if grid.Rows != 2 || grid.Cols != 4 {
		t.Error("Grid dimensions incorrect")
	}
}

func TestGridCellSize(t *testing.T) {
	bounds := NewRectangle(0, 0, 200, 100)
	grid := NewGrid(bounds, 2, 4)

	width, height := grid.CellSize()
	if width != 50 || height != 50 {
		t.Errorf("CellSize = %vx%v, want 50x50", width, height)
	}
}

func TestGridCellSizeWithSpacing(t *testing.T) {
	bounds := NewRectangle(0, 0, 230, 110)
	grid := NewGrid(bounds, 2, 4)
	grid.SetSpacing(10, 10)

	width, height := grid.CellSize()
	if width != 50 || height != 50 {
		t.Errorf("CellSize with spacing = %vx%v, want 50x50", width, height)
	}
}

func TestGridCell(t *testing.T) {
	bounds := NewRectangle(0, 0, 200, 100)
	grid := NewGrid(bounds, 2, 4)

	cell := grid.Cell(0, 0)
	if cell.X != 0 || cell.Width != 50 || cell.Height != 50 {
		t.Error("Cell(0,0) dimensions incorrect")
	}

	cell = grid.Cell(0, 1)
	if cell.X != 50 {
		t.Errorf("Cell(0,1).X = %v, want 50", cell.X)
	}
}

func TestGridCellOutOfBounds(t *testing.T) {
	grid := NewGrid(NewRectangle(0, 0, 200, 100), 2, 4)

	cell := grid.Cell(-1, 0)
	if cell.Width != 0 {
		t.Error("Out of bounds cell should be empty")
	}

	cell = grid.Cell(10, 0)
	if cell.Width != 0 {
		t.Error("Out of bounds cell should be empty")
	}
}

func TestGridCellSpan(t *testing.T) {
	bounds := NewRectangle(0, 0, 200, 100)
	grid := NewGrid(bounds, 2, 4)

	span := grid.CellSpan(0, 0, 2, 2)
	if span.Width != 100 || span.Height != 100 {
		t.Errorf("CellSpan = %vx%v, want 100x100", span.Width, span.Height)
	}
}

func TestGridAllCells(t *testing.T) {
	grid := NewGrid(NewRectangle(0, 0, 200, 100), 2, 4)
	cells := grid.AllCells()

	if len(cells) != 8 {
		t.Errorf("AllCells count = %d, want 8", len(cells))
	}
}

// Transform tests

func TestIdentity(t *testing.T) {
	id := Identity()
	p := NewPoint(10, 20)
	result := id.Apply(p)

	if result.X != p.X || result.Y != p.Y {
		t.Error("Identity should not change point")
	}
}

func TestTranslate(t *testing.T) {
	tr := Translate(10, 20)
	p := NewPoint(5, 5)
	result := tr.Apply(p)

	if result.X != 15 || result.Y != 25 {
		t.Errorf("Translate = (%v, %v), want (15, 25)", result.X, result.Y)
	}
}

func TestScaleTransform(t *testing.T) {
	sc := ScaleTransform(2, 3)
	p := NewPoint(10, 10)
	result := sc.Apply(p)

	if result.X != 20 || result.Y != 30 {
		t.Errorf("Scale = (%v, %v), want (20, 30)", result.X, result.Y)
	}
}

func TestRotate(t *testing.T) {
	rot := Rotate(math.Pi / 2) // 90 degrees
	p := NewPoint(1, 0)
	result := rot.Apply(p)

	if !floatEqual(result.X, 0) || !floatEqual(result.Y, 1) {
		t.Errorf("Rotate = (%v, %v), want (0, 1)", result.X, result.Y)
	}
}

func TestRotateDeg(t *testing.T) {
	rot := RotateDeg(90)
	p := NewPoint(1, 0)
	result := rot.Apply(p)

	if !floatEqual(result.X, 0) || !floatEqual(result.Y, 1) {
		t.Errorf("RotateDeg = (%v, %v), want (0, 1)", result.X, result.Y)
	}
}

func TestTransformMultiply(t *testing.T) {
	tr := Translate(10, 0)
	sc := ScaleTransform(2, 2)
	combined := tr.Multiply(sc)

	p := NewPoint(5, 5)
	result := combined.Apply(p)

	// Matrix multiplication: tr.Multiply(sc) applies sc first, then tr
	// First scale (5*2, 5*2) = (10, 10), then translate (10+10, 10) = (20, 10)
	if !floatEqual(result.X, 20) || !floatEqual(result.Y, 10) {
		t.Errorf("Combined transform = (%v, %v), want (20, 10)", result.X, result.Y)
	}
}

func TestTransformApplyRect(t *testing.T) {
	rot := RotateDeg(45)
	r := NewRectangle(0, 0, 10, 10)
	result := rot.ApplyRect(r)

	// Should have positive dimensions
	if result.Width <= 0 || result.Height <= 0 {
		t.Error("Transformed rectangle should have positive dimensions")
	}
}

func TestTransformInverse(t *testing.T) {
	tr := Translate(10, 20)
	inv := tr.Inverse()

	p := NewPoint(0, 0)
	translated := tr.Apply(p)
	back := inv.Apply(translated)

	if !floatEqual(back.X, 0) || !floatEqual(back.Y, 0) {
		t.Errorf("Inverse should return to original: (%v, %v)", back.X, back.Y)
	}
}

func TestTransformToPDFOperator(t *testing.T) {
	tr := Translate(10, 20)
	op := tr.ToPDFOperator()

	if !strings.Contains(op, "cm") {
		t.Error("PDF operator should contain 'cm'")
	}
}

// PageLayout tests

func TestNewPageLayout(t *testing.T) {
	layout := NewPageLayout(A4)

	if layout.Size != A4 {
		t.Error("Size not set")
	}
	if layout.Margins.Top != 72 {
		t.Error("Default margin should be 72 points")
	}
}

func TestPageLayoutSetMargins(t *testing.T) {
	layout := NewPageLayout(A4).SetMargins(UniformMargins(36))

	if layout.Margins.Top != 36 {
		t.Error("SetMargins not applied")
	}
}

func TestPageLayoutContentArea(t *testing.T) {
	layout := NewPageLayout(Letter).SetMargins(UniformMargins(72))
	content := layout.ContentArea()

	expectedWidth := 612.0 - 144.0  // 468
	expectedHeight := 792.0 - 144.0 // 648

	if content.Width != expectedWidth || content.Height != expectedHeight {
		t.Errorf("ContentArea = %vx%v, want %vx%v",
			content.Width, content.Height, expectedWidth, expectedHeight)
	}
}

func TestPageLayoutMediaBox(t *testing.T) {
	layout := NewPageLayout(Letter)
	media := layout.MediaBox()

	if media.Width != 612 || media.Height != 792 {
		t.Error("MediaBox dimensions incorrect")
	}
}

func TestPageLayoutColumns(t *testing.T) {
	layout := NewPageLayout(Letter).SetMargins(UniformMargins(72))
	columns := layout.Columns(2, 20)

	if len(columns) != 2 {
		t.Errorf("Columns count = %d, want 2", len(columns))
	}

	// Each column should be (468 - 20) / 2 = 224 wide
	if !floatEqual(columns[0].Width, 224) {
		t.Errorf("Column width = %v, want 224", columns[0].Width)
	}
}

// FlowLayout tests

func TestNewFlowLayout(t *testing.T) {
	bounds := NewRectangle(0, 0, 200, 100)
	flow := NewFlowLayout(bounds)

	if flow.Bounds != bounds {
		t.Error("Bounds not set")
	}
}

func TestFlowLayoutAddItem(t *testing.T) {
	flow := NewFlowLayout(NewRectangle(0, 0, 200, 100))
	flow.SetSpacing(5, 5)

	item, ok := flow.AddItem(50, 20)
	if !ok {
		t.Error("Should be able to add item")
	}
	if item.Width != 50 || item.Height != 20 {
		t.Error("Item dimensions incorrect")
	}
}

func TestFlowLayoutWrapping(t *testing.T) {
	flow := NewFlowLayout(NewRectangle(0, 0, 100, 200))

	flow.AddItem(40, 20)
	flow.AddItem(40, 20)
	item3, _ := flow.AddItem(40, 20) // Should wrap

	if item3.X != 0 {
		t.Errorf("Wrapped item X = %v, want 0", item3.X)
	}
}

func TestFlowLayoutNewLine(t *testing.T) {
	flow := NewFlowLayout(NewRectangle(0, 0, 200, 100))

	flow.AddItem(50, 20)
	flow.NewLine()
	item, _ := flow.AddItem(50, 20)

	if item.X != 0 {
		t.Error("After NewLine, item should start at X=0")
	}
}

func TestFlowLayoutRemainingHeight(t *testing.T) {
	flow := NewFlowLayout(NewRectangle(0, 0, 200, 100))
	flow.SetSpacing(0, 10)

	flow.AddItem(50, 30)
	flow.NewLine()

	remaining := flow.RemainingHeight()
	// 100 - 30 - 10 spacing = 60
	if remaining != 60 {
		t.Errorf("RemainingHeight = %v, want 60", remaining)
	}
}

func TestFlowLayoutNoRoom(t *testing.T) {
	flow := NewFlowLayout(NewRectangle(0, 0, 100, 50))

	flow.AddItem(100, 30)
	_, ok := flow.AddItem(100, 30) // No room

	if ok {
		t.Error("Should return false when no room")
	}
}

// Anchor tests

func TestAnchorPoint(t *testing.T) {
	r := NewRectangle(0, 0, 100, 50)

	tests := []struct {
		anchor   Anchor
		expected Point
	}{
		{AnchorTopLeft, NewPoint(0, 50)},
		{AnchorTopCenter, NewPoint(50, 50)},
		{AnchorTopRight, NewPoint(100, 50)},
		{AnchorMiddleLeft, NewPoint(0, 25)},
		{AnchorMiddleCenter, NewPoint(50, 25)},
		{AnchorMiddleRight, NewPoint(100, 25)},
		{AnchorBottomLeft, NewPoint(0, 0)},
		{AnchorBottomCenter, NewPoint(50, 0)},
		{AnchorBottomRight, NewPoint(100, 0)},
	}

	for _, tt := range tests {
		result := AnchorPoint(r, tt.anchor)
		if result.X != tt.expected.X || result.Y != tt.expected.Y {
			t.Errorf("AnchorPoint(%d) = (%v, %v), want (%v, %v)",
				tt.anchor, result.X, result.Y, tt.expected.X, tt.expected.Y)
		}
	}
}

func TestPositionAt(t *testing.T) {
	point := NewPoint(100, 100)

	// Position with center anchor
	result := PositionAt(50, 30, point, AnchorMiddleCenter)

	if result.X != 75 || result.Y != 85 {
		t.Errorf("PositionAt = (%v, %v), want (75, 85)", result.X, result.Y)
	}
}

func TestFitInto(t *testing.T) {
	item := NewRectangle(0, 0, 200, 100) // 2:1 aspect ratio
	container := NewRectangle(0, 0, 100, 100)

	fitted := FitInto(item, container, AlignCenter, AlignCenter)

	// Should fit width, centered vertically
	if fitted.Width != 100 {
		t.Errorf("Fitted width = %v, want 100", fitted.Width)
	}
	if fitted.Height != 50 {
		t.Errorf("Fitted height = %v, want 50", fitted.Height)
	}
	if fitted.Y != 25 {
		t.Errorf("Fitted Y = %v, want 25 (centered)", fitted.Y)
	}
}

func TestCenterIn(t *testing.T) {
	item := NewRectangle(0, 0, 50, 30)
	container := NewRectangle(0, 0, 100, 100)

	centered := CenterIn(item, container)

	if centered.X != 25 || centered.Y != 35 {
		t.Errorf("CenterIn = (%v, %v), want (25, 35)", centered.X, centered.Y)
	}
}

// Integration tests

func TestCompleteLayout(t *testing.T) {
	// Create a page layout
	page := NewPageLayout(Letter).SetMargins(UniformMargins(72))

	// Create a grid in the content area
	content := page.ContentArea()
	grid := NewGrid(content, 3, 2)
	grid.SetSpacing(10, 10)

	// Get all cells
	cells := grid.AllCells()
	if len(cells) != 6 {
		t.Error("Should have 6 cells")
	}

	// Each cell should have content
	for i, cell := range cells {
		if cell.Width <= 0 || cell.Height <= 0 {
			t.Errorf("Cell %d has invalid dimensions", i)
		}
	}
}

func TestTransformChain(t *testing.T) {
	// Build a complex transform chain
	tr := Identity().
		Multiply(Translate(100, 100)).
		Multiply(RotateDeg(45)).
		Multiply(ScaleTransform(2, 2))

	p := NewPoint(0, 0)
	result := tr.Apply(p)

	// The origin should move to (100, 100) after the chain
	// (rotation of origin is still origin, then translate)
	if !floatEqual(result.X, 100) || !floatEqual(result.Y, 100) {
		t.Errorf("Transform chain result = (%v, %v), want (100, 100)", result.X, result.Y)
	}
}
