package content

import (
	"bytes"
	"strings"
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

func TestContentStreamAddOperation(t *testing.T) {
	cs := NewContentStream()
	cs.AddOperation(OpMoveTo, 100.0, 200.0)
	cs.AddOperation(OpLineTo, 300.0, 400.0)
	cs.AddOperation(OpStroke)

	if len(cs.Operations) != 3 {
		t.Errorf("Expected 3 operations, got %d", len(cs.Operations))
	}

	if cs.Operations[0].Operator != OpMoveTo {
		t.Errorf("Expected OpMoveTo, got %s", cs.Operations[0].Operator)
	}
}

func TestContentStreamRender(t *testing.T) {
	cs := NewContentStream()
	cs.AddOperation(OpSaveState)
	cs.AddOperation(OpMoveTo, 100.0, 200.0)
	cs.AddOperation(OpLineTo, 300.0, 400.0)
	cs.AddOperation(OpStroke)
	cs.AddOperation(OpRestoreState)

	rendered := cs.Render()

	expected := []string{"q", "100 200 m", "300 400 l", "S", "Q"}
	for _, exp := range expected {
		if !strings.Contains(string(rendered), exp) {
			t.Errorf("Expected rendered stream to contain '%s'", exp)
		}
	}
}

func TestContentBuilderBasic(t *testing.T) {
	cb := NewContentBuilder()
	cb.SaveState().
		MoveTo(100, 200).
		LineTo(300, 400).
		Stroke().
		RestoreState()

	stream := cb.Build()
	if len(stream.Operations) != 5 {
		t.Errorf("Expected 5 operations, got %d", len(stream.Operations))
	}
}

func TestContentBuilderRectangle(t *testing.T) {
	cb := NewContentBuilder()
	cb.Rectangle(10, 20, 100, 50).Fill()

	rendered := cb.Render()

	if !strings.Contains(string(rendered), "10 20 100 50 re") {
		t.Error("Expected rectangle operation")
	}
	if !strings.Contains(string(rendered), "f") {
		t.Error("Expected fill operation")
	}
}

func TestContentBuilderText(t *testing.T) {
	cb := NewContentBuilder()
	cb.BeginText().
		SetFont("F1", 12).
		TextPosition(100, 700).
		ShowText("Hello, World!").
		EndText()

	rendered := cb.Render()

	if !strings.Contains(string(rendered), "BT") {
		t.Error("Expected BeginText operator")
	}
	if !strings.Contains(string(rendered), "/F1 12 Tf") {
		t.Error("Expected SetFont operator")
	}
	if !strings.Contains(string(rendered), "100 700 Td") {
		t.Error("Expected TextPosition operator")
	}
	if !strings.Contains(string(rendered), "Hello") {
		t.Error("Expected ShowText operator")
	}
	if !strings.Contains(string(rendered), "ET") {
		t.Error("Expected EndText operator")
	}
}

func TestContentBuilderColors(t *testing.T) {
	cb := NewContentBuilder()
	cb.SetStrokeColor(1, 0, 0).
		SetFillColor(0, 1, 0).
		SetStrokeGray(0.5).
		SetFillGray(0.8)

	rendered := cb.Render()

	if !strings.Contains(string(rendered), "1 0 0 RG") {
		t.Error("Expected SetStrokeColor (RGB)")
	}
	if !strings.Contains(string(rendered), "0 1 0 rg") {
		t.Error("Expected SetFillColor (RGB)")
	}
	if !strings.Contains(string(rendered), "0.5 G") {
		t.Error("Expected SetStrokeGray")
	}
	if !strings.Contains(string(rendered), "0.8 g") {
		t.Error("Expected SetFillGray")
	}
}

func TestContentBuilderTransform(t *testing.T) {
	cb := NewContentBuilder()
	cb.Translate(100, 200).
		Scale(2, 2)

	rendered := cb.Render()

	if !strings.Contains(string(rendered), "1 0 0 1 100 200 cm") {
		t.Error("Expected Translate transform")
	}
	if !strings.Contains(string(rendered), "2 0 0 2 0 0 cm") {
		t.Error("Expected Scale transform")
	}
}

func TestContentBuilderPaintXObject(t *testing.T) {
	cb := NewContentBuilder()
	cb.SaveState().
		PaintXObject("Image1").
		RestoreState()

	rendered := cb.Render()

	if !strings.Contains(string(rendered), "/Image1 Do") {
		t.Error("Expected PaintXObject operator")
	}
}

func TestContentBuilderSetLineWidth(t *testing.T) {
	cb := NewContentBuilder()
	cb.SetLineWidth(2.5).
		MoveTo(0, 0).
		LineTo(100, 100).
		Stroke()

	rendered := cb.Render()

	if !strings.Contains(string(rendered), "2.5 w") {
		t.Error("Expected SetLineWidth operator")
	}
}

func TestContentParserBasic(t *testing.T) {
	content := []byte("q 100 200 m 300 400 l S Q")

	parser := NewParser(content)
	cs, err := parser.Parse()
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(cs.Operations) != 5 {
		t.Errorf("Expected 5 operations, got %d", len(cs.Operations))
	}

	if cs.Operations[0].Operator != OpSaveState {
		t.Error("Expected first operator to be q")
	}

	if cs.Operations[1].Operator != OpMoveTo {
		t.Error("Expected second operator to be m")
	}

	if len(cs.Operations[1].Operands) != 2 {
		t.Errorf("Expected 2 operands for moveto, got %d", len(cs.Operations[1].Operands))
	}
}

func TestContentParserWithNames(t *testing.T) {
	content := []byte("/F1 12 Tf")

	parser := NewParser(content)
	cs, err := parser.Parse()
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(cs.Operations) != 1 {
		t.Errorf("Expected 1 operation, got %d", len(cs.Operations))
	}

	if cs.Operations[0].Operator != OpSetFont {
		t.Errorf("Expected Tf operator, got %s", cs.Operations[0].Operator)
	}
}

func TestContentParserWithStrings(t *testing.T) {
	content := []byte("BT (Hello World) Tj ET")

	parser := NewParser(content)
	cs, err := parser.Parse()
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(cs.Operations) != 3 {
		t.Errorf("Expected 3 operations, got %d", len(cs.Operations))
	}

	if cs.Operations[1].Operator != OpShowText {
		t.Errorf("Expected Tj operator, got %s", cs.Operations[1].Operator)
	}
}

func TestContentParserWithHexStrings(t *testing.T) {
	content := []byte("<48656C6C6F> Tj")

	parser := NewParser(content)
	cs, err := parser.Parse()
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(cs.Operations) != 1 {
		t.Errorf("Expected 1 operation, got %d", len(cs.Operations))
	}
}

func TestContentParserWithComments(t *testing.T) {
	content := []byte("q % This is a comment\n100 200 m S Q")

	parser := NewParser(content)
	cs, err := parser.Parse()
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(cs.Operations) != 4 {
		t.Errorf("Expected 4 operations, got %d", len(cs.Operations))
	}
}

func TestFormatOperand(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected string
	}{
		{42, "42"},
		{int64(100), "100"},
		{3.14, "3.14"},
		{"hello", "hello"},
		{generic.NameObject("Font"), "/Font"},
	}

	for _, tt := range tests {
		result := formatOperand(tt.input)
		if result != tt.expected {
			t.Errorf("formatOperand(%v) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

func TestFormatOperandArray(t *testing.T) {
	arr := generic.ArrayObject{
		generic.IntegerObject(1),
		generic.IntegerObject(2),
		generic.IntegerObject(3),
	}

	result := formatOperand(arr)
	if !strings.Contains(result, "[") || !strings.Contains(result, "]") {
		t.Error("Array should be formatted with brackets")
	}
}

func TestEscapeString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello", "Hello"},
		{"Hello(World)", "Hello\\(World\\)"},
		{"Path\\to\\file", "Path\\\\to\\\\file"},
		{"(nested (parens))", "\\(nested \\(parens\\)\\)"},
	}

	for _, tt := range tests {
		result := escapeString(tt.input)
		if result != tt.expected {
			t.Errorf("escapeString(%s) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

func TestIsOperator(t *testing.T) {
	operators := []string{"q", "Q", "m", "l", "S", "f", "BT", "ET", "Tf", "Tj", "cm", "Do"}
	for _, op := range operators {
		if !isOperator(op) {
			t.Errorf("Expected '%s' to be recognized as operator", op)
		}
	}

	nonOperators := []string{"hello", "123", "test", ""}
	for _, op := range nonOperators {
		if isOperator(op) {
			t.Errorf("Expected '%s' to NOT be recognized as operator", op)
		}
	}
}

func TestContentBuilderRotate(t *testing.T) {
	cb := NewContentBuilder()
	cb.Rotate(0) // 0 radians = identity

	rendered := cb.Render()

	// At 0 radians, cos=1, sin=0, so transform is identity-like
	if !bytes.Contains(rendered, []byte("cm")) {
		t.Error("Expected transform operation")
	}
}

func TestContentBuilderClosePath(t *testing.T) {
	cb := NewContentBuilder()
	cb.MoveTo(0, 0).
		LineTo(100, 0).
		LineTo(100, 100).
		ClosePath().
		Stroke()

	rendered := cb.Render()

	if !strings.Contains(string(rendered), "h") {
		t.Error("Expected ClosePath operator")
	}
}

func TestContentBuilderFillAndStroke(t *testing.T) {
	cb := NewContentBuilder()
	cb.Rectangle(10, 10, 100, 100).FillAndStroke()

	rendered := cb.Render()

	if !strings.Contains(string(rendered), "B") {
		t.Error("Expected FillAndStroke operator")
	}
}

func TestContentBuilderClip(t *testing.T) {
	cb := NewContentBuilder()
	cb.Rectangle(0, 0, 100, 100).Clip()

	rendered := cb.Render()

	if !strings.Contains(string(rendered), "W") {
		t.Error("Expected Clip operator")
	}
}

func TestContentParserRoundTrip(t *testing.T) {
	// Build content
	cb := NewContentBuilder()
	cb.SaveState().
		SetLineWidth(2).
		SetStrokeColor(1, 0, 0).
		MoveTo(100, 100).
		LineTo(200, 200).
		Stroke().
		RestoreState()

	original := cb.Render()

	// Parse it
	parser := NewParser(original)
	cs, err := parser.Parse()
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Re-render
	rerendered := cs.Render()

	// Should have same operators
	if len(cs.Operations) != 7 {
		t.Errorf("Expected 7 operations after round-trip, got %d", len(cs.Operations))
	}

	_ = rerendered
}

func TestHelperMathFunctions(t *testing.T) {
	// Test cosine at 0
	if cos := cosine(0); cos < 0.999 || cos > 1.001 {
		t.Errorf("cos(0) should be 1, got %f", cos)
	}

	// Test sine at 0
	if sin := sine(0); sin < -0.001 || sin > 0.001 {
		t.Errorf("sin(0) should be 0, got %f", sin)
	}

	// Test mod
	if m := mod(5, 3); m < 1.999 || m > 2.001 {
		t.Errorf("mod(5, 3) should be 2, got %f", m)
	}
}
