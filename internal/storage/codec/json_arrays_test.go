package codec

import "testing"

func TestStringArrayJSONHelpers(t *testing.T) {
	raw, err := MarshalStringArray("test_field", []string{"slack", "telegram"})
	if err != nil {
		t.Fatalf("MarshalStringArray returned error: %v", err)
	}
	if raw != `["slack","telegram"]` {
		t.Fatalf("unexpected raw JSON: %s", raw)
	}

	values, err := UnmarshalStringArray("test_field", raw)
	if err != nil {
		t.Fatalf("UnmarshalStringArray returned error: %v", err)
	}
	if len(values) != 2 || values[0] != "slack" || values[1] != "telegram" {
		t.Fatalf("unexpected decoded values: %+v", values)
	}
}

func TestStringArrayJSONHelpersRejectCorruption(t *testing.T) {
	if _, err := UnmarshalStringArray("test_field", `{not-json}`); err == nil {
		t.Fatal("expected corrupt JSON array to fail")
	}
}

func TestStringArrayJSONHelpersNormalizeEmptyValues(t *testing.T) {
	raw, err := MarshalStringArray("test_field", nil)
	if err != nil {
		t.Fatalf("MarshalStringArray returned error: %v", err)
	}
	if raw != `[]` {
		t.Fatalf("expected empty array JSON, got %s", raw)
	}

	values, err := UnmarshalStringArray("test_field", "")
	if err != nil {
		t.Fatalf("UnmarshalStringArray returned error: %v", err)
	}
	if len(values) != 0 {
		t.Fatalf("expected empty values, got %+v", values)
	}
}
