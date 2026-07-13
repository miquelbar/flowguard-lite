package codec

import (
	"encoding/json"
	"fmt"
)

func MarshalStringArray(field string, values []string) (string, error) {
	if values == nil {
		values = []string{}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("failed to marshal %s: %w", field, err)
	}
	return string(raw), nil
}

func UnmarshalStringArray(field, raw string) ([]string, error) {
	if raw == "" {
		return []string{}, nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, fmt.Errorf("failed to decode %s JSON array: %w", field, err)
	}
	if values == nil {
		return []string{}, nil
	}
	return values, nil
}
