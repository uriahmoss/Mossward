package datamigration

import (
	"encoding/json"
	"fmt"
	"time"
)

type ColumnType string

const (
	ColumnBoolean   ColumnType = "boolean"
	ColumnTimestamp ColumnType = "timestamp with time zone"
	ColumnJSON      ColumnType = "jsonb"
	ColumnBinary    ColumnType = "bytea"
)

// ConvertValue preserves SQL NULL and rejects ambiguous source representations.
func ConvertValue(value any, target ColumnType) (any, error) {
	if value == nil {
		return nil, nil
	}
	switch target {
	case ColumnBoolean:
		return convertBoolean(value)
	case ColumnTimestamp:
		return convertTimestamp(value)
	case ColumnJSON:
		return convertJSON(value)
	case ColumnBinary:
		bytes, ok := value.([]byte)
		if !ok {
			return nil, fmt.Errorf("migration binary field requires bytes")
		}
		return append([]byte{}, bytes...), nil
	default:
		return value, nil
	}
}

func convertBoolean(value any) (bool, error) {
	if boolean, ok := value.(bool); ok {
		return boolean, nil
	}
	integer, ok := value.(int64)
	if !ok || (integer != 0 && integer != 1) {
		return false, fmt.Errorf("migration boolean field requires zero or one")
	}
	return integer == 1, nil
}

func convertTimestamp(value any) (time.Time, error) {
	if timestamp, ok := value.(time.Time); ok {
		return timestamp.UTC(), nil
	}
	text, ok := value.(string)
	if !ok {
		return time.Time{}, fmt.Errorf("migration timestamp field requires RFC3339 text")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		// Do not include the source value in errors: fields may contain sensitive data.
		return time.Time{}, fmt.Errorf("migration timestamp field contains invalid RFC3339 text")
	}
	return timestamp.UTC(), nil
}

func convertJSON(value any) (string, error) {
	var encoded []byte
	switch typed := value.(type) {
	case string:
		encoded = []byte(typed)
	case []byte:
		encoded = typed
	default:
		return "", fmt.Errorf("migration JSON field requires encoded text")
	}
	if !json.Valid(encoded) {
		return "", fmt.Errorf("migration JSON field contains invalid JSON")
	}
	return string(encoded), nil
}
