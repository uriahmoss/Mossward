package datamigration

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestMigrationConversionPreservesValues(t *testing.T) {
	for _, target := range []ColumnType{ColumnBoolean, ColumnTimestamp, ColumnJSON, ColumnBinary} {
		value, err := ConvertValue(nil, target)
		if err != nil || value != nil {
			t.Fatalf("NULL conversion for %s: %v %v", target, value, err)
		}
	}
	value, err := ConvertValue(int64(1), ColumnBoolean)
	if err != nil || value != true {
		t.Fatalf("boolean conversion: %v %v", value, err)
	}
	value, err = ConvertValue("2026-10-07T01:02:03.123456-05:00", ColumnTimestamp)
	wanted := time.Date(2026, 10, 7, 6, 2, 3, 123456000, time.UTC)
	if err != nil || !value.(time.Time).Equal(wanted) {
		t.Fatalf("timestamp conversion: %v %v", value, err)
	}
	value, err = ConvertValue(`{"count":9007199254740993}`, ColumnJSON)
	if err != nil || value != `{"count":9007199254740993}` {
		t.Fatalf("JSON numeric precision changed: %v %v", value, err)
	}
	source := []byte{0, 255, 1}
	value, err = ConvertValue(source, ColumnBinary)
	if err != nil || !bytes.Equal(value.([]byte), source) {
		t.Fatalf("binary conversion: %v %v", value, err)
	}
	source[0] = 9
	if value.([]byte)[0] != 0 {
		t.Fatal("converted binary value shares mutable source storage")
	}
}

func TestMigrationConversionRejectsInvalidValuesWithoutDisclosure(t *testing.T) {
	for _, test := range []struct {
		value  any
		target ColumnType
	}{
		{int64(2), ColumnBoolean}, {"secret-value", ColumnBoolean},
		{"secret-value", ColumnTimestamp}, {"secret-value", ColumnJSON},
		{"secret-value", ColumnBinary},
	} {
		_, err := ConvertValue(test.value, test.target)
		if err == nil || strings.Contains(err.Error(), "secret-value") {
			t.Fatalf("invalid %s conversion returned unsafe error: %v", test.target, err)
		}
	}
}
