package datamigration

import (
	"bytes"
	"encoding/json"
	"reflect"
	"time"
)

func equivalentValue(source, destination any, target ColumnType) bool {
	if target == ColumnJSON && source != nil && destination != nil {
		return reflect.DeepEqual(decodeJSON(source), decodeJSON(destination))
	}
	if target == ColumnTimestamp && source != nil && destination != nil {
		left, leftOK := source.(time.Time)
		right, rightOK := destination.(time.Time)
		return leftOK && rightOK && left.UTC().Truncate(time.Microsecond).Equal(right.UTC())
	}
	if encoded, ok := destination.([]byte); ok && target != ColumnBinary {
		destination = string(encoded)
	}
	return reflect.DeepEqual(source, destination)
}

func decodeJSON(value any) any {
	var encoded []byte
	switch typed := value.(type) {
	case string:
		encoded = []byte(typed)
	case []byte:
		encoded = typed
	default:
		return value
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var result any
	if decoder.Decode(&result) != nil {
		return nil
	}
	return result
}
