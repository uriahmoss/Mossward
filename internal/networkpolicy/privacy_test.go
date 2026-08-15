package networkpolicy

import (
	"reflect"
	"testing"

	"mossward/internal/model"
)

func TestNetworkTelemetrySchemaRemainsMetadataOnly(t *testing.T) {
	contract := PrivacyContract()
	if contract.CollectionMode != "metadata_only" || contract.PayloadCaptureSupported || contract.TLSInterceptionSupported ||
		contract.CertificateInjectionSupported || contract.DNSPacketCaptureSupported || contract.RuntimeMutable {
		t.Fatalf("unsafe network privacy contract: %#v", contract)
	}
	typeOfConnection := reflect.TypeOf(model.NetworkConnection{})
	if typeOfConnection.NumField() != len(contract.CollectedFields) {
		t.Fatalf("network telemetry schema changed without privacy-contract review: %d fields, contract has %d", typeOfConnection.NumField(), len(contract.CollectedFields))
	}
	for index, expected := range contract.CollectedFields {
		field := typeOfConnection.Field(index)
		if field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Map {
			t.Fatalf("network telemetry field %s can carry unbounded content", field.Name)
		}
		if got := field.Tag.Get("json"); got != expected && got != expected+",omitempty" {
			t.Fatalf("network telemetry field %d = %q, want %q", index, got, expected)
		}
	}
}
