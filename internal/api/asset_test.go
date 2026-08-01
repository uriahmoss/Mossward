package api

import (
	"strings"
	"testing"

	"mossward/internal/model"
)

func TestAssetMetadataValidation(t *testing.T) {
	if !validAssetMetadata(model.AssetMetadata{Owner: "Infrastructure", Environment: "Production", Classification: "Critical"}) {
		t.Fatal("valid metadata was rejected")
	}
	if validAssetMetadata(model.AssetMetadata{Owner: strings.Repeat("a", assetMetadataLimit+1)}) {
		t.Fatal("oversized metadata was accepted")
	}
}

func TestOverlapRequiresExplicitAcknowledgement(t *testing.T) {
	if !overlapRequiresAcknowledgement([]string{"group-one"}, false) {
		t.Fatal("overlap did not require acknowledgement")
	}
	if overlapRequiresAcknowledgement([]string{"group-one"}, true) {
		t.Fatal("acknowledged overlap remained blocked")
	}
	if overlapRequiresAcknowledgement(nil, false) {
		t.Fatal("non-overlap was blocked")
	}
}
