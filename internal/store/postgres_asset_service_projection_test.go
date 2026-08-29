package store

import (
	"reflect"
	"testing"

	"mossward/internal/model"
)

func TestPostgreSQLObservationRelationshipIDs(t *testing.T) {
	observation := model.ServiceObservation{ID: "observation-1", Address: "192.0.2.20", Port: 443}
	scan := model.Scan{
		Findings: []model.Finding{
			{ID: "finding-match", Address: observation.Address, Port: observation.Port},
			{ID: "finding-other", Address: observation.Address, Port: 22},
		},
		CVEMatches: []model.CVEMatch{
			{CVEID: "CVE-2026-0001", ObservationID: observation.ID},
			{CVEID: "CVE-2026-0002", ObservationID: "observation-2"},
		},
	}
	findings, cves := postgreSQLObservationRelationshipIDs(scan, observation)
	if !reflect.DeepEqual(findings, []string{"finding-match"}) {
		t.Fatalf("unexpected related findings: %v", findings)
	}
	if !reflect.DeepEqual(cves, []string{"CVE-2026-0001"}) {
		t.Fatalf("unexpected related CVEs: %v", cves)
	}
}
