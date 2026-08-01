package intelligence

import "testing"

func TestParseNVD(t *testing.T) {
	payload := []byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-1000","published":"2026-07-01T00:00:00.000","lastModified":"2026-07-02T00:00:00.000","descriptions":[{"lang":"en","value":"Test issue"}],"metrics":{"cvssMetricV31":[{"cvssData":{"vectorString":"CVSS:3.1/AV:N","baseScore":9.8,"baseSeverity":"CRITICAL"}}]},"cisaExploitAdd":"2026-07-03","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*","versionEndExcluding":"1.25.4"}]}]}],"references":[{"url":"https://example.test/advisory","source":"vendor"}]}}]}`)
	records, total, err := ParseNVD(payload)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(records) != 1 || records[0].CVSSScore != 9.8 || !records[0].KnownExploited || records[0].Products[0].Product != "nginx" {
		t.Fatalf("unexpected parsed feed: %#v", records)
	}
}
