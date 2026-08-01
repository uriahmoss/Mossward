package intelligence

import "testing"

func TestVersionAffected(t *testing.T) {
	tests := []struct {
		version, start, end string
		want                bool
	}{
		{"1.24.0", "1.20.0", "1.25.3", true},
		{"1.26.0", "1.20.0", "1.25.3", false},
		{"9.8p1", "9.0", "9.8p1", true},
	}
	for _, test := range tests {
		if got := VersionAffected(test.version, "", test.start, "", test.end, ""); got != test.want {
			t.Errorf("VersionAffected(%q) = %v, want %v", test.version, got, test.want)
		}
	}
}

func TestNormalizeProduct(t *testing.T) {
	vendor, product, ok := NormalizeProduct("OpenSSH")
	if !ok || vendor != "openbsd" || product != "openssh" {
		t.Fatalf("unexpected mapping: %q %q %v", vendor, product, ok)
	}
}
