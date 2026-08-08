package agentupdate

import "testing"

func TestIsUpgradeRejectsDowngradeAndDevelopmentBuild(t *testing.T) {
	tests := []struct {
		current string
		target  string
		want    bool
	}{
		{"1.2.3", "1.2.4", true},
		{"1.2.3", "2.0.0", true},
		{"1.2.3-beta.1", "1.2.3", true},
		{"1.2.3", "1.2.3", false},
		{"1.2.3", "1.2.2", false},
		{"development", "1.2.3", false},
	}
	for _, test := range tests {
		if got := IsUpgrade(test.current, test.target); got != test.want {
			t.Errorf("IsUpgrade(%q, %q) = %t", test.current, test.target, got)
		}
	}
}
