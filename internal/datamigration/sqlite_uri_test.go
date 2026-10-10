package datamigration

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadOnlySQLiteURIEncodesNativePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "space # percent% café.db")
	parsed, err := url.Parse(readOnlySQLiteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != "" || parsed.Query().Get("mode") != "ro" {
		t.Fatal("invalid read-only file URI")
	}
	want := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" && !strings.HasPrefix(want, "/") {
		want = "/" + want
	}
	if parsed.Path != want {
		t.Fatalf("decoded file path mismatch: %q", parsed.Path)
	}
}
