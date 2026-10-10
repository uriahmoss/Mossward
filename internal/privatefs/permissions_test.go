package privatefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestrictAndCheckPrivatePaths(t *testing.T) {
	directory := t.TempDir()
	if err := Restrict(directory); err != nil {
		t.Fatal(err)
	}
	if err := Check(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "secret")
	if err := os.WriteFile(path, []byte("synthetic"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Restrict(path); err != nil {
		t.Fatal(err)
	}
	if err := Check(path); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateCreateNeverOverwritesAndWriteFileIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := WriteFile(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if file, err := Create(path); err == nil {
		_ = file.Close()
		t.Fatal("existing private file overwritten")
	}
	if err := WriteFile(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	if err := Check(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "second" {
		t.Fatal("private replacement failed")
	}
}
