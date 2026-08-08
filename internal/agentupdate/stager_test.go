package agentupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStagerDownloadsExactVerifiedArtifact(t *testing.T) {
	artifact := []byte("signed endpoint agent artifact")
	manifest := stagingManifest("https://updates.example.test/agent", artifact)
	stager, err := newStager(t.TempDir(), responseClient(http.StatusOK, artifact, int64(len(artifact)), ""), "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	path, err := stager.Stage(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil || string(stored) != string(artifact) {
		t.Fatalf("staged artifact = %q, error = %v", stored, err)
	}
}

func TestStagerRejectsDigestMismatchAndCleansTemporaryFile(t *testing.T) {
	artifact := []byte("artifact")
	manifest := stagingManifest("https://updates.example.test/agent", artifact)
	manifest.ArtifactSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	directory := t.TempDir()
	stager, err := newStager(directory, responseClient(http.StatusOK, artifact, -1, ""), "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stager.Stage(context.Background(), manifest); err == nil {
		t.Fatal("artifact with incorrect digest was staged")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed staging left files: %v, error = %v", entries, err)
	}
}

func TestStagerRejectsRedirect(t *testing.T) {
	manifest := stagingManifest("https://updates.example.test/agent", []byte("artifact"))
	stager, err := newStager(t.TempDir(), responseClient(http.StatusFound, nil, 0, "https://other.example.test/agent"), "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stager.Stage(context.Background(), manifest); err == nil {
		t.Fatal("redirected update artifact was accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func responseClient(status int, body []byte, contentLength int64, location string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		if location != "" {
			header.Set("Location", location)
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(string(body))),
			ContentLength: contentLength, Request: request}, nil
	})}
}

func stagingManifest(rawURL string, artifact []byte) Manifest {
	digest := sha256.Sum256(artifact)
	return Manifest{SchemaVersion: 1, Version: "1.2.3", OperatingSystem: "linux", Architecture: "amd64",
		ArtifactURL: rawURL, ArtifactSHA256: hex.EncodeToString(digest[:]), ArtifactSize: int64(len(artifact)),
		IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), HealthTimeoutSeconds: 60}
}

func TestNewStagerRequiresAbsolutePrivateDirectory(t *testing.T) {
	if _, err := NewStager(filepath.Join("relative", "updates"), nil); err == nil {
		t.Fatal("relative update directory was accepted")
	}
}
