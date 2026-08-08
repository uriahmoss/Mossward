package agentupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyArtifactRequiresExactSizeAndDigest(t *testing.T) {
	contents := []byte("verified executable")
	path := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(path, contents, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	if err := VerifyArtifact(path, int64(len(contents)), hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact(path, int64(len(contents)), strings.Repeat("f", 64)); err == nil {
		t.Fatal("incorrect artifact digest was accepted")
	}
	if err := VerifyArtifact(path, int64(len(contents)+1), hex.EncodeToString(digest[:])); err == nil {
		t.Fatal("incorrect artifact size was accepted")
	}
}
