package agentupdate

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const artifactDownloadTimeout = 10 * time.Minute

type Stager struct {
	directory       string
	client          *http.Client
	operatingSystem string
	architecture    string
}

func NewStager(directory string, client *http.Client) (*Stager, error) {
	return newStager(directory, client, runtime.GOOS, runtime.GOARCH)
}

func newStager(directory string, client *http.Client, operatingSystem, architecture string) (*Stager, error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("update staging directory must be absolute")
	}
	if client == nil {
		client = &http.Client{Timeout: artifactDownloadTimeout}
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = artifactDownloadTimeout
	}
	return &Stager{directory: directory, client: &clientCopy, operatingSystem: operatingSystem, architecture: architecture}, nil
}

func (s *Stager) Stage(ctx context.Context, manifest Manifest) (string, error) {
	if err := manifest.Validate(time.Now().UTC()); err != nil {
		return "", err
	}
	if manifest.OperatingSystem != s.operatingSystem || manifest.Architecture != s.architecture {
		return "", errors.New("update artifact does not match this operating system and architecture")
	}
	if err := os.MkdirAll(s.directory, 0o700); err != nil {
		return "", fmt.Errorf("create update staging directory: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(s.directory, 0o700); err != nil {
			return "", fmt.Errorf("protect update staging directory: %w", err)
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, manifest.ArtifactURL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := s.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("download endpoint-agent update: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("update download returned status %d", response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != manifest.ArtifactSize {
		return "", errors.New("update artifact Content-Length does not match the signed manifest")
	}
	return s.writeCandidate(response.Body, manifest)
}

func (s *Stager) writeCandidate(source io.Reader, manifest Manifest) (string, error) {
	file, err := os.CreateTemp(s.directory, ".mossward-update-")
	if err != nil {
		return "", fmt.Errorf("create staged update: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return "", err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(source, manifest.ArtifactSize+1))
	if copyErr != nil {
		file.Close()
		return "", fmt.Errorf("write staged update: %w", copyErr)
	}
	if written != manifest.ArtifactSize {
		file.Close()
		return "", errors.New("downloaded update size does not match the signed manifest")
	}
	expected, _ := hex.DecodeString(manifest.ArtifactSHA256)
	if subtle.ConstantTimeCompare(hash.Sum(nil), expected) != 1 {
		file.Close()
		return "", errors.New("downloaded update SHA-256 does not match the signed manifest")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", fmt.Errorf("sync staged update: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	finalPath := filepath.Join(s.directory, "candidate-"+manifest.Version)
	if _, err := os.Lstat(finalPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return "", errors.New("update version is already staged")
		}
		return "", err
	}
	if err := os.Rename(temporary, finalPath); err != nil {
		return "", fmt.Errorf("install staged update: %w", err)
	}
	return finalPath, nil
}
