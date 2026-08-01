package serverbackup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mossward/internal/auth"
	"mossward/internal/store"
)

const (
	FormatVersion       = 1
	maximumArchiveBytes = 1 << 30
	maximumArchiveFiles = 10000
)

type Source struct {
	IdentityKeyFile string
	ACMECacheDir    string
	AgentPKIDir     string
}

type Manifest struct {
	FormatVersion int             `json:"format_version"`
	CreatedAt     time.Time       `json:"created_at"`
	SchemaVersion int             `json:"schema_version"`
	Files         []ManifestEntry `json:"files"`
}

type ManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func Create(output string, repository *store.SQLiteStore, source Source, now time.Time) error {
	temporary, err := os.MkdirTemp("", "mossward-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	databaseSnapshot := filepath.Join(temporary, "mossward.db")
	if err := repository.BackupSQLite(databaseSnapshot); err != nil {
		return err
	}
	schemaVersion, err := store.ValidateSQLiteSnapshot(databaseSnapshot)
	if err != nil {
		return err
	}
	files := map[string]string{"database/mossward.db": databaseSnapshot, "identity/identity.key": source.IdentityKeyFile}
	if err := addDirectory(files, source.ACMECacheDir, "acme"); err != nil {
		return err
	}
	if err := addDirectory(files, source.AgentPKIDir, "agent-pki"); err != nil {
		return err
	}
	return writeArchive(output, files, schemaVersion, now)
}

func addDirectory(files map[string]string, source, archiveRoot string) error {
	info, err := os.Stat(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("backup source %q is not a directory", source)
	}
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("backup source contains unsupported symbolic link %q", path)
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(filepath.Join(archiveRoot, relative))] = path
		return nil
	})
}

func writeArchive(output string, files map[string]string, schemaVersion int, now time.Time) (resultErr error) {
	if err := os.MkdirAll(filepath.Dir(output), 0o750); err != nil {
		return err
	}
	file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create backup archive: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); resultErr == nil {
			resultErr = closeErr
		}
		if resultErr != nil {
			_ = os.Remove(output)
		}
	}()
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	manifest := Manifest{FormatVersion: FormatVersion, CreatedAt: now.UTC(), SchemaVersion: schemaVersion}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		entry, err := writeFile(tarWriter, path, files[path])
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, entry)
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := tarWriter.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(manifestJSON)), ModTime: now}); err != nil {
		return err
	}
	if _, err := tarWriter.Write(manifestJSON); err != nil {
		return err
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	return gzipWriter.Close()
}

func writeFile(writer *tar.Writer, archivePath, sourcePath string) (ManifestEntry, error) {
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return ManifestEntry{}, fmt.Errorf("read backup source %q: %w", sourcePath, err)
	}
	if archivePath == "identity/identity.key" {
		if err := auth.ValidateIdentityKeyData(data); err != nil {
			return ManifestEntry{}, fmt.Errorf("identity key is invalid: %w", err)
		}
	}
	digest := sha256.Sum256(data)
	header := &tar.Header{Name: archivePath, Mode: 0o600, Size: int64(len(data)), ModTime: time.Now().UTC()}
	if err := writer.WriteHeader(header); err != nil {
		return ManifestEntry{}, err
	}
	if _, err := writer.Write(data); err != nil {
		return ManifestEntry{}, err
	}
	return ManifestEntry{Path: archivePath, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(data))}, nil
}

func Inspect(path string) (Manifest, error) {
	directory, manifest, err := extractAndValidate(path)
	if directory != "" {
		_ = os.RemoveAll(directory)
	}
	return manifest, err
}

func extractAndValidate(path string) (string, Manifest, error) {
	directory, err := os.MkdirTemp("", "mossward-restore-")
	if err != nil {
		return "", Manifest{}, err
	}
	fail := func(err error) (string, Manifest, error) {
		_ = os.RemoveAll(directory)
		return "", Manifest{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return fail(err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(io.LimitReader(file, maximumArchiveBytes))
	if err != nil {
		return fail(err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	var totalSize int64
	var fileCount int
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fail(err)
		}
		if header.Typeflag != tar.TypeReg || !safeArchivePath(header.Name) || header.Size < 0 || header.Size > maximumArchiveBytes {
			return fail(fmt.Errorf("unsafe backup entry %q", header.Name))
		}
		totalSize += header.Size
		fileCount++
		if totalSize > maximumArchiveBytes {
			return fail(errors.New("backup expands beyond the maximum supported size"))
		}
		if fileCount > maximumArchiveFiles {
			return fail(errors.New("backup contains too many files"))
		}
		destination := filepath.Join(directory, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return fail(err)
		}
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return fail(err)
		}
		_, copyErr := io.CopyN(output, tarReader, header.Size)
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil {
			return fail(errors.Join(copyErr, closeErr))
		}
	}
	manifestData, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return fail(errors.New("backup manifest is missing"))
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil || manifest.FormatVersion != FormatVersion {
		return fail(errors.New("backup manifest is invalid or unsupported"))
	}
	if err := validateExtracted(directory, manifest); err != nil {
		return fail(err)
	}
	return directory, manifest, nil
}

func validateExtracted(directory string, manifest Manifest) error {
	required := map[string]bool{"database/mossward.db": false, "identity/identity.key": false}
	expected := map[string]bool{"manifest.json": true}
	for _, entry := range manifest.Files {
		if !safeArchivePath(entry.Path) {
			return fmt.Errorf("unsafe manifest path %q", entry.Path)
		}
		data, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(entry.Path)))
		if err != nil || int64(len(data)) != entry.Size {
			return fmt.Errorf("backup entry %q is missing or has the wrong size", entry.Path)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != entry.SHA256 {
			return fmt.Errorf("backup entry %q failed its SHA-256 check", entry.Path)
		}
		if _, ok := required[entry.Path]; ok {
			required[entry.Path] = true
		}
		if expected[entry.Path] {
			return fmt.Errorf("duplicate manifest entry %q", entry.Path)
		}
		expected[entry.Path] = true
	}
	if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, _ := filepath.Rel(directory, path)
		if !expected[filepath.ToSlash(relative)] {
			return fmt.Errorf("backup contains unmanifested entry %q", relative)
		}
		return nil
	}); err != nil {
		return err
	}
	for path, found := range required {
		if !found {
			return fmt.Errorf("required backup entry %q is missing", path)
		}
	}
	identity, _ := os.ReadFile(filepath.Join(directory, "identity", "identity.key"))
	if err := auth.ValidateIdentityKeyData(identity); err != nil {
		return fmt.Errorf("identity key is invalid: %w", err)
	}
	version, err := store.ValidateSQLiteSnapshot(filepath.Join(directory, "database", "mossward.db"))
	if err != nil {
		return err
	}
	if version != manifest.SchemaVersion {
		return fmt.Errorf("backup schema version does not match its manifest")
	}
	return nil
}

func safeArchivePath(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	return path != "" && clean == path && !strings.HasPrefix(clean, "/") && clean != ".." && !strings.HasPrefix(clean, "../")
}
