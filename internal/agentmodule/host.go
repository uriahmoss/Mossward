package agentmodule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func RunNative(ctx context.Context, packageRoot string, manifest Manifest, request HostRequest) (HostResult, error) {
	if manifest.Kind != KindNative || request.SchemaVersion != 1 || request.ModuleID != manifest.ID {
		return HostResult{}, errors.New("native module host request is invalid")
	}
	if !samePermissions(request.Permissions, manifest.Permissions) {
		return HostResult{}, errors.New("native module requested undeclared permissions")
	}
	root, err := filepath.Abs(packageRoot)
	if err != nil {
		return HostResult{}, err
	}
	executable := filepath.Join(root, manifest.Entrypoint)
	resolved, err := filepath.Abs(executable)
	if err != nil || filepath.Dir(resolved) != root {
		return HostResult{}, errors.New("native module entrypoint escapes its package")
	}
	if info, err := os.Lstat(resolved); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return HostResult{}, errors.New("native module entrypoint is not a regular file")
	}
	moduleContext, cancel := context.WithTimeout(ctx, time.Duration(manifest.TimeoutSeconds)*time.Second)
	defer cancel()
	input, err := json.Marshal(request)
	if err != nil {
		return HostResult{}, err
	}
	command := exec.CommandContext(moduleContext, resolved)
	command.Dir, command.Env, command.Stdin = root, moduleEnvironment(), bytes.NewReader(input)
	var output limitedBuffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		return HostResult{}, fmt.Errorf("native module failed: %w", err)
	}
	var result HostResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.SchemaVersion != 1 || result.ModuleID != manifest.ID {
		return HostResult{}, errors.New("native module returned an invalid result")
	}
	return result, nil
}

func samePermissions(left, right []Permission) bool {
	if len(left) != len(right) {
		return false
	}
	wanted := map[Permission]bool{}
	for _, permission := range right {
		wanted[permission] = true
	}
	for _, permission := range left {
		if !wanted[permission] {
			return false
		}
	}
	return true
}

func moduleEnvironment() []string {
	allowed := []string{"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR", "LANG"}
	environment := make([]string, 0, len(allowed)+1)
	for _, name := range allowed {
		if value, ok := os.LookupEnv(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	return append(environment, "MOSSWARD_MODULE_HOST=1")
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(value []byte) (int, error) {
	if b.Len()+len(value) > MaximumResultBytes {
		return 0, errors.New("module result exceeds limit")
	}
	return b.Buffer.Write(value)
}

func ValidatePackageFiles(root string, manifest Manifest) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"package.bin": true, "envelope.json": true}
	if manifest.Kind == KindNative {
		allowed[manifest.Entrypoint] = true
	}
	for _, entry := range entries {
		if entry.IsDir() || !allowed[entry.Name()] || strings.HasPrefix(entry.Name(), ".") {
			return errors.New("module package contains an undeclared file")
		}
	}
	return nil
}
