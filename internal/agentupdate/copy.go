package agentupdate

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

func copyVerifiedCandidate(destination *os.File, candidate string, size int64, digest string) error {
	source, err := os.Open(candidate)
	if err != nil {
		return err
	}
	defer source.Close()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(source, size+1))
	if err != nil || written != size {
		return errors.New("candidate changed or could not be copied")
	}
	expected, _ := hex.DecodeString(digest)
	if subtle.ConstantTimeCompare(hash.Sum(nil), expected) != 1 {
		return errors.New("candidate digest changed before replacement")
	}
	return nil
}

func VerifyArtifact(path string, size int64, digest string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return errors.New("artifact size or file type does not match the update transaction")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, size+1))
	if err != nil || written != size {
		return errors.New("artifact could not be verified")
	}
	expected, err := hex.DecodeString(digest)
	if err != nil || subtle.ConstantTimeCompare(hash.Sum(nil), expected) != 1 {
		return errors.New("artifact digest does not match the update transaction")
	}
	return nil
}
