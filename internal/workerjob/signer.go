package workerjob

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"mossward/internal/model"
)

const (
	signingKeyFile   = "worker-job-signing-key.pem"
	signingKeyMode   = 0o600
	algorithmEd25519 = "Ed25519"
)

type Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
}

func LoadOrCreateSigner(directory string) (*Signer, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create worker-job signing directory: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(directory, 0o700); err != nil {
			return nil, fmt.Errorf("secure worker-job signing directory: %w", err)
		}
	}
	path := filepath.Join(directory, signingKeyFile)
	privateKey, err := loadOrCreateSigningKey(path)
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(publicKey)
	return &Signer{privateKey: privateKey, publicKey: publicKey, keyID: hex.EncodeToString(digest[:16])}, nil
}

func (s *Signer) Sign(job model.WorkerJob) (model.SignedWorkerJob, error) {
	payload, err := canonicalJob(job)
	if err != nil {
		return model.SignedWorkerJob{}, err
	}
	signature := ed25519.Sign(s.privateKey, payload)
	return model.SignedWorkerJob{Algorithm: algorithmEd25519, KeyID: s.keyID, Job: job,
		Signature: base64.RawStdEncoding.EncodeToString(signature)}, nil
}

func (s *Signer) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.publicKey...)
}

func (s *Signer) KeyID() string { return s.keyID }

func Verify(envelope model.SignedWorkerJob, publicKey ed25519.PublicKey) error {
	if envelope.Algorithm != algorithmEd25519 {
		return errors.New("unsupported worker-job signature algorithm")
	}
	digest := sha256.Sum256(publicKey)
	if envelope.KeyID != hex.EncodeToString(digest[:16]) {
		return errors.New("worker-job signing key identifier mismatch")
	}
	signature, err := base64.RawStdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return errors.New("worker-job signature is invalid")
	}
	payload, err := canonicalJob(envelope.Job)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("worker-job signature verification failed")
	}
	return nil
}

func canonicalJob(job model.WorkerJob) ([]byte, error) {
	return json.Marshal(job)
}

func loadOrCreateSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if runtime.GOOS != "windows" {
			info, statErr := os.Stat(path)
			if statErr != nil || info.Mode().Perm()&0o077 != 0 {
				return nil, errors.New("worker-job signing key permissions are too broad")
			}
		}
		return parseSigningKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read worker-job signing key: %w", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate worker-job signing key: %w", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("encode worker-job signing key: %w", err)
	}
	data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, signingKeyMode)
	if err != nil {
		return nil, fmt.Errorf("write worker-job signing key: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write worker-job signing key: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("sync worker-job signing key: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close worker-job signing key: %w", err)
	}
	return privateKey, nil
}

func parseSigningKey(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid worker-job signing key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid worker-job signing key")
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("worker-job signing key is not Ed25519")
	}
	return privateKey, nil
}
