package workerevidence

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"mossward/internal/model"
)

const (
	algorithmECDSASHA256  = "ECDSA-SHA256"
	algorithmRSAPSSSHA256 = "RSA-PSS-SHA256"
)

func Sign(batch model.WorkerEvidenceBatch, certificate *x509.Certificate, signer crypto.Signer) (model.SignedWorkerEvidenceBatch, error) {
	if certificate == nil || signer == nil || certificate.SerialNumber == nil {
		return model.SignedWorkerEvidenceBatch{}, errors.New("worker evidence signing identity is unavailable")
	}
	algorithm, options, err := signingParameters(signer.Public())
	if err != nil {
		return model.SignedWorkerEvidenceBatch{}, err
	}
	if !publicKeysEqual(certificate.PublicKey, signer.Public()) {
		return model.SignedWorkerEvidenceBatch{}, errors.New("worker evidence signer does not match its certificate")
	}
	payload, err := canonicalBatch(batch)
	if err != nil {
		return model.SignedWorkerEvidenceBatch{}, err
	}
	digest := sha256.Sum256(payload)
	signature, err := signer.Sign(rand.Reader, digest[:], options)
	if err != nil {
		return model.SignedWorkerEvidenceBatch{}, fmt.Errorf("sign worker evidence batch: %w", err)
	}
	return model.SignedWorkerEvidenceBatch{Algorithm: algorithm, CertificateSerial: certificate.SerialNumber.String(),
		Batch: batch, Signature: base64.RawStdEncoding.EncodeToString(signature)}, nil
}

func Verify(envelope model.SignedWorkerEvidenceBatch, certificate *x509.Certificate) error {
	if certificate == nil || certificate.SerialNumber == nil || envelope.CertificateSerial != certificate.SerialNumber.String() {
		return errors.New("worker evidence certificate identity mismatch")
	}
	payload, err := canonicalBatch(envelope.Batch)
	if err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return errors.New("worker evidence signature is invalid")
	}
	digest := sha256.Sum256(payload)
	switch publicKey := certificate.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if envelope.Algorithm != algorithmECDSASHA256 || !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
			return errors.New("worker evidence signature verification failed")
		}
	case *rsa.PublicKey:
		if envelope.Algorithm != algorithmRSAPSSSHA256 || rsa.VerifyPSS(publicKey, crypto.SHA256, digest[:], signature, nil) != nil {
			return errors.New("worker evidence signature verification failed")
		}
	default:
		return errors.New("worker evidence certificate key type is unsupported")
	}
	return nil
}

func signingParameters(publicKey crypto.PublicKey) (string, crypto.SignerOpts, error) {
	switch publicKey.(type) {
	case *ecdsa.PublicKey:
		return algorithmECDSASHA256, crypto.SHA256, nil
	case *rsa.PublicKey:
		return algorithmRSAPSSSHA256, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}, nil
	default:
		return "", nil, errors.New("worker evidence signing key type is unsupported")
	}
}

func publicKeysEqual(left, right crypto.PublicKey) bool {
	leftEncoded, leftErr := x509.MarshalPKIXPublicKey(left)
	rightEncoded, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && string(leftEncoded) == string(rightEncoded)
}

func canonicalBatch(batch model.WorkerEvidenceBatch) ([]byte, error) {
	return json.Marshal(batch)
}
