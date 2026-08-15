//go:build !linux && !windows

package agentapp

import (
	"errors"
	"mossward/internal/model"
)

func platformPostureEvidence() ([]model.PostureEvidence, error) {
	return nil, errors.New("security-posture evidence is supported only on Linux and Windows")
}
