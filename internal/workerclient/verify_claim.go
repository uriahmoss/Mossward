package workerclient

import (
	"crypto/ed25519"
	"errors"
	"time"

	"mossward/internal/model"
	"mossward/internal/workerjob"
)

func VerifyAndClaim(envelope model.SignedWorkerJob, publicKey ed25519.PublicKey, worker model.ScannerWorker, ledger *ReplayLedger, now time.Time) error {
	if ledger == nil {
		return errors.New("scanner-worker replay ledger is unavailable")
	}
	if err := workerjob.VerifyForWorker(envelope, publicKey, worker, now); err != nil {
		return err
	}
	return ledger.Claim(envelope, now)
}
