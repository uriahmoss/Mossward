//go:build windows

package agentupdate

import "time"

func Recover(string, string, time.Time) error {
	return nil
}
