//go:build windows

package agentupdate

import "errors"

var ErrRestartRequired = errors.New("endpoint-agent restart required to complete update")

func Activate(string, string, string, Transaction) error {
	return errors.New("Windows endpoint-agent activation requires the stopped-service update helper")
}
