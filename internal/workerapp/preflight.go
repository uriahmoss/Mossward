package workerapp

// CheckConfig validates configuration and reads the TLS identity, without
// connecting to the server or opening/creating worker state.
func CheckConfig(config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	_, _, _, err := loadWorkerTLSIdentity(config)
	return err
}
