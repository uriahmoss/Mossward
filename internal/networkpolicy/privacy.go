package networkpolicy

type PrivacyGuarantees struct {
	CollectionMode                string   `json:"collection_mode"`
	PayloadCaptureSupported       bool     `json:"payload_capture_supported"`
	TLSInterceptionSupported      bool     `json:"tls_interception_supported"`
	CertificateInjectionSupported bool     `json:"certificate_injection_supported"`
	DNSPacketCaptureSupported     bool     `json:"dns_packet_capture_supported"`
	RuntimeMutable                bool     `json:"runtime_mutable"`
	CollectedFields               []string `json:"collected_fields"`
}

func PrivacyContract() PrivacyGuarantees {
	return PrivacyGuarantees{
		CollectionMode: "metadata_only",
		CollectedFields: []string{
			"protocol", "local_address", "local_port", "remote_address",
			"remote_port", "process_id", "process_name", "executable",
			"remote_hostname", "hostname_source", "tls_server_name", "direction",
		},
	}
}
