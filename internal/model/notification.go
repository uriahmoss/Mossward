package model

type SMTPSettings struct {
	Enabled            bool     `json:"enabled"`
	Host               string   `json:"host"`
	Port               int      `json:"port"`
	Username           string   `json:"username"`
	PasswordCiphertext []byte   `json:"-"`
	HasPassword        bool     `json:"has_password"`
	FromAddress        string   `json:"from_address"`
	TLSMode            string   `json:"tls_mode"`
	RecipientUserIDs   []string `json:"recipient_user_ids"`
}
type SMTPConfiguration struct {
	SMTPSettings
	Password string `json:"password"`
}
