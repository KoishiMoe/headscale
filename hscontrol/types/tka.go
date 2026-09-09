package types

import "time"

// TKAState records the persistent Tailnet Key Authority (TKA) state for the tailnet.
type TKAState struct {
	ID                uint   `gorm:"primary_key"`
	Enabled           bool   `gorm:"column:enabled;default:false"`
	Head              string `gorm:"column:head"`
	DisablementSecret []byte `gorm:"column:disablement_secret"`
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func (TKAState) TableName() string {
	return "tka_states"
}

// TKAAUM records an Authority Update Message (AUM) in the TKA hash chain.
type TKAAUM struct {
	Hash       string `gorm:"column:hash;primary_key"`
	ParentHash string `gorm:"column:parent_hash;index:idx_tka_aums_parent_hash"`
	Data       []byte `gorm:"column:data"`
	CreatedAt  time.Time
}

func (TKAAUM) TableName() string {
	return "tka_aums"
}

// TKALockStatus describes the overall Tailnet Key Authority (TKA) lock status.
type TKALockStatus struct {
	ConfigEnabled           bool            `json:"configEnabled"`
	Enabled                 bool            `json:"enabled"`
	Head                    string          `json:"head,omitempty"`
	DisablementSecretsCount int             `json:"disablementSecretsCount"`
	TrustedKeys             []TKATrustedKey `json:"trustedKeys"`
	Summary                 TKASummary      `json:"summary"`
}

// TKATrustedKey describes a trusted signing key in the TKA.
type TKATrustedKey struct {
	KeyID     string            `json:"keyId"`
	PublicKey string            `json:"publicKey"`
	Votes     uint              `json:"votes"`
	Kind      string            `json:"kind"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// TKASummary provides high-level node counts relative to tailnet lock.
type TKASummary struct {
	TotalNodes      int `json:"totalNodes"`
	SignedNodes     int `json:"signedNodes"`
	AuthorizedNodes int `json:"authorizedNodes"`
	UnsignedNodes   int `json:"unsignedNodes"`
}

// TKANodeLockStatus describes the tailnet lock status of an individual node.
type TKANodeLockStatus struct {
	ID           string `json:"id"`
	Hostname     string `json:"hostname"`
	GivenName    string `json:"givenName"`
	Owner        string `json:"owner"`
	NodeKey      string `json:"nodeKey"`
	Signed       bool   `json:"signed"`
	Authorized   bool   `json:"authorized"`
	SigningKeyID string `json:"signingKeyId,omitempty"`
}
