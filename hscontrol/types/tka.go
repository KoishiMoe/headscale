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
