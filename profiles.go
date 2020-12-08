// Package cfgprofiles provides structs and helpers for working with Apple Configuration Profiles in go.
// Note that marshaling and unmarshaling are dependent on the https://github.com/groob/plist package.
package cfgprofiles

import (
	"time"
)

// Profile represents an Apple Configuration Profile.
// See https://developer.apple.com/documentation/devicemanagement/toplevel
type Profile struct {
	Payload
	PayloadContent           []payloadWrapper
	PayloadExpirationDate    *time.Time        `plist:",omitempty"`
	PayloadRemovalDisallowed bool              `plist:",omitempty"`
	PayloadScope             string            `plist:",omitempty"`
	PayloadDate              *time.Time        `plist:",omitempty"`
	DurationUntilRemoval     float32           `plist:",omitempty"`
	ConsentText              map[string]string `plist:",omitempty"`
	EncryptedPayloadContent  []byte            `plist:",omitempty"`
	HasRemovalPasscode       bool              `plist:",omitempty"`
	IsEncrypted              bool              `plist:",omitempty"`
	RemovalDate              *time.Time        `plist:",omitempty"`
	TargetDeviceType         int               `plist:",omitempty"`
}

// NewProfile creates a new Configuration Profile struct with identifier i
func NewProfile(i string) *Profile {
	return &Profile{
		Payload: *NewPayload("Configuration", i),
	}
}

// AddPayload adds a payload struct to the profile. Properly wraps the type for
// correct property list marshalling.
func (p *Profile) AddPayload(pld interface{}) {
	p.PayloadContent = append(
		p.PayloadContent,
		payloadWrapper{Payload: pld},
	)
}
