package cfgprofiles

import (
	"strings"

	"github.com/google/uuid"
)

// payloadWrapper is a wrapper around a profile payload struct.
// It exists to implement custom Plist marshal/unmarshal logic required
// for correctly parsing arbitrary profile payloads in a profile.
type payloadWrapper struct {
	Payload interface{}
}

// UnmarshalPlist tries to find the matching payload struct to unmarshal.
func (p *payloadWrapper) UnmarshalPlist(f func(interface{}) error) error {
	plType := struct {
		PayloadType string
	}{}
	err := f(&plType)
	if err != nil {
		return err
	}
	plStruct := newPayloadForType(plType.PayloadType)
	err = f(plStruct)
	if err != nil {
		return err
	}
	p.Payload = plStruct
	return nil
}

// MarshalPlist returns the wrapped payload struct to marshal.
func (p *payloadWrapper) MarshalPlist() (interface{}, error) {
	return p.Payload, nil
}

// newPayloadForType instantiates an empty payload struct given PayloadType t.
func newPayloadForType(t string) interface{} {
	switch t {
	case "com.apple.security.pkcs1":
		return &ComAppleSecurityPkcs1Payload{}
	case "com.apple.mdm":
		return &ComAppleMDMPayload{}
	case "com.apple.security.scep":
		return &ComAppleSecuritySCEPPayload{}
	default:
		return &Payload{}
	}
}

// Payload contains payload keys common to all payloads. Including profiles.
// See https://developer.apple.com/documentation/devicemanagement/configuring_multiple_devices_using_profiles#3234127
type Payload struct {
	PayloadDescription  string `plist:",omitempty"`
	PayloadDisplayName  string `plist:",omitempty"`
	PayloadIdentifier   string
	PayloadOrganization string `plist:",omitempty"`
	PayloadUUID         string
	PayloadType         string
	PayloadVersion      int
}

// NewPayload creates a new 'raw' payload with a random UUID, type t and identifier i.
func NewPayload(t, i string) *Payload {
	return &Payload{
		PayloadIdentifier: i,
		PayloadUUID:       strings.ToUpper(uuid.New().String()),
		PayloadType:       t,
		PayloadVersion:    1,
	}
}

// UnknownPayloads returns a slice of profile payloads not matched to specific payload structs.
func (p *Profile) UnknownPayloads() (plds []*Payload) {
	for _, pc := range p.PayloadContent {
		if pld, ok := pc.Payload.(*Payload); ok {
			plds = append(plds, pld)
		}
	}
	return
}

// ComAppleSecurityPkcs1Payload represents the "com.apple.security.pkcs1" PayloadType.
// See https://developer.apple.com/documentation/devicemanagement/certificatepkcs1
type ComAppleSecurityPkcs1Payload struct {
	Payload
	PayloadCertificateFileName string `plist:",omitempty"`
	PayloadContent             []byte
}

// NewComAppleSecurityPkcs1Payload creates a new payload with identifier i
func NewComAppleSecurityPkcs1Payload(i string) *ComAppleSecurityPkcs1Payload {
	return &ComAppleSecurityPkcs1Payload{
		Payload: *NewPayload("com.apple.security.pkcs1", i),
	}
}

// ComAppleSecurityPkcs1Payloads returns a slice of all payloads of that type
func (p *Profile) ComAppleSecurityPkcs1Payloads() (plds []*ComAppleSecurityPkcs1Payload) {
	for _, pc := range p.PayloadContent {
		if pld, ok := pc.Payload.(*ComAppleSecurityPkcs1Payload); ok {
			plds = append(plds, pld)
		}
	}
	return
}

// ComAppleSecuritySCEPPayload represents the "com.apple.security.scep" PayloadType.
// See https://developer.apple.com/documentation/devicemanagement/scep
type ComAppleSecuritySCEPPayload struct {
	Payload
	URL                string
	Name               string       `plist:",omitempty"`
	Subject            [][][]string `plist:",omitempty"`
	Challenge          string       `plist:",omitempty"`
	KeySize            int          `plist:"Keysize,omitempty"`
	KeyType            string       `plist:"Key Type,omitempty"`
	KeyUsage           int          `plist:"Key Usage,omitempty"`
	Retries            int          `plist:",omitempty"`
	RetryDelay         int          `plist:",omitempty"`
	CAFingerprint      []byte       `plist:",omitempty"`
	AllowAllAppsAccess bool         `plist:",omitempty"`
	KeyIsExtractable   *bool        `plist:",omitempty"` // default true
	// TODO: SubjectAltName *SubjectAltName `plist:",omitempty"`
}

// NewComAppleSecuritySCEPPayload creates a new payload with identifier i
func NewComAppleSecuritySCEPPayload(i string) *ComAppleSecuritySCEPPayload {
	return &ComAppleSecuritySCEPPayload{
		Payload: *NewPayload("com.apple.security.scep", i),
	}
}

// ComAppleSecuritySCEPPayloads returns a slice of all payloads of that type
func (p *Profile) ComAppleSecuritySCEPPayloads() (plds []*ComAppleSecuritySCEPPayload) {
	for _, pc := range p.PayloadContent {
		if pld, ok := pc.Payload.(*ComAppleSecuritySCEPPayload); ok {
			plds = append(plds, pld)
		}
	}
	return
}

// ComAppleMDMPayload represents the "com.apple.mdm" PayloadType.
// See https://developer.apple.com/documentation/devicemanagement/mdm
type ComAppleMDMPayload struct {
	Payload
	IdentityCertificateUUID           string
	Topic                             string
	ServerURL                         string
	ServerCapabilities                []string `plist:",omitempty"`
	SignMessage                       bool     `plist:",omitempty"`
	CheckInURL                        string   `plist:",omitempty"`
	CheckOutWhenRemoved               bool     `plist:",omitempty"`
	AccessRights                      int
	UseDevelopmentAPNS                bool     `plist:",omitempty"`
	ServerURLPinningCertificateUUIDs  []string `plist:",omitempty"`
	CheckInURLPinningCertificateUUIDs []string `plist:",omitempty"`
	PinningRevocationCheckRequired    bool     `plist:",omitempty"`
}

// NewComAppleMDMPayload creates a new payload with identifier i
func NewComAppleMDMPayload(i string) *ComAppleMDMPayload {
	return &ComAppleMDMPayload{
		Payload: *NewPayload("com.apple.mdm", i),
	}
}

// ComAppleMDMPayloads returns a slice of all payloads of that type
func (p *Profile) ComAppleMDMPayloads() (plds []*ComAppleMDMPayload) {
	for _, pc := range p.PayloadContent {
		if pld, ok := pc.Payload.(*ComAppleMDMPayload); ok {
			plds = append(plds, pld)
		}
	}
	return
}
