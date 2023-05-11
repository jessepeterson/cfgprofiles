package cfgprofiles

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/groob/plist"
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
		return &CertificatePKCS1Payload{}
	case "com.apple.mdm":
		return &MDMPayload{}
	case "com.apple.security.scep":
		return &SCEPPayload{}
	case "com.apple.security.acme":
		return &ACMECertificatePayload{}
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

// CommonPayload returns the common Payload struct of a profile payload i or returns nil.
func CommonPayload(i interface{}) *Payload {
	switch pl := i.(type) {
	case *CertificatePKCS1Payload:
		return &pl.Payload
	case *SCEPPayload:
		return &pl.Payload
	case *ACMECertificatePayload:
		return &pl.Payload
	case *MDMPayload:
		return &pl.Payload
	case *Payload:
		return pl
	default:
		return nil
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

// CertificatePKCS1Payload represents the "com.apple.security.pkcs1" PayloadType.
// See https://developer.apple.com/documentation/devicemanagement/certificatepkcs1
type CertificatePKCS1Payload struct {
	Payload
	PayloadCertificateFileName string `plist:",omitempty"`
	PayloadContent             []byte
}

// NewCertificatePKCS1Payload creates a new payload with identifier i
func NewCertificatePKCS1Payload(i string) *CertificatePKCS1Payload {
	return &CertificatePKCS1Payload{
		Payload: *NewPayload("com.apple.security.pkcs1", i),
	}
}

// CertificatePKCS1Payloads returns a slice of all payloads of that type
func (p *Profile) CertificatePKCS1Payloads() (plds []*CertificatePKCS1Payload) {
	for _, pc := range p.PayloadContent {
		if pld, ok := pc.Payload.(*CertificatePKCS1Payload); ok {
			plds = append(plds, pld)
		}
	}
	return
}

// SCEPPayloadContent represents the PayloadContent of the SCEPPayload
// See https://developer.apple.com/documentation/devicemanagement/scep/payloadcontent
type SCEPPayloadContent struct {
	URL                string
	Name               string          `plist:",omitempty"`
	Subject            [][][]string    `plist:",omitempty"`
	Challenge          string          `plist:",omitempty"`
	KeySize            int             `plist:"Keysize,omitempty"`
	KeyType            string          `plist:"Key Type,omitempty"`
	KeyUsage           int             `plist:"Key Usage,omitempty"`
	Retries            int             `plist:",omitempty"`
	RetryDelay         int             `plist:",omitempty"`
	CAFingerprint      []byte          `plist:",omitempty"`
	AllowAllAppsAccess bool            `plist:",omitempty"`
	KeyIsExtractable   *bool           `plist:",omitempty"` // default true
	SubjectAltName     *SubjectAltName `plist:",omitempty"`
}

// SCEPPayload represents the "com.apple.security.scep" PayloadType.
// See https://developer.apple.com/documentation/devicemanagement/scep
type SCEPPayload struct {
	Payload
	PayloadContent SCEPPayloadContent
}

// NewSCEPPayload creates a new payload with identifier i
func NewSCEPPayload(i string) *SCEPPayload {
	return &SCEPPayload{
		Payload: *NewPayload("com.apple.security.scep", i),
	}
}

// SCEPPayloads returns a slice of all payloads of that type
func (p *Profile) SCEPPayloads() (plds []*SCEPPayload) {
	for _, pc := range p.PayloadContent {
		if pld, ok := pc.Payload.(*SCEPPayload); ok {
			plds = append(plds, pld)
		}
	}
	return
}

// SubjectAltName contains the Subject Alternative Name details.
// See https://developer.apple.com/documentation/devicemanagement/acmecertificate/subjectaltname
//
// For SCEP, this is mentioned about the number of entries:
// You can specify a single string or an array of strings for each key.
// The values you specify depend on the CA you're using but might
// include DNS name, URL, or email values. The assumption is the
// same is true for ACME.
//
// Single key/string example:
//
// <key>SubjectAltName</key>
// <dict>
// <key>dNSName</key>
// <string>site.example.com</string>
// </dict>
//
// Example for key with multiple strings:
//
// <dict>
// <key>dNSName</key>
// <string>site.example.com</string>
// <key>rfc822Name</key>
// <array>
// <string>alice@example.com</string>
// <string>bob@example.com</string>
// </array>
// </dict>
type SubjectAltName struct {
	DNSNames     multiString `plist:"dNSName,omitempty"`
	NTPrincipals multiString `plist:"ntPrincipalName,omitempty"`
	RFC822Names  multiString `plist:"rfc822Name,omitempty"`
	URIs         multiString `plist:"uniformResourceIdentifier,omitempty"`
}

type multiString []string

// UnmarshalPlist unmarshals the contents of a [multiString], which can
// be either a single value or an array of strings.
func (m *multiString) UnmarshalPlist(f func(interface{}) error) error {
	var trySingle string
	err := f(&trySingle)
	if err == nil {
		*m = []string{trySingle}
		return nil
	}

	var tryMulti []string
	err = f(&tryMulti)
	if err == nil {
		*m = tryMulti
		return nil
	}

	var umterr plist.UnmarshalTypeError
	if errors.As(err, &umterr) {
		umterr.Type = reflect.TypeOf(*m) // override type to cfgprofiles.multiString
		return umterr
	}

	// fallback error; this is the most information we can provide
	return fmt.Errorf("cannot unmarshal value into %T: %w", *m, err)
}

// MarshalPlist marshals the contents of a [multiString], which can
// be either a single value or slice of strings.
func (m *multiString) MarshalPlist() (interface{}, error) {
	switch n := *m; len(n) {
	case 0:
		return nil, fmt.Errorf("cannot marshal empty %T", n)
	case 1:
		return n[0], nil
	default:
		return append([]string{}, n...), nil
	}
}

// ACMECertificatePayload represents the "com.apple.security.acme" PayloadType.
// See https://developer.apple.com/documentation/devicemanagement/acmecertificate
type ACMECertificatePayload struct {
	Payload
	AllowAllAppsAccess bool            `plist:",omitempty"`
	Attest             bool            `plist:",omitempty"`
	ClientIdentifier   string          `plist:",omitempty"`
	DirectoryURL       string          `plist:",omitempty"`
	ExtendedKeyUsage   []string        `plist:",omitempty"`
	HardwareBound      bool            `plist:",omitempty"`
	KeySize            int             `plist:",omitempty"`
	KeyIsExtractable   *bool           `plist:",omitempty"` // default true
	KeyType            string          `plist:",omitempty"` // Possible values: RSA, ECSECPrimeRandom
	Subject            [][][]string    `plist:",omitempty"` // Example: [ [ ["C", "US"] ], [ ["O", "Apple Inc."] ], ..., [ [ "1.2.5.3", "bar" ] ] ]
	UsageFlags         int             `plist:",omitempty"`
	SubjectAltName     *SubjectAltName `plist:",omitempty"`
}

// NewACMECertificatePayload creates a new payload with identifier i
func NewACMECertificatePayload(i string) *ACMECertificatePayload {
	return &ACMECertificatePayload{
		Payload: *NewPayload("com.apple.security.acme", i),
	}
}

// ACMECertificatePayloads returns a slice of all payloads of that type
func (p *Profile) ACMECertificatePayloads() (plds []*ACMECertificatePayload) {
	for _, pc := range p.PayloadContent {
		if pld, ok := pc.Payload.(*ACMECertificatePayload); ok {
			plds = append(plds, pld)
		}
	}
	return
}

// MDMPayload represents the "com.apple.mdm" PayloadType.
// See https://developer.apple.com/documentation/devicemanagement/mdm
type MDMPayload struct {
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

// NewMDMPayload creates a new payload with identifier i
func NewMDMPayload(i string) *MDMPayload {
	return &MDMPayload{
		Payload: *NewPayload("com.apple.mdm", i),
	}
}

// MDMPayloads returns a slice of all payloads of that type
func (p *Profile) MDMPayloads() (plds []*MDMPayload) {
	for _, pc := range p.PayloadContent {
		if pld, ok := pc.Payload.(*MDMPayload); ok {
			plds = append(plds, pld)
		}
	}
	return
}
