package cfgprofiles

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/groob/plist"
)

func GetCertData(t *testing.T) *x509.Certificate {
	r, err := ioutil.ReadFile(filepath.Join("testdata", "entrust.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(r)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// PKCS1CertProfileTest tests various aspects of our testdata profile & payload
func PKCS1CertProfileTest(p *Profile, t *testing.T) {
	profileUUID := "2689BE77-60CE-4588-83F7-7CDC494DB1AA"
	if p.PayloadUUID != profileUUID {
		t.Errorf("have %q, want %q", p.PayloadUUID, profileUUID)
	}
	profileID := "com.github.erikberglund.ProfileCreator.2689BE77-60CE-4588-83F7-7CDC494DB1AA"
	if p.PayloadIdentifier != profileID {
		t.Errorf("have %q, want %q", p.PayloadIdentifier, profileID)
	}
	if p.PayloadScope != "User" {
		t.Errorf("PayloadScope: want %q, have %q", "User", p.PayloadScope)
	}
	if len(p.PayloadContent) != 1 {
		t.Fatal("payload count is not 1")
	}

	pls := p.ComAppleSecurityPkcs1Payloads()
	if len(pls) != 1 {
		t.Fatal("payload count is not 1")
	}
	pl := pls[0]
	payloadUUID := "8BF53919-B83E-4280-A40C-0407FB6AF341"
	if pl.PayloadUUID != payloadUUID {
		t.Errorf("have %s, want %s", pl.PayloadUUID, payloadUUID)
	}
	payloadID := "com.github.erikberglund.ProfileCreator.2689BE77-60CE-4588-83F7-7CDC494DB1AA.com.apple.security.pkcs1.8BF53919-B83E-4280-A40C-0407FB6AF341"
	if pl.PayloadIdentifier != payloadID {
		t.Errorf("have %s, want %s", pl.PayloadIdentifier, payloadID)
	}
	if pl.PayloadDisplayName != "Certificate" {
		t.Errorf("PayloadDisplayName: want %q, have %q", "Certificate", p.PayloadDisplayName)
	}

	cert, err := x509.ParseCertificate(pl.PayloadContent)
	if err != nil {
		t.Fatal(err)
	}
	cn := "Entrust Root Certification Authority - G2"
	if cert.Subject.CommonName != cn {
		t.Errorf("cert CN: want %q, have %q", cn, cert.Subject.CommonName)
	}
}

// TestProfileCreation manually assembles a profile that closely resembles our test data
// It tests both this profile as well as a plist marhsalled & unmarshaled instance
func TestProfileCreation(t *testing.T) {
	p := NewProfile("com.github.erikberglund.ProfileCreator.2689BE77-60CE-4588-83F7-7CDC494DB1AA")
	p.PayloadScope = "User"
	p.PayloadUUID = "2689BE77-60CE-4588-83F7-7CDC494DB1AA" // override new UUID for test

	pl := NewComAppleSecurityPkcs1Payload("com.github.erikberglund.ProfileCreator.2689BE77-60CE-4588-83F7-7CDC494DB1AA.com.apple.security.pkcs1.8BF53919-B83E-4280-A40C-0407FB6AF341")
	pl.PayloadDisplayName = "Certificate"
	pl.PayloadUUID = "8BF53919-B83E-4280-A40C-0407FB6AF341" // override new UUID for test
	cert := GetCertData(t)
	pl.PayloadContent = cert.Raw

	p.AddPayload(pl)

	t.Run("profile", func(t *testing.T) { PKCS1CertProfileTest(p, t) })

	plBytes, err := plist.MarshalIndent(p, "\t")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("plist decode", func(t *testing.T) { PKCS1CertProfileByteTest(plBytes, t) })
}

func PKCS1CertProfileByteTest(plBytes []byte, t *testing.T) {
	p := &Profile{}
	err := plist.Unmarshal(plBytes, p)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("profile", func(t *testing.T) { PKCS1CertProfileTest(p, t) })
}

func TestProfileAndPayloadDecode(t *testing.T) {
	plBytes, err := ioutil.ReadFile(filepath.Join("testdata", "1.mobileconfig"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("plist decode", func(t *testing.T) { PKCS1CertProfileByteTest(plBytes, t) })
}
