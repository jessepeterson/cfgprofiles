# Structs and helpers for working with Apple Configuration Profiles in go.

Package `cfgprofiles` provides structs and helpers for working with Apple Configuration Profiles in go.

[![Go Reference](https://pkg.go.dev/badge/github.com/jessepeterson/cfgprofiles.svg)](https://pkg.go.dev/github.com/jessepeterson/cfgprofiles)

*Note:* marshaling and unmarshaling are dependent on the https://github.com/micromdm/plist package.

Example unmarshaling (parsing):

```go
b, _ := ioutil.ReadFile("profile.mobileconfig")
p := &cfgprofiles.Profile{}
_ := plist.Unmarshal(b, p)
fmt.Println(p.PayloadIdentifier)
// returns: "com.my.profile.id"
```

Example marshaling:

```go
p := cfgprofiles.NewProfile("com.my.profile.id")
pld := cfgprofiles.NewCertificatePKCS1Payload("com.my.profile.id.payload")
cert, _ := x509.ParseCertificate(certBytes)
pld.PayloadContent = cert.Raw
p.AddPayload(pld)
b, _ := plist.Marshal(p)
fmt.Println(string(b))
// returns "<?xml version="1.0" encod [...] <key>PayloadContent</key><data>MIIEPjCCAy [...]"
```
