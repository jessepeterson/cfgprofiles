# Structs and helpers for working with Apple Configuration Profiles in go.

Package `cfgprofiles` provides structs and helpers for working with Apple Configuration Profiles in go.

[Documentation at godoc.org](https://godoc.org/github.com/jessepeterson/cfgprofiles)

Example unmarshaling (parsing):

```go
pBytes, _ := ioutil.ReadFile("profile.mobileconfig")
p := &cfgprofiles.Profile{}
_ := plist.Unmarshal(plBytes, p)
fmt.Println(p.PayloadIdentifier)
// returns: "com.my.profile.id"
```

Example marshaling:

```go
p := cfgprofiles.NewProfile("com.my.profile.id")
pld := cfgprofiles.NewCertificatePKCS1Payload("com.my.profile.id.payload")
cert, _ := x509.ParseCertificate(certBytes)
pld.PayloadContent = cert.Raw
p.AddPayload(pl)
pBytes, _ := plist.Marshal(p)
fmt.Println(string(pBytes))
// returns "<?xml version="1.0" encod [...] <key>PayloadContent</key><data>MIIEPjCCAy [...]"
```
