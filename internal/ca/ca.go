package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
)

// MaxSerialNumber is the upper boundary that is used to create unique serial
// numbers for the certificate. This can be any unsigned integer up to 20
// bytes (2^(8*20)-1).
var MaxSerialNumber = big.NewInt(0).SetBytes(bytes.Repeat([]byte{255}, 20))

type Option struct {
	Name         string
	Organization string
	Validity     time.Duration
}

// NewCA creates a new Certificate and associated private key.
func NewCA(optFns ...func(*Option)) (*x509.Certificate, *rsa.PrivateKey) {
	options := Option{
		Name:         "github.com/ddkwork/mitmproxy ca",
		Organization: "github.com/ddkwork/mitmproxy",
		Validity:     24 * time.Hour,
	}
	for _, fn := range optFns {
		fn(&options)
	}
	privateKey := mylog.Check2(rsa.GenerateKey(rand.Reader, 2048))
	publicKey := privateKey.Public()
	tmpl := &x509.Certificate{
		SerialNumber: mylog.Check2(rand.Int(rand.Reader, MaxSerialNumber)),
		Subject: pkix.Name{
			CommonName:   options.Name,
			Organization: []string{options.Organization},
		},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-options.Validity),
		NotAfter:              time.Now().Add(options.Validity),
		DNSNames:              []string{options.Name},
		IsCA:                  true,
	}
	raw := mylog.Check2(x509.CreateCertificate(rand.Reader, tmpl, tmpl, publicKey, privateKey))
	// Parse certificate bytes so that we have a leaf certificate.
	return mylog.Check2(x509.ParseCertificate(raw)), privateKey
}

func LoadCA(certFile, keyFile string) (*x509.Certificate, crypto.PrivateKey, bool) {
	if !stream.IsFilePathEx(certFile) || !stream.IsFilePathEx(keyFile) {
		return nil, nil, false
	}
	keyPair := mylog.Check2(tls.LoadX509KeyPair(certFile, keyFile))
	cert := mylog.Check2(x509.ParseCertificate(keyPair.Certificate[0]))
	return cert, keyPair.PrivateKey, true
}

func LoadOrCreateCA(certFile, keyFile string, optFns ...func(*Option)) (cert *x509.Certificate, privateKey crypto.PrivateKey) {
	ok := false
	cert, privateKey, ok = LoadCA(certFile, keyFile)
	if !ok {
		cert, privateKey = NewCA(optFns...)
	}
	certOut := mylog.Check2(os.Create(certFile))
	defer func() { mylog.Check(certOut.Close()) }()
	keyOut := mylog.Check2(os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600))
	defer func() { mylog.Check(keyOut.Close()) }()
	mylog.Check(pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	keyBytes := mylog.Check2(x509.MarshalPKCS8PrivateKey(privateKey))
	mylog.Check(pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	return cert, privateKey
}

type certHandler struct{ cert []byte }

// NewCertHandler returns a http.Handler that will present the client
// with the Certificate to use in browser.
func NewCertHandler(ca *x509.Certificate) http.Handler {
	return &certHandler{
		cert: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.Raw,
		}),
	}
}

// ServeHTTP writes the Certificate in PEM format to the client.
func (h *certHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/x-x509-ca-cert")
	mylog.Check2(rw.Write(h.cert))
}
