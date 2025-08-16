package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // nolint: gosec // ok
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/ddkwork/golibrary/std/mylog"
)

var DefaultTLSServerConfig = &tls.Config{
	MinVersion: tls.VersionTLS12,
	NextProtos: []string{"http/1.1"},
	// Accept client certs without verifying them
	// Note that we will still verify remote server certs
	InsecureSkipVerify: true, // nolint: gosec // ok
}

type CertTemplateGenFunc func(serial *big.Int, ski []byte, hostname, organization string, validity time.Duration) *x509.Certificate

type Options struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
	// Organization (will be used for generated certificates)
	Organization string
	// Validity of the generated certificates
	Validity time.Duration
	// NewConfig structure is used to configure the TLS server.
	TLSServerConfig *tls.Config
	// Storage for generated certificates
	CertTemplateGen CertTemplateGenFunc
	// Logger specifies an optional logger.
	// If nil, logging is done via the log package's standard logger.
}

// Config is a set of configuration values that are used to build TLS configs
// capable of MITM.
type Config struct {
	ca           *x509.Certificate // Root certificate authority
	caPrivateKey crypto.PrivateKey // CA private key
	// roots is a CertPool that contains the root CA GetOrCreateCert
	// it serves a single purpose -- to verify the cached domain certs
	roots      *x509.CertPool
	privateKey crypto.Signer
	validity   time.Duration
	// SKI to use in generated certificates (https://tools.ietf.org/html/rfc3280#section-4.2.1.2)
	keyID           []byte
	organization    string
	tlsServerConfig *tls.Config
	certTemplateGen CertTemplateGenFunc
}

func NewConfig(optFns ...func(*Options)) *Config {
	options := Options{
		Organization:    "github.com/ddkwork/mitmproxy",
		Validity:        time.Hour,
		TLSServerConfig: DefaultTLSServerConfig,
	}
	for _, fn := range optFns {
		fn(&options)
	}
	if options.Certificate == nil || options.PrivateKey == nil {
		ca, privateKey := NewCA()
		options.Certificate = ca
		options.PrivateKey = privateKey
	}
	if options.CertTemplateGen == nil {
		options.CertTemplateGen = func(serial *big.Int, ski []byte, hostname, organization string, validity time.Duration) *x509.Certificate {
			tmpl := &x509.Certificate{
				SerialNumber: serial,
				Subject: pkix.Name{
					CommonName:   hostname,
					Organization: []string{organization},
				},
				SubjectKeyId:          ski,
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				NotBefore:             time.Now().Add(-validity),
				NotAfter:              time.Now().Add(validity),
			}
			if ip := net.ParseIP(hostname); ip != nil {
				tmpl.IPAddresses = []net.IP{ip}
			} else {
				tmpl.DNSNames = []string{hostname}
			}
			return tmpl
		}
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(options.Certificate)
	// Generating the private key that will be used for domain certificates
	signer := makeSigner(options.PrivateKey)
	publicKey := signer.Public()
	// Subject Label Identifier support for end entity certificate.
	// https://tools.ietf.org/html/rfc3280#section-4.2.1.2
	PkixPublicKey := mylog.Check2(x509.MarshalPKIXPublicKey(publicKey))
	// nolint: gosec // ok
	h := sha1.New()
	mylog.Check2(h.Write(PkixPublicKey))
	return &Config{
		ca:              options.Certificate,
		caPrivateKey:    options.PrivateKey,
		privateKey:      signer,
		keyID:           h.Sum(nil),
		validity:        options.Validity,
		organization:    options.Organization,
		tlsServerConfig: options.TLSServerConfig,
		certTemplateGen: options.CertTemplateGen,
		roots:           certPool,
	}
}

// CA returns the authority cert
func (c *Config) CA() *x509.Certificate { return c.ca }

// NewTlsConfigForHost creates a *tls.Config that will generate
// domain certificates on-the-fly using the SNI extension (if specified)
// or the hostname
func (c *Config) NewTlsConfigForHost(hostname string) *tls.Config {
	if c.tlsServerConfig == nil {
		// c.tlsServerConfig = mylog.Check2( c.GetOrCreateCert(hostname))
	}
	// deepcopy.Clone(c.tlsServerConfig) // todo test
	tlsConfig := c.tlsServerConfig.Clone()
	tlsConfig.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		host := clientHello.ServerName
		if host == "" {
			host = hostname
		}
		return c.GetOrCreateCert(host)
	}
	tlsConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		if info.ServerName == "" {
			info.ServerName = hostname
		}
		return nil, nil
	}
	mylog.Struct(tlsConfig)
	return tlsConfig
}

// GetOrCreateCert gets or creates a certificate for the specified hostname
func (c *Config) GetOrCreateCert(hostname string) (*tls.Certificate, error) {
	// Remove the port if it exists.
	host, _, e := net.SplitHostPort(hostname)
	if e == nil {
		hostname = host
	}
	tlsCertificate, b := CertPool.Get(hostname)
	if b {
		mylog.Info("Cache hit for", hostname)
		// Check validity of the certificate for hostname match, expiry, etc. In
		// particular, if the cached certificate has expired, create a new one.
		mylog.Check2(tlsCertificate.Leaf.Verify(x509.VerifyOptions{
			DNSName: hostname,
			Roots:   c.roots,
		}))
		return tlsCertificate, nil
		// mylog.Info("Invalid certificate in the cache for %s", hostname)
	}
	mylog.Info("Cache miss for", hostname)
	serial := mylog.Check2(rand.Int(rand.Reader, MaxSerialNumber))
	tmpl := c.certTemplateGen(serial, c.keyID, hostname, c.organization, c.validity)
	raw := mylog.Check2(x509.CreateCertificate(rand.Reader, tmpl, c.ca, c.privateKey.Public(), c.caPrivateKey))
	// Parse certificate bytes so that we have a leaf certificate.
	x509c := mylog.Check2(x509.ParseCertificate(raw))
	tlsCertificate = &tls.Certificate{
		Certificate: [][]byte{raw, c.ca.Raw},
		PrivateKey:  c.privateKey,
		Leaf:        x509c,
	}
	CertPool.Update(hostname, tlsCertificate)
	return tlsCertificate, nil
}

func makeSigner(privateKey crypto.PrivateKey) crypto.Signer {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return mylog.Check2(rsa.GenerateKey(rand.Reader, 2048))
	case *ecdsa.PrivateKey:
		return mylog.Check2(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	default:
		mylog.Check(fmt.Errorf("unsupported key type %T", privateKey))
		return nil
	}
}
