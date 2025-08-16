package ca

import (
	"crypto/tls"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/ddkwork/golibrary/std/mylog"
	"github.com/ddkwork/golibrary/std/safemap"
	"github.com/ddkwork/golibrary/std/stream"
	"github.com/ddkwork/golibrary/std/stream/net/httpClient"
)

var (
	Cfg            *Config
	ProxyPort      = "7890"
	FileServerPort = "7777"
	CertFile       = ""
	KeyFile        = ""
	CertPool       = safemap.New[string, *tls.Certificate]()
)

func init() {
	homeDir := stream.HomeDir()
	CertFile = filepath.Join(homeDir, "ca.crt")
	KeyFile = filepath.Join(homeDir, "ca.key")

	mylog.Call(func() {
		cert, key := LoadOrCreateCA(CertFile, KeyFile, func(c *Option) {
			c.Validity = 365 * 24 * time.Hour
		})
		Cfg = NewConfig(func(m *Options) {
			m.Certificate = cert
			m.PrivateKey = key
		})
	})
	go func() {
		mylog.Warning("ListenAndServe", ProxyServeAddress())
		mylog.Trace("Cert FileServer", "http://"+ProxyFileServerAddress())
		mylog.CheckIgnore(http.ListenAndServe(ProxyFileServerAddress(), http.FileServer(http.Dir(homeDir))))
	}()
}

func ProxyServeAddress() string      { return net.JoinHostPort(httpClient.Localhost, ProxyPort) }
func ProxyFileServerAddress() string { return net.JoinHostPort(httpClient.Localhost, FileServerPort) }
