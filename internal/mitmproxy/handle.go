package mitmproxy

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/ddkwork/mitmproxy/internal/socks"

	"github.com/ddkwork/mitmproxy/packet"
)

type (
	Handle interface {
		Serve()
		ServeTls()
		packet.SessionEventCallBacker
	}
	HandleFunc func(*packet.Session)
	WebSocket  struct {
		err error
		*packet.Session
	}
	Http struct {
		transport http.RoundTripper
		*packet.Session
	}
	Kcp     struct{ *packet.Session }
	Pipe    struct{ *packet.Session }
	Quic    struct{ *packet.Session }
	Rpc     struct{ *packet.Session }
	Socket4 struct {
		*packet.Session
		*socks.Socks4Handler
	}
	Socket5 struct {
		*packet.Session
		*socks.Socks5Handler
	}
	Ssh struct{ *packet.Session }
	Tcp struct{ *packet.Session }
	Udp struct{ *packet.Session }
)

func NewTcp(s *packet.Session) Handle       { return &Tcp{Session: s} }
func NewSocket5(s *packet.Session) Handle   { return &Socket5{Session: s} }
func NewSocket4(s *packet.Session) Handle   { return &Socket4{Session: s} }
func NewWebSocket(s *packet.Session) Handle { return &WebSocket{Session: s} }
func NewHttp(s *packet.Session) Handle {
	return &Http{
		transport: &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			OnProxyConnectResponse: nil,
			DialContext:            nil,
			Dial:                   nil,
			DialTLSContext:         nil,
			DialTLS:                nil,
			TLSClientConfig: &tls.Config{
				GetClientCertificate: func(info *tls.CertificateRequestInfo) (certificate *tls.Certificate, e error) {
					return nil, errClientCertRequested
				},
			},
			TLSHandshakeTimeout:    tlsHandshakeTimeout,
			DisableKeepAlives:      false,
			DisableCompression:     true,
			MaxIdleConns:           10,
			MaxIdleConnsPerHost:    10,
			MaxConnsPerHost:        10,
			IdleConnTimeout:        defaultTimeout,
			ResponseHeaderTimeout:  defaultTimeout,
			ExpectContinueTimeout:  time.Second,
			TLSNextProto:           make(map[string]func(string, *tls.Conn) http.RoundTripper),
			ProxyConnectHeader:     nil,
			GetProxyConnectHeader:  nil,
			MaxResponseHeaderBytes: 4096 * 10,
			WriteBufferSize:        4096 * 10,
			ReadBufferSize:         4096 * 10,
			ForceAttemptHTTP2:      false,
		},
		Session: s,
	}
}

// todo
// func NewUdp(s *Session) Handle       { return &Udp{Session: s} }
// func NewRpc(s *Session) Handle       { return &Rpc{Session: s} }
// func NewQuic(s *Session) Handle      { return &Quic{Session: s} }
// func NewPipe(s *Session) Handle      { return &Pipe{Session: s} }
// func NewKcp(s *Session) Handle       { return &Kcp{Session: s} }
// func NewSsh(s *Session) Handle       { return &Ssh{Session: s} }
