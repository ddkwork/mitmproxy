package mitmproxy

import (
	"github.com/ddkwork/mitmproxy/internal/socks"
	"net"
	"time"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/mitmproxy/packet"
)

func (s *Socket4) SessionEvent(session *packet.Session) {
	s.Socks4Handler.EventCallBack(session)
}

func (s *Socket5) SessionEvent(session *packet.Session) {
	s.Socks5Handler.EventCallBack(session)
}

func (s *Socket4) Serve() {
	options := &socks.Options{
		Dialer: &net.Dialer{
			Timeout:       dialTimeout,
			Deadline:      time.Time{},
			LocalAddr:     nil,
			DualStack:     false,
			FallbackDelay: 0,
			KeepAlive:     dialTimeout,
			Resolver:      nil,
			Cancel:        nil,
			Control:       nil,
		},
		Listener:    &net.ListenConfig{},
		AuthMethods: []socks.AuthMethod{socks.AuthMethodNotRequired},
	}
	socksConn := &socks.Conn{
		Reader:  s.ReadWriter.Reader,
		Writer:  s.ClientConn,
		SendBuf: make([]byte, 4096),
		RecvBuf: make([]byte, 4096),
	}
	mylog.Info("Socket4 proxy")
	s.Socks4Handler = &socks.Socks4Handler{
		Session: s.Session,
		Conn:    socksConn,
		Dialer:  options.Dialer,
	}
	mylog.Check(s.Socks4Handler.Handle())
}

func (s *Socket4) ServeTls() {
	// TODO implement me
	panic("implement me")
}

func (s *Socket5) Serve() {
	options := &socks.Options{
		Dialer: &net.Dialer{
			Timeout:       dialTimeout,
			Deadline:      time.Time{},
			LocalAddr:     nil,
			DualStack:     false,
			FallbackDelay: 0,
			KeepAlive:     dialTimeout,
			Resolver:      nil,
			Cancel:        nil,
			Control:       nil,
		},
		Listener:    &net.ListenConfig{},
		AuthMethods: []socks.AuthMethod{socks.AuthMethodNotRequired},
	}
	socksConn := &socks.Conn{
		Reader:  s.ReadWriter.Reader,
		Writer:  s.ClientConn,
		SendBuf: make([]byte, 4096),
		RecvBuf: make([]byte, 4096),
	}
	mylog.Info("Socket5 proxy")
	s.Socks5Handler = &socks.Socks5Handler{
		Session:      s.Session,
		Conn:         socksConn,
		Dialer:       options.Dialer,
		AuthMethods:  options.AuthMethods,
		Authenticate: options.Authenticate,
	}
	mylog.Check(s.Socks5Handler.Handle())
}

func (s *Socket5) ServeTls() {
	// TODO implement me
	panic("implement me")
}
