package socks

import (
	"fmt"
	"log"
	"net"

	"github.com/hupe1980/golog"

	"github.com/ddkwork/golibrary/mylog"
)

type Options struct {
	// Logger specifies an optional Logger.
	// If nil, logging is done via the log package's standard Logger.
	Logger golog.Logger

	Dialer Dialer

	Listener Listener

	// Ident specifies the optional ident function.
	// It must return an error when the ident is failed.
	Ident IdentFunc

	// AuthMethods specifies the list of supported authentication
	// methods.
	// If empty, SOCKS server supports AuthMethodNotRequired.
	AuthMethods []AuthMethod

	// Authenticate specifies the optional authentication
	// function. It must be non-nil when AuthMethods is not empty.
	// It must return an error when the authentication is failed.
	Authenticate AuthenticateFunc
}

type Server struct {
	*Logger
	dialer       Dialer
	listener     Listener
	ident        IdentFunc
	authMethods  []AuthMethod
	authenticate AuthenticateFunc
}

func New(optFns ...func(*Options)) *Server {
	options := Options{
		Logger:      golog.NewGoLogger(golog.INFO, log.Default()),
		Dialer:      &net.Dialer{},
		Listener:    &net.ListenConfig{},
		AuthMethods: []AuthMethod{AuthMethodNotRequired},
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &Server{
		Logger:       &Logger{options.Logger},
		dialer:       options.Dialer,
		listener:     options.Listener,
		ident:        options.Ident,
		authMethods:  options.AuthMethods,
		authenticate: options.Authenticate,
	}
}

func ListenAndServe(addr string) error {
	server := New()
	return server.ListenAndServe(addr)
}

func (s *Server) ListenAndServe(addr string) error {
	l := mylog.Check2(net.Listen("tcp", addr))
	return s.Serve(l)
}

// Serve serves connections from a listener
func (s *Server) Serve(l net.Listener) error {
	defer func() {
		mylog.Check(l.Close())
	}()

	for {
		conn := mylog.Check2(l.Accept())
		go func() {
			mylog.Check(s.handleConnection(conn))
		}()
	}
}

func (s *Server) handleConnection(conn net.Conn) error {
	defer func() {
		mylog.Check(conn.Close())
	}()
	socksConn := NewConn(conn)
	version := mylog.Check2(socksConn.Peek(3))
	switch Version(version[0]) {
	case Socks4Version:
		socks4Handler := &Socks4Handler{
			Dialer: s.dialer,
			Conn:   socksConn,
		}

		return socks4Handler.Handle()
	case Socks5Version:
		socks5Handler := &Socks5Handler{
			Dialer:       s.dialer,
			Conn:         socksConn,
			AuthMethods:  s.authMethods,
			Authenticate: s.authenticate,
		}

		return socks5Handler.Handle()
	default:
		return fmt.Errorf("unsupported socks version: %d", version[0])
	}
}
