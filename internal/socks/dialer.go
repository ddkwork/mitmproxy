package socks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/hupe1980/golog"

	"github.com/ddkwork/golibrary/std/mylog"
)

type Socks4DialerOptions struct {
	UserID string

	// Logger specifies an optional Logger.
	// If nil, logging is done via the log package's standard Logger.
	Logger golog.Logger

	// ProxyDialer specifies the optional dialer for
	// establishing the transport connection.
	ProxyDialer Dialer
}

type Socks4Dialer struct {
	*Logger
	cmd          Command
	proxyNetwork string // network between a proxy server and a client
	proxyAddress string // proxy server address
	proxyDialer  Dialer
	userID       string
}

// NewSocks4Dialer returns a new Socks4Dialer that dials through the provided
// proxy server's network and address.
func NewSocks4Dialer(network, address string, optFns ...func(*Socks4DialerOptions)) *Socks4Dialer {
	options := Socks4DialerOptions{
		Logger:      golog.NewGoLogger(golog.INFO, log.Default()),
		ProxyDialer: &net.Dialer{},
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &Socks4Dialer{
		Logger:       &Logger{options.Logger},
		cmd:          ConnectCommand,
		proxyNetwork: network,
		proxyAddress: address,
		proxyDialer:  options.ProxyDialer,
		userID:       options.UserID,
	}
}

func (d *Socks4Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Socks4Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn := mylog.Check2(d.proxyDialer.DialContext(ctx, d.proxyNetwork, d.proxyAddress))
	socksConn := NewConn(conn)
	mylog.Check(socksConn.Write(&Socks4Request{
		CMD:    ConnectCommand,
		Addr:   addr,
		UserID: d.userID,
	}))

	resp := &Socks4Response{}
	mylog.Check(socksConn.Read(resp))
	if resp.Status != Socks4StatusGranted {
		return nil, fmt.Errorf("socks error: %v", resp.Status)
	}
	return conn, nil
}

type Socks5DialerOptions struct {
	// Logger specifies an optional Logger.
	// If nil, logging is done via the log package's standard Logger.
	Logger golog.Logger

	// ProxyDialer specifies the optional dialer for
	// establishing the transport connection.
	ProxyDialer Dialer

	// AuthMethods specifies the list of request authentication
	// methods.
	// If empty, SOCKS client requests only AuthMethodNotRequired.
	AuthMethods []AuthMethod

	// Authenticate specifies the optional authentication
	// function. It must be non-nil when AuthMethods is not empty.
	// It must return an error when the authentication is failed.
	Authenticate AuthenticateFunc
}

type Socks5Dialer struct {
	*Logger
	cmd          Command
	proxyNetwork string // network between a proxy server and a client
	proxyAddress string // proxy server address
	proxyDialer  Dialer
	authMethods  []AuthMethod
	authenticate AuthenticateFunc
}

// NewSocks5Dialer returns a new Socks5Dialer that dials through the provided
// proxy server's network and address.
func NewSocks5Dialer(network, address string, optFns ...func(*Socks5DialerOptions)) *Socks5Dialer {
	options := Socks5DialerOptions{
		Logger:      golog.NewGoLogger(golog.INFO, log.Default()),
		ProxyDialer: &net.Dialer{},
		AuthMethods: []AuthMethod{AuthMethodNotRequired},
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &Socks5Dialer{
		Logger:       &Logger{options.Logger},
		cmd:          ConnectCommand,
		proxyNetwork: network,
		proxyAddress: address,
		proxyDialer:  options.ProxyDialer,
		authMethods:  options.AuthMethods,
		authenticate: options.Authenticate,
	}
}

func (d *Socks5Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn := mylog.Check2(d.proxyDialer.DialContext(ctx, d.proxyNetwork, d.proxyAddress))
	socksConn := NewConn(conn)
	mylog.Check(socksConn.Write(&MethodSelectRequest{
		Methods: d.authMethods,
	}))
	methodSelectResp := &MethodSelectResponse{}
	mylog.Check(socksConn.Read(methodSelectResp))
	// If the selected METHOD is X'FF', none of the methods listed by the
	// client are acceptable, and the client MUST close the connection.
	if methodSelectResp.Method == AuthMethodNoAcceptableMethods {
		mylog.Check(conn.Close())
		return nil, errors.New("no authentication method accepted")
	}

	if d.authenticate != nil {
		mylog.Check(d.authenticate(ctx, socksConn, methodSelectResp.Method))
	}
	mylog.Check(socksConn.Write(&Socks5Request{
		CMD:  ConnectCommand,
		Addr: addr,
	}))
	// todo func (pc *persistConn) readResponse(r

	resp := &Socks5Response{}
	mylog.Check(socksConn.Read(resp))
	if resp.Status != Socks5StatusGranted {
		return nil, fmt.Errorf("socks error: %v", resp.Status)
	}
	return conn, nil
}

func (d *Socks5Dialer) ReadResponse(dst io.Writer, src io.Reader, buf []byte) {
	// copyBuffer(dst, src, buf, nil, nil) //todo
}
