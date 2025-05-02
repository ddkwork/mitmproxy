package socks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ddkwork/golibrary/assert"
	"github.com/ddkwork/golibrary/mylog"
)

var testServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	_ = mylog.Check2(rw.Write([]byte("hello")))
}))

var userPassServerAuthenticateFuncGen = func(user, pass string) AuthenticateFunc {
	return func(ctx context.Context, conn *Conn, am AuthMethod) error {
		authReq := &UsernamePasswordAuthRequest{}
		if readErr := conn.Read(authReq); readErr != nil {
			return readErr
		}

		authResp := &UsernamePasswordAuthResponse{
			Status: AuthStatusFailure,
		}
		if authReq.Username == user && authReq.Password == pass {
			authResp.Status = AuthStatusSuccess
		}

		if writeErr := conn.Write(authResp); writeErr != nil {
			return writeErr
		}

		return nil
	}
}

var userPassDialerAuthenticateFuncGen = func(user, pass string) AuthenticateFunc {
	return func(ctx context.Context, conn *Conn, am AuthMethod) error {
		if writeErr := conn.Write(&UsernamePasswordAuthRequest{
			Username: user,
			Password: pass,
		}); writeErr != nil {
			return writeErr
		}

		authResp := &UsernamePasswordAuthResponse{}
		if readErr := conn.Read(authResp); readErr != nil {
			return readErr
		}

		if authResp.Status == AuthStatusSuccess {
			return nil
		}

		return errors.New("authentication failure")
	}
}

func TestSocks5WithStdDialer(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		listen := mylog.Check2(net.Listen("tcp", "localhost:0"))
		defer listen.Close()
		server := New()
		go func() {
			mylog.Check(server.Serve(listen))
		}()
		cli := testServer.Client()
		cli.Transport = &http.Transport{
			Proxy: func(request *http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("socks5://%s", listen.Addr()))
			},
		}
		resp := mylog.Check2(cli.Get(testServer.URL))
		defer resp.Body.Close()
		body := mylog.Check2(io.ReadAll(resp.Body))
		assert.Equal(t, "hello", string(body))
	})

	t.Run("auth success", func(t *testing.T) {
		listen := mylog.Check2(net.Listen("tcp", "localhost:0"))
		defer listen.Close()
		server := New(func(o *Options) {
			o.AuthMethods = []AuthMethod{AuthMethodUsernamePassword}
			o.Authenticate = userPassServerAuthenticateFuncGen("user", "pass")
		})
		go func() {
			mylog.Check(server.Serve(listen))
		}()
		cli := testServer.Client()
		cli.Transport = &http.Transport{
			Proxy: func(request *http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("socks5://%s:%s@%s", "user", "pass", listen.Addr()))
			},
		}
		resp := mylog.Check2(cli.Get(testServer.URL))
		defer resp.Body.Close()
		body := mylog.Check2(io.ReadAll(resp.Body))
		assert.Equal(t, "hello", string(body))
	})

	t.Run("auth failure", func(t *testing.T) {
		listen := mylog.Check2(net.Listen("tcp", "localhost:0"))
		defer listen.Close()
		server := New(func(o *Options) {
			o.AuthMethods = []AuthMethod{AuthMethodUsernamePassword}
			o.Authenticate = userPassServerAuthenticateFuncGen("user", "pass")
		})
		go func() {
			mylog.Check(server.Serve(listen))
		}()
		cli := testServer.Client()
		cli.Transport = &http.Transport{
			Proxy: func(request *http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("socks5://%s:%s@%s", "user", "wrong", listen.Addr()))
			},
		}
		mylog.Check2(cli.Get(testServer.URL)) //nolint: bodyclose //error expected
	})
}

func TestSocks5Connect(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		listen := mylog.Check2(net.Listen("tcp", "localhost:0"))
		defer listen.Close()
		server := New()
		go func() {
			mylog.Check(server.Serve(listen))
		}()
		cli := testServer.Client()
		cli.Transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := NewSocks5Dialer("tcp", listen.Addr().String())
				return d.DialContext(ctx, network, addr)
			},
		}
		resp := mylog.Check2(cli.Get(testServer.URL))
		defer resp.Body.Close()
		body := mylog.Check2(io.ReadAll(resp.Body))
		assert.Equal(t, "hello", string(body))
	})

	t.Run("auth success", func(t *testing.T) {
		listen := mylog.Check2(net.Listen("tcp", "localhost:0"))
		defer listen.Close()
		server := New(func(o *Options) {
			o.AuthMethods = []AuthMethod{AuthMethodUsernamePassword}
			o.Authenticate = userPassServerAuthenticateFuncGen("user", "pass")
		})
		go func() {
			mylog.Check(server.Serve(listen))
		}()
		cli := testServer.Client()
		cli.Transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := NewSocks5Dialer("tcp", listen.Addr().String(), func(o *Socks5DialerOptions) {
					o.AuthMethods = []AuthMethod{AuthMethodUsernamePassword}
					o.Authenticate = userPassDialerAuthenticateFuncGen("user", "pass")
				})

				return d.DialContext(ctx, network, addr)
			},
		}
		resp := mylog.Check2(cli.Get(testServer.URL))
		defer resp.Body.Close()
		body := mylog.Check2(io.ReadAll(resp.Body))
		assert.Equal(t, "hello", string(body))
	})

	t.Run("auth failure", func(t *testing.T) {
		listen := mylog.Check2(net.Listen("tcp", "localhost:0"))
		defer listen.Close()
		server := New(func(o *Options) {
			o.AuthMethods = []AuthMethod{AuthMethodUsernamePassword}
			o.Authenticate = userPassServerAuthenticateFuncGen("user", "pass")
		})
		go func() {
			mylog.Check(server.Serve(listen))
		}()
		cli := testServer.Client()
		cli.Transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := NewSocks5Dialer("tcp", listen.Addr().String(), func(o *Socks5DialerOptions) {
					o.AuthMethods = []AuthMethod{AuthMethodUsernamePassword}
					o.Authenticate = userPassDialerAuthenticateFuncGen("user", "wrong")
				})

				return d.DialContext(ctx, network, addr)
			},
		}
		mylog.Check2(cli.Get(testServer.URL)) //nolint: bodyclose //error expected
	})
}
