package socks

import (
	"testing"

	"github.com/ddkwork/golibrary/assert"
	"github.com/ddkwork/golibrary/mylog"
)

func TestSocks4Request(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		req := &Socks4Request{
			CMD:  ConnectCommand,
			Addr: "127.0.0.1:8080",
		}
		b := mylog.Check2(req.MarshalBinary())
		req2 := &Socks4Request{}
		mylog.Check(req2.UnmarshalBinary(b))
		assert.Equal(t, req, req2)
	})

	t.Run("v4 with userID", func(t *testing.T) {
		req := &Socks4Request{
			CMD:    ConnectCommand,
			Addr:   "127.0.0.1:8080",
			UserID: "xyz",
		}
		b := mylog.Check2(req.MarshalBinary())
		req2 := &Socks4Request{}
		mylog.Check(req2.UnmarshalBinary(b))
		assert.Equal(t, req, req2)
	})

	t.Run("v4a", func(t *testing.T) {
		req := &Socks4Request{
			CMD:  ConnectCommand,
			Addr: "localhost:8080",
		}
		b := mylog.Check2(req.MarshalBinary())
		req2 := &Socks4Request{}
		mylog.Check(req2.UnmarshalBinary(b))
		assert.Equal(t, req, req2)
	})

	t.Run("v4a with userID", func(t *testing.T) {
		req := &Socks4Request{
			CMD:    ConnectCommand,
			Addr:   "localhost:8080",
			UserID: "xyz",
		}
		b := mylog.Check2(req.MarshalBinary())
		req2 := &Socks4Request{}
		mylog.Check(req2.UnmarshalBinary(b))
		assert.Equal(t, req, req2)
	})
}

func TestSocks4Response(t *testing.T) {
	t.Run("connect", func(t *testing.T) {
		resp := &Socks4Response{
			Status: Socks4StatusGranted,
			Addr:   "",
		}

		b := mylog.Check2(resp.MarshalBinary())
		resp2 := &Socks4Response{}
		mylog.Check(resp2.UnmarshalBinary(b))
		assert.Equal(t, resp, resp2)
	})

	t.Run("bind", func(t *testing.T) {
		resp := &Socks4Response{
			Status: Socks4StatusGranted,
			Addr:   "127.0.0.1:5566",
		}
		b := mylog.Check2(resp.MarshalBinary())
		resp2 := &Socks4Response{}
		mylog.Check(resp2.UnmarshalBinary(b))
		assert.Equal(t, resp, resp2)
	})
}

func TestMethodSelectRequest(t *testing.T) {
	t.Run("single method", func(t *testing.T) {
		req := &MethodSelectRequest{
			Methods: []AuthMethod{AuthMethodNotRequired},
		}

		b := mylog.Check2(req.MarshalBinary())
		req2 := &MethodSelectRequest{}
		mylog.Check(req2.UnmarshalBinary(b))
		assert.Equal(t, req, req2)
	})

	t.Run("multi methods", func(t *testing.T) {
		req := &MethodSelectRequest{
			Methods: []AuthMethod{AuthMethodNotRequired, AuthMethodUsernamePassword},
		}

		b := mylog.Check2(req.MarshalBinary())
		req2 := &MethodSelectRequest{}
		mylog.Check(req2.UnmarshalBinary(b))
		assert.Equal(t, req, req2)
	})
}

func TestMethodSelectResponse(t *testing.T) {
	resp := &MethodSelectResponse{
		Method: AuthMethodNotRequired,
	}

	b := mylog.Check2(resp.MarshalBinary())
	resp2 := &MethodSelectResponse{}
	mylog.Check(resp2.UnmarshalBinary(b))
	assert.Equal(t, resp, resp2)
}

func TestUsernamePasswordAuthRequest(t *testing.T) {
	req := &UsernamePasswordAuthRequest{
		Username: "User",
		Password: "Pass",
	}

	b := mylog.Check2(req.MarshalBinary())
	req2 := &UsernamePasswordAuthRequest{}
	mylog.Check(req2.UnmarshalBinary(b))
	assert.Equal(t, req, req2)
}

func TestUsernamePasswordAuthResponse(t *testing.T) {
	resp := &UsernamePasswordAuthResponse{
		Status: AuthStatusSuccess,
	}

	b := mylog.Check2(resp.MarshalBinary())
	resp2 := &UsernamePasswordAuthResponse{}
	mylog.Check(resp2.UnmarshalBinary(b))
	assert.Equal(t, resp, resp2)
}

func TestSocks5Request(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		req := &Socks5Request{
			CMD:  ConnectCommand,
			Addr: "127.0.0.1:8080",
		}

		b := mylog.Check2(req.MarshalBinary())
		req2 := &Socks5Request{}
		mylog.Check(req2.UnmarshalBinary(b))
		assert.Equal(t, req, req2)
	})

	t.Run("IPv6", func(t *testing.T) {
		req := &Socks5Request{
			CMD:  ConnectCommand,
			Addr: "[::1]:8080",
		}

		b := mylog.Check2(req.MarshalBinary())
		req2 := &Socks5Request{}
		mylog.Check(req2.UnmarshalBinary(b))
		assert.Equal(t, req, req2)
	})

	t.Run("FQDN", func(t *testing.T) {
		req := &Socks5Request{
			CMD:  ConnectCommand,
			Addr: "localhost:8080",
		}

		b := mylog.Check2(req.MarshalBinary())
		req2 := &Socks5Request{}
		mylog.Check(req2.UnmarshalBinary(b))
		assert.Equal(t, req, req2)
	})
}

func TestSocks5Response(t *testing.T) {
	t.Run("connect", func(t *testing.T) {
		resp := &Socks5Response{
			Status: Socks5StatusFailure,
		}

		b := mylog.Check2(resp.MarshalBinary())
		resp2 := &Socks5Response{}
		mylog.Check(resp2.UnmarshalBinary(b))
		assert.Equal(t, resp, resp2)
	})

	t.Run("bind", func(t *testing.T) {
		resp := &Socks5Response{
			Status: Socks5StatusGranted,
			Addr:   "127.0.0.1:5544",
		}

		b := mylog.Check2(resp.MarshalBinary())
		resp2 := &Socks5Response{}
		mylog.Check(resp2.UnmarshalBinary(b))
		assert.Equal(t, resp, resp2)
	})
}
