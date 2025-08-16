package socks

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/ddkwork/golibrary/std/assert"
	"github.com/ddkwork/golibrary/std/mylog"
)

func TestSocks4Connect(t *testing.T) {
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
				d := NewSocks4Dialer("tcp", listen.Addr().String())
				return d.DialContext(ctx, network, addr)
			},
		}
		resp := mylog.Check2(cli.Get(testServer.URL))
		defer resp.Body.Close()
		body := mylog.Check2(io.ReadAll(resp.Body))
		assert.Equal(t, "hello", string(body))
	})
}
