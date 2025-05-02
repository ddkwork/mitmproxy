package mitmproxy

import (
	"io"
	"net"
	"time"

	"github.com/ddkwork/golibrary/mylog"
)

func TcpKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		mylog.Check(tcp.SetKeepAlive(true))
		mylog.Check(tcp.SetKeepAlivePeriod(3 * time.Second))
	}
}

type PeekedConn struct {
	net.Conn
	Reader io.Reader
}

func (c *PeekedConn) Read(buf []byte) (int, error) { return c.Reader.Read(buf) }
