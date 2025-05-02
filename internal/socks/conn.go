package socks

import (
	"bufio"
	"context"
	"encoding"
	"errors"
	"io"
	"net"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/mitmproxy/packet"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Listener interface {
	Listen(ctx context.Context, network string, address string) (net.Listener, error)
}

type Conn struct {
	*packet.Session
	Reader  *bufio.Reader
	Writer  io.Writer
	SendBuf []byte
	RecvBuf []byte
}

func NewConn(conn net.Conn) *Conn {
	return &Conn{
		Reader:  bufio.NewReader(conn),
		Writer:  conn,
		SendBuf: make([]byte, 0),
		RecvBuf: make([]byte, 0),
	}
}

func (c *Conn) Peek(n int) ([]byte, error) { return c.Reader.Peek(n) }

func (c *Conn) Read(req encoding.BinaryUnmarshaler) error {
	buff := make([]byte, 1024)
	n := mylog.Check2(c.Reader.Read(buff))
	mylog.Check(req.UnmarshalBinary(buff[:n]))
	c.RecvBuf = buff[:n]
	return nil
}

func (c *Conn) Write(resp encoding.BinaryMarshaler) error {
	b := mylog.Check2(resp.MarshalBinary())
	c.SendBuf = b
	mylog.Check2(c.Writer.Write(b))
	return nil
}

func (c *Conn) SessionEvent(session *packet.Session) {
	switch session.StreamDirection {
	case packet.Inbound:
		mylog.HexDump(session.SchemerType.String()+" "+session.StreamDirection.String(), session.ReqBodyDecoder.Payload)
	case packet.Outbound:
		mylog.HexDump(session.SchemerType.String()+" "+session.StreamDirection.String(), session.RespBodyDecoder.Payload)
	}
}

func (c *Conn) Tunnel(target net.Conn) error {
	errCh := make(chan error, 2)

	go c.proxy(target, c.Reader, errCh, packet.Outbound)
	go c.proxy(c.Writer, target, errCh, packet.Inbound)

	for range 2 {
		e := <-errCh
		if e != nil {
			return e
		}
	}

	return nil
}

func (c *Conn) WaitForClose() {
	buf := make([]byte, 1)

	for {
		if _, e := c.Reader.Read(buf[:]); e == io.EOF {
			break
		}
	}
}

func (c *Conn) proxy(dst io.Writer, src io.Reader, errCh chan error, direction packet.StreamDirection) {
	//_, err := io.Copy(dst, src)
	_, e := c.copyBuffer(dst, src, nil, direction)
	if tcpConn, ok := dst.(*net.TCPConn); ok {
		mylog.Check(tcpConn.CloseWrite())
	}
	errCh <- e
}

func (c *Conn) copyBuffer(dst io.Writer, src io.Reader, buf []byte, direction packet.StreamDirection) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}

	var written int64

	for {
		nr, err := src.Read(buf)
		if err != nil && err != io.EOF && !errors.Is(err, context.Canceled) {
			mylog.Info("Proxy read error during body copy", err)
		}
		if nr > 0 {
			c.Session.StreamDirection = direction
			switch direction {
			case packet.Inbound:
				c.Session.ReqBodyDecoder.Payload = buf[:nr]
			case packet.Outbound:
				c.Session.RespBodyDecoder.Payload = buf[:nr]
			}
			if c.Session.EventCallBack == nil {
				c.SessionEvent(c.Session)
			} else {
				c.EventCallBack(c.Session)
			}
			nw := mylog.Check2(dst.Write(buf[:nr]))
			if nw > 0 {
				written += int64(nw)
			}

			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if mylog.Check(err) {
			return written, nil
		}
		return written, err
	}
}
