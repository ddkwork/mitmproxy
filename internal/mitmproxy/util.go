package mitmproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"

	"github.com/ddkwork/golibrary/mylog"
)

// DecodeLatin1 - decodes Latin1 string from the reader
// This method is useful for editing response bodies when you don't want
// to handle different encodings
func DecodeLatin1(reader io.Reader) (string, error) {
	r := transform.NewReader(reader, charmap.ISO8859_1.NewDecoder())
	b := mylog.Check2(io.ReadAll(r))
	return string(b), nil
}

// EncodeLatin1 - encodes the string as a byte array using Latin1
func EncodeLatin1(str string) ([]byte, error) {
	return charmap.ISO8859_1.NewEncoder().Bytes([]byte(str))
}

var (
	ErrShutdown = errors.New("proxy is shutting down")
	ErrClose    = errors.New("closing connection")
)

func isCloseable(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	switch {
	case err == io.EOF, errors.Is(err, io.ErrClosedPipe), errors.Is(err, ErrClose), errors.Is(err, ErrShutdown):
		return true
	}
	return false
}

func IsClosing(Request *http.Request, Response *http.Response) bool {
	if (Response.ContentLength == 0 || Response.ContentLength == -1) &&
		!Response.Close &&
		Response.ProtoAtLeast(1, 1) &&
		!Response.Uncompressed &&
		(len(Response.TransferEncoding) == 0 || Response.TransferEncoding[0] != "chunked") {
		return true
	}
	if Request.Close || Response.Close {
		return true
	}
	return false
}

func GetFlushInterval(res *http.Response) time.Duration {
	resCT := res.Header.Get("Content-Type")
	if resCT == "text/sessionEventCallBack-stream" {
		return -1
	}
	if res.ContentLength == -1 {
		return -1
	}
	return 10 * time.Second
}

func CopyResponse(dst io.Writer, src io.Reader, flushInterval time.Duration) error {
	if flushInterval != 0 {
		if wf, ok := dst.(WriteFlusher); ok {
			mlw := &MaxLatencyWriter{
				dst:     wf,
				latency: flushInterval,
			}
			defer mlw.Stop()
			mlw.flushPending = true
			mlw.t = time.AfterFunc(flushInterval, mlw.DelayedFlush)

			dst = mlw
		}
	}
	mylog.Check2(CopyBuffer(dst, src, nil))
	return nil
}

func CopyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	var written int64
	for {
		nr, err := src.Read(buf)
		if err != nil && err != io.EOF && !errors.Is(err, context.Canceled) {
			mylog.Warning("Proxy read error during body copy: %v", err)
		}
		if nr > 0 {
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

type WriteFlusher interface {
	io.Writer
	http.Flusher
}

type MaxLatencyWriter struct {
	dst          WriteFlusher
	latency      time.Duration
	mu           sync.Mutex
	t            *time.Timer
	flushPending bool
}

func (m *MaxLatencyWriter) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n = mylog.Check2(m.dst.Write(p))
	if m.latency < 0 {
		m.dst.Flush()
		return
	}
	if m.flushPending {
		return
	}
	if m.t == nil {
		m.t = time.AfterFunc(m.latency, m.DelayedFlush)
	} else {
		m.t.Reset(m.latency)
	}
	m.flushPending = true
	return
}

func (m *MaxLatencyWriter) DelayedFlush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.flushPending { // if stop was called but AfterFunc already started this goroutine
		return
	}
	m.dst.Flush()
	m.flushPending = false
}

func (m *MaxLatencyWriter) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushPending = false
	if m.t != nil {
		m.t.Stop()
	}
}
