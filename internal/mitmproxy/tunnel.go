package mitmproxy

import (
	"context"
	"errors"
	"io"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
	"github.com/ddkwork/mitmproxy/packet"
)

func (t *Tcp) transfer(session *packet.Session, destination io.WriteCloser, source io.ReadCloser, direction packet.StreamDirection) {
	defer func() {
		mylog.Check(destination.Close())
		mylog.Check(source.Close())
	}()
	buf := make([]byte, 32*1024)
	mylog.Check2(t.copyBuffer(session, destination, source, buf, direction))
}

func (t *Tcp) copyBuffer(s *packet.Session, dst io.Writer, src io.Reader, buf []byte, direction packet.StreamDirection) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	messages := make([]*TunnelStream, 0)
	var written int64
	for {
		nr, err := src.Read(buf)
		if err != nil && err != io.EOF && !errors.Is(err, context.Canceled) {
			mylog.Info("Proxy read error during body copy", err)
		}
		if nr > 0 {
			if t.ReqBodyDecoder.SteamAesKey != nil {
				s.ReqBodyDecoder.SteamAesKey = t.ReqBodyDecoder.SteamAesKey
			}
			if nr > 8 && len(messages) == 0 {
				t.StreamDirection = direction
				switch direction {
				case packet.Inbound:
					t.ReqBodyDecoder.Payload = buf[:nr]
				case packet.Outbound:
					t.RespBodyDecoder.Payload = buf[:nr]
				}
				if t.EventCallBack == nil {
					t.SessionEvent(t.Session)
				} else {
					t.EventCallBack(t.Session)
				}
			} else {
				messages = append(messages, MakeTcpMessage(buf[:nr], direction))
				if len(messages) == 2 {
					t.StreamDirection = direction
					switch direction {
					case packet.Inbound:
						t.ReqBodyDecoder.Payload = stream.NewBuffer(messages[0].Payload).AppendByteSlice(messages[1].Payload)
					case packet.Outbound:
						t.RespBodyDecoder.Payload = stream.NewBuffer(messages[0].Payload).AppendByteSlice(messages[1].Payload)
					}
					if t.EventCallBack == nil {
						t.SessionEvent(t.Session)
					} else {
						t.EventCallBack(t.Session)
					}
					messages = messages[:0]
				}
			}
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
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

type TunnelStream struct {
	packet.StreamDirection
	Payload []byte
}

func MakeTcpMessage(buf []byte, direction packet.StreamDirection) *TunnelStream {
	message := &TunnelStream{
		StreamDirection: direction,
		Payload:         make([]byte, len(buf)),
	}
	copy(message.Payload, buf)
	return message
}
