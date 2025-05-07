package mitmproxy

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ddkwork/websocket"

	"golang.org/x/net/http/httpguts"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
	"github.com/ddkwork/golibrary/stream/net/httpClient"
	"github.com/ddkwork/mitmproxy/packet"
)

func (w *WebSocket) SessionEvent(session *packet.Session) {
	ss := stream.NewBuffer(session.StreamDirection.String() + " " + session.Request.URL.String())
	ss.Indent(1)
	ss.WriteString(session.WebsocketStatus)
	ss.Indent(1)
	switch session.StreamDirection {
	case packet.Inbound:
		mylog.HexDump(ss.String(), session.ReqBodyDecoder.Payload)
	case packet.Outbound:
		mylog.HexDump(ss.String(), session.RespBodyDecoder.Payload)
	}
}

func (w *WebSocket) ServeTls() {
	// TODO implement me
	panic("implement me")
}

func (w *WebSocket) Serve() {
	w.SchemerType = httpClient.WebSocketType
	w.Request.URL.Scheme = "ws"
	if w.IsTls() {
		w.Request.URL.Scheme = "wss"
		w.SchemerType = httpClient.WebsocketTlsType
	}
	ctx := w.Request.Context()
	outReq := w.Request.Clone(ctx)
	if w.Request.ContentLength == 0 {
		outReq.Body = nil
	}
	defer func() {
		mylog.Check(outReq.Body)
		mylog.Check(outReq.Body.Close())
	}()

	if outReq.Header == nil {
		outReq.Header = make(http.Header)
	}
	outReq.Close = false
	RemoveHopByHopHeaders(outReq.Header)
	outReq.Header.Del("Sec-Websocket-Version")
	outReq.Header.Del("Sec-Websocket-Key")
	outReq.Header.Del("Sec-Websocket-Extensions")
	var wssConn *websocket.Conn

	wssConn, w.Response, w.err = DefaultWSDialer.DialContext(ctx, outReq.URL.String(), outReq.Header)
	mylog.Check(w.err)

	backConnCloseCh := make(chan bool)
	go func() {
		select {
		case <-w.Request.Context().Done():
		case <-backConnCloseCh:
		}
		mylog.Check(wssConn.Close())
	}()
	defer close(backConnCloseCh)
	upgradeHeader := http.Header{}
	if hdr := w.Response.Header.Get("Sec-Websocket-Protocol"); hdr != "" {
		upgradeHeader.Set("Sec-Websocket-Protocol", hdr)
	}
	if hdr := w.Response.Header.Get("Set-Cookie"); hdr != "" {
		upgradeHeader.Set("Set-Cookie", hdr)
	}
	conn := mylog.Check2(DefaultWebsocketUpGrader.UpgradeEx(w.ClientConn, w.ReadWriter, w.Request, upgradeHeader))
	defer func() { mylog.Check(conn.Close()) }()
	RemoveExtraHTTPHostPort(w.Request)
	// w.RequestPacket = MakeHttpRequestPacket(w.Request, w.ProcessName)
	// w.ResponsePacket = MakeHttpResponsePacket(w.Response)
	// w.RequestEvent(w)
	// w.ResponseEvent(w)
	// src was closed
	if wssConn == nil || conn == nil {
		return
	}
	errClient := make(chan error, 1)
	errBackend := make(chan error, 1)
	go w.copy(wssConn, conn, packet.Outbound, errBackend)
	go w.copy(conn, wssConn, packet.Inbound, errClient)
	var er error
	select {
	case er = <-errClient:
	case er = <-errBackend:
	}
	var e *websocket.CloseError
	if !errors.As(e, &e) || e.Code == websocket.CloseAbnormalClosure {
		mylog.Check(er)
	}
}

func (w *WebSocket) copy(dst, src *websocket.Conn, direction packet.StreamDirection, errChan chan error) {
	src.SetPingHandler(func(data string) error {
		return dst.WriteControl(websocket.PingMessage, []byte(data), time.Time{})
	})
	src.SetPongHandler(func(data string) error {
		return dst.WriteControl(websocket.PongMessage, []byte(data), time.Time{})
	})
	for {
		// src was closed
		if src == nil || dst == nil || w == nil {
			return
		}

		msgType, msg, err2 := src.ReadMessage()
		if err2 != nil {
			m := websocket.FormatCloseMessage(websocket.CloseNormalClosure, fmt.Sprintf("%v", err2))
			var e *websocket.CloseError
			if errors.As(e, &err2) {
				if e != nil {
					if e.Code == websocket.CloseAbnormalClosure || e.Code == websocket.CloseTLSHandshake {
						errChan <- e
						return
					}
					if e.Code != websocket.CloseNoStatusReceived {
						m = websocket.FormatCloseMessage(e.Code, e.Text)
					}
				}
			}
			errChan <- e
			errChan <- dst.WriteMessage(websocket.CloseMessage, m)
			return
		}
		w.StreamDirection = direction
		w.WebsocketMessageType = packet.WebsocketMessageType(msgType)
		switch direction {
		case packet.Inbound:
			w.ReqBodyDecoder.Payload = msg
			switch w.WebsocketMessageType {
			case packet.TextMessage:
				w.ReqBodyDecoder.Websocket = string(msg)
			case packet.BinaryMessage:
				w.ReqBodyDecoder.Websocket = hex.Dump(msg)
			case packet.CloseMessage:
			case packet.PingMessage:
			case packet.PongMessage:

			}
		case packet.Outbound:
			w.RespBodyDecoder.Payload = msg
			switch w.WebsocketMessageType {
			case packet.TextMessage:
				w.RespBodyDecoder.Websocket = string(msg)
			case packet.BinaryMessage:
				w.RespBodyDecoder.Websocket = hex.Dump(msg)
			case packet.CloseMessage:
			case packet.PingMessage:
			case packet.PongMessage:

			}
		}

		w.EditData = packet.EditData{
			SchemerType:   w.SchemerType,
			Method:        w.StreamDirection.String(),
			Host:          w.Host,
			Path:          w.Path,
			ContentType:   w.WebsocketMessageType.String(),
			ContentLength: len(w.ReqBodyDecoder.Payload),
			Status:        w.WebsocketStatus, // todo test
			Note:          w.Note,
			Process:       w.Process,
			PadTime:       w.PadTime, // todo
		}
		if direction == packet.Outbound {
			w.PadTime = time.Since(w.StartTime)
		}
		var er *websocket.CloseError
		if er != nil {
			if errors.As(er, &er) {
				w.Session.WebsocketStatus = er.Error()
			}
		}

		if w.EventCallBack == nil {
			w.SessionEvent(w.Session)
		} else {
			w.EventCallBack(w.Session)
		}
		if mylog.Check(dst.WriteMessage(msgType, w.Session.ReqBodyDecoder.Payload)); er != nil {
			errChan <- er
			return
		}
	}
}

var (
	DefaultWebsocketUpGrader = &websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}
	DefaultWSDialer = &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}},
	}
)

func UpgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

func CopyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

var HopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func RemoveHopByHopHeaders(header http.Header) {
	for _, vs := range header["Connection"] {
		for v := range strings.SplitSeq(vs, ",") {
			k := http.CanonicalHeaderKey(strings.TrimSpace(v))
			header.Del(k)
		}
	}
	for _, k := range HopByHopHeaders {
		header.Del(k)
	}
}
