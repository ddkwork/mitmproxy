package mitmproxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ddkwork/mitmproxy/internal/ca"
	"github.com/ddkwork/mitmproxy/packet"

	"github.com/ddkwork/golibrary/std/mylog"
	"github.com/ddkwork/golibrary/std/stream"
	"github.com/ddkwork/golibrary/std/stream/net/httpClient"
	"github.com/ddkwork/websocket"
	"github.com/google/gopacket/layers"
)

var portMap = map[string]string{
	"http":   "80",
	"https":  "443",
	"socks5": "1080",
}

var errClientCertRequested = errors.New("tls: client cert authentication unsupported")

const (
	defaultTimeout      = 30 * time.Second
	dialTimeout         = defaultTimeout
	tlsHandshakeTimeout = defaultTimeout
)

func (h *Http) SessionEvent(session *packet.Session) {
	if session.StreamDirection == packet.Outbound {
		mylog.Response(session.Response, false)
		return
	}
	mylog.Request(session.Request, false)
}

func (h *Http) Serve() {
	// defer func() { mylog.Check(h.ClientConn.Close()) }() //todo  use of closed network connection ,连接是在监听结束一次后才关闭的，这里的上一层才有关闭操作啊，why？
	// 以下的情况可能走
	// tcp 自己关闭请求连接
	// wss 自己关闭请求连接
	// https 只有这个才需要关闭，逻辑上是

	mylog.Call(func() {
		// 	for {
		var err1 error
		h.Request, err1 = http.ReadRequest(h.ReadWriter.Reader)
		// if mylog.Check(err1) {
		// 	return
		// }
		// if !mylog.Check(err1) {
		// 	continue
		// }
		if err1 != nil {
			return
		}

		h.Packet.EditData = packet.EditData{ // todo
			SchemerType:   h.Session.SchemerType,
			Method:        h.Request.Method,
			Host:          h.Request.URL.Host,
			Path:          h.Request.URL.Path,
			ContentType:   "",
			ContentLength: 0,
			Status:        "",
			Note:          "",
			Process:       "",
			PadTime:       0,
		}

		if packet.IsTcp(h.Request.URL.Hostname()) { // todo test steam
			mylog.Warning("IsTcp", h.Request.URL.Hostname())
			NewTcp(h.Session).Serve()
		}

		aesKey := h.Request.Header.Get("aeskey")
		if aesKey != "" {
			h.ReqBodyDecoder.SteamAesKey = stream.NewHexDump(stream.HexDumpString(aesKey)).Bytes()
		}
		if websocket.IsWebSocketUpgrade(h.Request) {
			if h.Request.URL.Host == "" {
				h.Request.URL.Host = h.Request.Host
			}
			mylog.Warning("IsWebSocketUpgrade", h.Request.URL.Hostname())
			NewWebSocket(h.Session).Serve()
		}
		PrepareRequest(h.IsTls(), h.Request, h.ClientConn)
		RemoveHopByHopHeaders(h.Request.Header)

		if h.Request.Method == http.MethodConnect { // 默认丢弃MethodConnect包不显示
			h.ServeTls()
		}

		h.StreamDirection = packet.Inbound
		if h.SchemerType != httpClient.HttpsType {
			h.SchemerType = httpClient.HttpType
		}
		h.Packet = packet.MakeHttpRequestPacket(h.Request, h.Process, h.SchemerType) // invalid Read on closed Row
		if h.Request.Body != nil {
			mylog.Check(h.Request.Body.Close())
		}

		h.Response = mylog.Check2(h.transport.RoundTrip(h.Request))

		h.Status = h.Response.Status
		// if h.EventCallBack == nil {
		// 	h.SessionEvent(h.Session)
		// } else {
		// 	h.EventCallBack(h.Session)
		// }

		h.StreamDirection = packet.Outbound
		h.Packet = packet.MakeHttpResponsePacket(h.Response, h.SchemerType)
		if h.EventCallBack == nil {
			h.SessionEvent(h.Session)
		} else {
			// 这里gui不应该创建节点显示，应该保存返回的body和头部供给选中行事件显示，
			// 同样上面的请求也是一样的，应该保存请的body和头部给选中行事件调用显示请求信息
			h.EventCallBack(h.Session)
		}
		packet.WriteResponse(h.Response, h.ReadWriter)
		mylog.Check(h.Response.Body.Close())
		// 	}
	})
}

func (h *Http) ServeTls() {
	if h.Request == nil {
		h.Request = mylog.Check2(http.NewRequest(http.MethodConnect, "http://"+ca.ProxyServeAddress(), nil))
	}

	// defer func() { mylog.CheckIgnore(h.ClientConn.Close()) }() // todo  use of closed network connection ,连接是在监听结束一次后才关闭的，这里的上一层才有关闭操作啊，why？
	h.Response = packet.NewResponse(http.StatusOK, nil, h.Request)
	packet.WriteResponse(h.Response, h.ReadWriter)
	mylog.Check(h.Response.Body.Close())
	h.Packet = packet.MakeHttpResponsePacket(h.Response, h.SchemerType)
	h.StreamDirection = packet.Outbound
	if packet.IsTcp(h.Request.URL.Hostname()) {
		// mylog.Warning("IsTcp", h.Request.URL.Hostname())
		// h.SchemerType = httpClient.TcpType
		// NewTcp(h.Session).Serve()
	}

	b := make([]byte, 1)
	mylog.Check2(h.ReadWriter.Read(b))
	buf := make([]byte, h.ReadWriter.Reader.Buffered())
	mylog.Check2(h.ReadWriter.Read(buf))
	// s := stream.NewBuffer(b)
	// s.Write(buf)
	// mylog.HexDump("", s.Bytes())

	peekConn := &PeekedConn{
		Conn:   h.ClientConn,
		Reader: io.MultiReader(bytes.NewReader(b), bytes.NewReader(buf), h.ClientConn),
	}

	// tls 套件解析  todo

	// conn := tls.Client(peekConn, ca.Cfg.NewTlsConfigForHost(h.Request.URL.Host))
	// clientHello, context := mylog.Check3(conn.readClientHello())
	// mylog.Check(conn.serverHandshake(context.Background())) // http不设置证书代理https流量，所有协议只需一个监听端口

	layer := layers.TLSType(b[0])
	if layer == layers.TLSHandshake {
		mylog.Hex(h.Request.URL.String(), layer)
		var tlsClientConn *tls.Conn

		tlsClientConn = tls.Server(peekConn, ca.Cfg.NewTlsConfigForHost(h.Request.URL.Host))
		// hello, _ := mylog.Check3(tlsClientConn.ClientHello())
		// mylog.Check(tlsClientConn.ServerHandshake(hello))
		mylog.Check(tlsClientConn.Handshake())

		// ServerHandshake use top todo
		// mylog.Success("https Handshake Success", h.Request.Method, " ", h.Request.URL.String())
		h.Session = packet.NewSession(tlsClientConn, httpClient.HttpsType, h.EventCallBack)
		h.Serve()
		return
	}
	h.Session = packet.NewSession(peekConn, httpClient.HttpType, h.EventCallBack)
	h.Serve()
}

func PrepareRequest(IsTls bool, request *http.Request, ClientConn net.Conn) {
	request.Header.Del("Connection")
	if request.URL.Host == "" {
		request.URL.Host = request.Host
	}
	request.URL.Scheme = "http"
	if IsTls {
		tlsConn := ClientConn.(*tls.Conn)
		cs := tlsConn.ConnectionState()
		request.TLS = &cs
		request.URL.Scheme = "https"
	}
	request.RemoteAddr = ClientConn.RemoteAddr().String()
	if request.Header.Get("Accept-Encoding") != "" {
		request.Header.Set("Accept-Encoding", "gzip")
	}
}
