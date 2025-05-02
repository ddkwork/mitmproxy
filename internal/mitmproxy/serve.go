package mitmproxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"time"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream/net/httpClient"
	"github.com/ddkwork/mitmproxy/internal/ca"
	"github.com/ddkwork/mitmproxy/packet"
)

type (
	Server interface {
		ListenAndServe()
		Handle
	}
	Proxy struct {
		dial                 func(string, string) (net.Conn, error)
		port                 string
		sessionEventCallBack packet.SessionEventCallBack
		keysTemp
		tcpListener *net.TCPListener
		err         error
	}
	keysTemp struct {
		SteamAesKey []byte
	}
)

func (p *Proxy) SessionEvent(_ *packet.Session) {
	mylog.Warning("SessionEvent", "未设置数据包的回调函数,将调用各层协议的默认事件输出")
}

func New(port string, sessionEventCallBack packet.SessionEventCallBack) Server {
	if port == "" {
		port = ca.ProxyPort
	}
	p := &Proxy{
		dial: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: dialTimeout,
		}).Dial,
		port:                 port,
		sessionEventCallBack: sessionEventCallBack,
		keysTemp:             keysTemp{},
		tcpListener:          nil,
		err:                  nil,
	}
	if sessionEventCallBack == nil {
		p.SessionEvent(nil)
	}
	return p
}

func (p *Proxy) ListenAndServe() {
	addr := mylog.Check2(net.ResolveTCPAddr("tcp", ca.ProxyServeAddress()))
	p.tcpListener = mylog.Check2(net.ListenTCP("tcp", addr))
	defer func() { mylog.Check(p.tcpListener.Close()) }()

	// go func() {
	//	return
	//	udpListenAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(httpClient.Localhost, p.port))
	//	if ! {
	//		return
	//	}
	//	udpListen, err := net.ListenUDP("udp", udpListenAddr)
	//	if ! {
	//		return
	//	}
	//	udpListen = udpListen
	// }()
	p.Serve()
}

func (p *Proxy) ServeTls() {
	// TODO implement me
	panic("implement me")
}

func (p *Proxy) Serve() {
	var delay time.Duration
	for {
		clientConn, e := p.tcpListener.Accept()
		mylog.CheckIgnore(e)
		if e != nil {
			var err net.Error
			if errors.As(err, &err) && err.Timeout() {
				mylog.CheckIgnore(err)
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if maxT := time.Second; delay > maxT {
					delay = maxT
				}
				time.Sleep(delay)
				continue
			}
			return
		}
		delay = 0
		TcpKeepAlive(clientConn)
		readWriter := bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn))
		mylog.Check(clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)))

		// gpt说maxPeekLayerBufSize超过三个字节卡顿的原因是没有加锁
		mylog.Todo("add lock for peek buf")
		layerBuf, e := readWriter.Reader.Peek(maxPeekLayerBufSize) // before ReadRequest call redder, but peek ways read conn?
		mylog.CheckIgnore(e)
		if e != nil {
			if errors.Is(e, io.EOF) {
				mylog.Trace("无法读取到协议buffer，建议直接走tcp隧道转发，但是tcp是无头head，首次连接body流可有可无，无法得到目标服务器ip，所以粗腰gui传进来")
			}
			continue
		}
		mylog.HexDump("layerBuf", layerBuf)

		mylog.Check(clientConn.SetReadDeadline(time.Time{}))
		isS5 := func(b []byte) bool { return bytes.Contains(b, []byte{5, 1}) }
		isS4 := func(b []byte) bool { return bytes.Contains(b, []byte{4, 1}) }
		switch {
		case isS5(layerBuf):
			go NewSocket5(packet.NewSessionWithReadWriter(clientConn, readWriter, httpClient.Socket5Type, p.sessionEventCallBack)).Serve()
		case isS4(layerBuf):
			go NewSocket4(packet.NewSessionWithReadWriter(clientConn, readWriter, httpClient.Socket4Type, p.sessionEventCallBack)).Serve()
		default:
			go NewHttp(packet.NewSessionWithReadWriter(clientConn, readWriter, httpClient.HttpType, p.sessionEventCallBack)).Serve()
		}
	}
}

const (
	maxPeekLayerBufSize = 3

	// tcp代理只支持http转tcp，或者可以用peek是eof支持？但是不知道远程服务器ip和端口，得构造req并从ui传进来？
	//	if packet.IsTcp(h.Request.URL.Hostname()) {
	//		mylog.Warning("IsTcp", h.Request.URL.Hostname())
	//		return NewTcp(h.Session).Serve()
	//	}

	// 4096 直接等待，不行，还有一种是io多读取器，但是只能http成功，s5的实现代码里面不不知道怎么支持多读
	// 3是Proxifier的s5包的最大值，s4直接不发，s4代理失败
	// sock包是发了  04 01 1f，s4代理成功
	// edge 浏览器发的是 04 01 01 ，s4代理失败

	// 正确设置
	//	Transport: &http.Transport{
	//			Proxy: func(request *http.Request) (*url.URL, error) {
	//				return url.Parse("socks5://" + ca.ProxyServeAddress())
	//				return url.Parse("socks5://localhost:1080")
	//			},
	//		},

	//		Transport: &http.Transport{
	//			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
	//				//d := socks.NewSocks4Dialer("tcp", "localhost:1080")
	//				d := socks.NewSocks4Dialer("tcp", ca.ProxyServeAddress())
	//				return d.DialContext(ctx, network, addr)
	//			},
	//		},
)
