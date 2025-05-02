package mitmproxy

import (
	"io"
	"net"
	"time"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream/net/httpClient"
	"github.com/ddkwork/mitmproxy/packet"
)

func (t *Tcp) SessionEvent(session *packet.Session) {
	switch session.StreamDirection {
	case packet.Inbound:
		mylog.HexDump(session.StreamDirection.String()+" "+session.Request.URL.String(), session.ReqBodyDecoder.Payload)
	case packet.Outbound:
		mylog.HexDump(session.StreamDirection.String()+" "+session.Request.URL.String(), session.RespBodyDecoder.Payload)
	}
}

func (t *Tcp) ServeTls() {
	// TODO implement me
	panic("implement me")
}

func (t *Tcp) Serve() {
	server := mylog.Check2(net.DialTimeout("tcp", t.Request.Host, 10*time.Second))
	t.Request.Close = false
	t.Request.URL.Scheme = "tcp"
	t.SchemerType = httpClient.TcpType
	RemoveExtraHTTPHostPort(t.Request)
	t.Packet = packet.MakeHttpRequestPacket(t.Request, t.Process, t.SchemerType)

	// p.RequestEvent(t)
	if t.Response.ContentLength > 0 {
		panic(t.Response.ContentLength)
		// return p.ServeHttp(t)
	}
	go t.transfer(t.Session, t.ClientConn, server, packet.Inbound)
	t.transfer(t.Session, server, t.ClientConn, packet.Outbound)
}

func tcpTuner() { // tcp代理是点对点的p2p全双工通信，无头协议，必须知道双方的ip和端口才能代理，俗称隧道
	// 监听本地端口
	localAddr := mylog.Check2(net.ResolveTCPAddr("tcp", ":8080"))
	localListener := mylog.Check2(net.ListenTCP("tcp", localAddr))

	// 监听代理服务器端口
	proxyAddr := mylog.Check2(net.ResolveTCPAddr("tcp", "proxyAddr:8080"))

	// 循环等待本地客户端连接
	for {
		localConn, e := localListener.Accept()
		if e != nil {
			continue
		}
		remoteConn := mylog.Check2(net.DialTCP("tcp", nil, proxyAddr))
		// defer remoteConn.Close()
		// defer localConn.Close()
		go func() { mylog.Check2(io.Copy(localConn, remoteConn)) }()
		mylog.Check2(io.Copy(remoteConn, localConn))
	}
}
