package main

import (
	"github.com/ddkwork/golibrary/std/mylog"
	"github.com/ddkwork/golibrary/std/stream"
	"github.com/ddkwork/golibrary/std/stream/net/httpClient"
	"github.com/ddkwork/mitmproxy/internal/mitmproxy"

	"github.com/ddkwork/mitmproxy/packet"
)

//go:generate  go run -x .

func main() {
	mitmproxy.New("7890", func(session *packet.Session) {
		switch session.SchemerType {
		case httpClient.HttpType:
			if session.StreamDirection == packet.Outbound {
				mylog.Response(session.Response, false)
				return
			}
			mylog.Request(session.Request, false)
		case httpClient.HttpsType:
			if session.StreamDirection == packet.Outbound {
				mylog.Response(session.Response, false)
				return
			}
			mylog.Request(session.Request, false)
		case httpClient.Socket4Type:
			mylog.HexDump(session.SchemerType.String()+" "+session.StreamDirection.String(), session.ReqBodyDecoder.Payload) // todo switch direction
		case httpClient.Socket5Type:
			mylog.HexDump(session.SchemerType.String()+" "+session.StreamDirection.String(), session.ReqBodyDecoder.Payload)
		case httpClient.WebSocketType:
			ss := stream.NewBuffer(session.StreamDirection.String() + " " + session.Request.URL.String())
			ss.Indent(1)
			ss.WriteString(session.WebsocketStatus)
			ss.Indent(1)
			mylog.HexDump(ss.String(), session.ReqBodyDecoder.Payload)
		case httpClient.WebsocketTlsType:
			ss := stream.NewBuffer(session.StreamDirection.String() + " " + session.Request.URL.String())
			ss.Indent(1)
			ss.WriteString(session.WebsocketStatus)
			ss.Indent(1)
			mylog.HexDump(ss.String(), session.ReqBodyDecoder.Payload)
		case httpClient.TcpType:
			mylog.HexDump(session.StreamDirection.String()+" "+session.Request.URL.String(), session.ReqBodyDecoder.Payload)
		case httpClient.TcpTlsType:
			mylog.HexDump(session.StreamDirection.String()+" "+session.Request.URL.String(), session.ReqBodyDecoder.Payload)
		case httpClient.UdpType:
		case httpClient.KcpType:
		case httpClient.PipeType:
		case httpClient.QuicType:
		case httpClient.RpcType:
		case httpClient.SshType:
		}
	}).ListenAndServe()
}
