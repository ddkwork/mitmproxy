package packet

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"time"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream/net/httpClient"
)

type (
	SessionEventCallBacker interface {
		SessionEvent(session *Session)
	}
	SessionEventCallBack func(session *Session)
	Session              struct {
		Packet
		EventCallBack SessionEventCallBack
		ClientConn    net.Conn
		ReadWriter    *bufio.ReadWriter
		Request       *http.Request
		Response      *http.Response
		StartTime     time.Time
	}
)

func NewSessionWithReadWriter(clientConn net.Conn, readWriter *bufio.ReadWriter, layer httpClient.SchemerType, event SessionEventCallBack) *Session {
	s := &Session{
		Packet: Packet{
			StreamDirection: 0,
			EditData: EditData{
				SchemerType:   layer,
				Method:        "",
				Host:          "",
				Path:          "",
				ContentType:   "",
				ContentLength: 0,
				Status:        "",
				Note:          "",
				PadTime:       0,
			},
			ReqBodyDecoder:       BodyDecoder{},
			RespBodyDecoder:      BodyDecoder{},
			WebsocketMessageType: 0,
			WebsocketStatus:      "",
		},
		EventCallBack: event,
		ClientConn:    clientConn,
		ReadWriter:    readWriter,
		Request:       nil,
		Response:      nil,
		StartTime:     time.Now(),
	}
	if clientConn.LocalAddr() != nil && clientConn.RemoteAddr() != nil {
		s.Process = FindProcessPath(clientConn.RemoteAddr().Network(), clientConn.LocalAddr().String(), clientConn.RemoteAddr().String())
	}
	return s
}

func NewSession(clientConn net.Conn, layer httpClient.SchemerType, event SessionEventCallBack) *Session {
	s := &Session{
		Packet: Packet{
			StreamDirection: 0,
			EditData: EditData{
				SchemerType:   layer,
				Method:        "",
				Host:          "",
				Path:          "",
				ContentType:   "",
				ContentLength: 0,
				Status:        "",
				Note:          "",
				PadTime:       0,
			},
			ReqBodyDecoder:       BodyDecoder{},
			RespBodyDecoder:      BodyDecoder{},
			WebsocketMessageType: 0,
			WebsocketStatus:      "",
		},
		EventCallBack: event,
		ClientConn:    clientConn,
		ReadWriter:    bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn)),
		Request:       nil,
		Response:      nil,
		StartTime:     time.Now(),
	}
	if clientConn.LocalAddr() != nil && clientConn.RemoteAddr() != nil {
		s.Process = FindProcessPath(clientConn.RemoteAddr().Network(), clientConn.LocalAddr().String(), clientConn.RemoteAddr().String())
	}
	return s
}

func (s *Session) RemoteAddr() string { return s.Request.URL.Host }
func (s *Session) IsTls() bool {
	_, ok := s.ClientConn.(*tls.Conn)
	return ok
}

func MakeHttpRequestPacket(request *http.Request, Process string, layer httpClient.SchemerType) (P Packet) {
	bodyBuffer := new(bytes.Buffer)
	defer func() {
		// mylog.hexDump("RequestBuffer", bodyBuffer.Payload())
		P = Packet{
			StreamDirection: Inbound,
			EditData: EditData{
				SchemerType:   httpClient.HttpType.AssertBy(request.URL.Scheme),
				Method:        request.Method,
				Host:          request.URL.Host,
				Path:          request.URL.Path,
				ContentType:   request.Header.Get("Content-Type"),
				ContentLength: int(request.ContentLength), // fmt.sprint(request.ContentLength),//todo fmt to kb byte mb
				Status:        "",                         // fill when resp
				Note:          decodeSteamAeskeyIntoNotes(request),
				Process:       Process,
				PadTime:       0,
			},
			ReqBodyDecoder: BodyDecoder{
				Payload:        bodyBuffer.Bytes(),
				PayloadHexDump: hex.Dump(bodyBuffer.Bytes()),
				HttpDump:       mylog.DumpRequest(request, false),
				UnitTest:       makeUnitTest(request, bodyBuffer.Bytes()),
				SteamAesKey:    nil,
				Steam:          "", // use plugin
				ProtoBuf:       "", // use plugin
				Tdf:            "", // use plugin
				Taf:            "", // use plugin
				Acc:            "", // use plugin
				Websocket:      "", // use default payload,but this should in wss event set it not in req resp event
				Msgpack:        "", // todo test
			},
			WebsocketMessageType: 0,
			WebsocketStatus:      "",
		}
		Text := decodeText(request, bodyBuffer.Bytes())
		Json := decodeJson(request, bodyBuffer.Bytes())
		Html := decodeHtml(request, bodyBuffer.Bytes())
		Javascript := decodeJavaScript(request, bodyBuffer.Bytes())
		P.ReqBodyDecoder.HttpDump += "\n"
		switch {
		case Text != "":
			P.ReqBodyDecoder.HttpDump += Text
		case Json != "":
			P.ReqBodyDecoder.HttpDump += Json
		case Html != "":
			P.ReqBodyDecoder.HttpDump += Html
		case Javascript != "":
			P.ReqBodyDecoder.HttpDump += Javascript
		}
	}()
	body, backBody := DrainBody(request.Body)
	request.Body = backBody
	mylog.Check2(bodyBuffer.ReadFrom(body))
	mylog.Call(func() {
		body := ReadDecompressedBody(request.Header, bodyBuffer) // gzip
		bodyBuffer.Reset()
		bodyBuffer.Write(body)
	})
	return
}

func MakeHttpResponsePacket(response *http.Response, layer httpClient.SchemerType) (P Packet) {
	bodyBuffer := new(bytes.Buffer)
	defer func() {
		// mylog.hexDump("ResponseBuffer", bodyBuffer.Payload())
		request := response.Request
		P = Packet{
			StreamDirection: Outbound,
			EditData: EditData{
				SchemerType:   layer, // todo fill it request.URL.Layer,
				Method:        request.Method,
				Host:          request.URL.Host,
				Path:          request.URL.Path,
				ContentType:   response.Header.Get("Content-Type"),
				ContentLength: int(response.ContentLength),
				Status:        response.Status,
				Note:          "",
				Process:       "",
				PadTime:       0,
			},
			RespBodyDecoder: BodyDecoder{
				Payload:        bodyBuffer.Bytes(),
				PayloadHexDump: hex.Dump(bodyBuffer.Bytes()),
				HttpDump:       mylog.DumpResponse(response, false),
				UnitTest:       "",
				SteamAesKey:    nil,
				Steam:          "",
				ProtoBuf:       "",
				Tdf:            "",
				Taf:            "",
				Acc:            "",
				Websocket:      "",
				Msgpack:        "",
			},
			WebsocketMessageType: 0,
			WebsocketStatus:      "",
		}
		Text := decodeText(request, bodyBuffer.Bytes())             // todo 解码返回body
		Json := decodeJson(request, bodyBuffer.Bytes())             // todo 解码返回body
		Html := decodeHtml(request, bodyBuffer.Bytes())             // todo 解码返回body
		Javascript := decodeJavaScript(request, bodyBuffer.Bytes()) // todo 解码返回body
		P.RespBodyDecoder.HttpDump += "\n"
		switch {
		case Text != "":
			P.RespBodyDecoder.HttpDump += Text
		case Json != "":
			P.RespBodyDecoder.HttpDump += Json
		case Html != "":
			P.RespBodyDecoder.HttpDump += Html
		case Javascript != "":
			P.RespBodyDecoder.HttpDump += Javascript
		}
	}()
	body, backBody := DrainBody(response.Body)
	response.Body = backBody
	mylog.Check2(bodyBuffer.ReadFrom(body))
	decompressedBody := ReadDecompressedBody(response.Header, bodyBuffer) // gzip
	bodyBuffer.Reset()
	bodyBuffer.Write(decompressedBody)
	return
}

func decodeSteamAeskeyIntoNotes(Request *http.Request) string {
	aesKey := Request.Header.Get("aeskey")
	if aesKey != "" {
		return "SteamAesKey hooked"
	}
	return ""
}
