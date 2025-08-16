package packet

import (
	"net"
	"time"

	"github.com/ddkwork/websocket"

	"github.com/ddkwork/golibrary/std/stream/net/httpClient"
)

type (
	Packet struct { //gti:add
		StreamDirection `table:"_"`
		EditData
		ReqBodyDecoder       BodyDecoder `table:"_"`
		RespBodyDecoder      BodyDecoder `table:"_"`
		WebsocketMessageType `table:"_"`
		WebsocketStatus      string `table:"_"` // todo 增加类型别名和实现fmt的字符串方法
	}
	EditData struct {
		httpClient.SchemerType `table:"Scheme"` // 请求协议
		Method                 string           // 请求方式
		Host                   string           // 请求主机
		Path                   string           // 请求路径
		ContentType            string           // 收发都有
		ContentLength          int              // 收发都有
		Status                 string           // 返回的状态码文本
		Note                   string           // 注释
		Process                string           // 进程
		PadTime                time.Duration    // 请求到返回耗时
	}
	BodyDecoder struct {
		HttpDump       string // 收发都有
		Payload        []byte // 收发都有
		PayloadHexDump string // 收发都有
		UnitTest       string // 模拟请求
		SteamAesKey    []byte // 请求
		Steam          string // 收发都有
		ProtoBuf       string // 收发都有
		Tdf            string // 收发都有
		Taf            string // 收发都有
		Acc            string // 收发都有
		Websocket      string // 收发都有
		Msgpack        string // 收发都有
	}
)

func IsTcp(hostname string) bool { return net.ParseIP(hostname) != nil }

// func Clone(packet Packet) *Packet {
//	return &Packet{
//		Layer:           packet.Layer,
//		StreamDirection: packet.StreamDirection,
//		EditData: EditData{
//			Layer:        packet.Layer,
//			Method:        packet.Method,
//			Host:          packet.Host,
//			Path:          packet.Path,
//			ContentType:   packet.ContentType,
//			ContentLength: packet.ContentLength,
//			Status:        packet.Status,
//			Note:          packet.Note,
//			Process:       packet.Process,
//			PadTime:       packet.PadTime,
//		},
//		BodyDecoder: BodyDecoder{
//			Payload:        stream.NewBuffer(packet.Payload).Bytes(),
//			PayloadHexDump: packet.PayloadHexDump,
//			HttpDump:       packet.HttpDump,
//			UnitTest:       packet.UnitTest,
//			SteamAesKey:    stream.NewBuffer(packet.SteamAesKey).Bytes(),
//			Steam:          packet.Steam,
//			ProtoBuf:       packet.ProtoBuf,
//			Tdf:            packet.Tdf,
//			Taf:            packet.Taf,
//			Acc:            packet.Acc,
//			Websocket:      packet.Websocket,
//			Msgpack:        packet.Msgpack,
//		},
//		WebsocketMessageType: packet.WebsocketMessageType,
//		WebsocketStatus:      packet.WebsocketStatus,
//	}
// }

type StreamDirection int32 // 流向

const (
	Inbound  StreamDirection = iota // 入站
	Outbound                        // 出站
)

func (s StreamDirection) String() string {
	if s == Inbound {
		return "Inbound"
	}
	return "Outbound"
}

type WebsocketMessageType int

const (
	TextMessage   WebsocketMessageType = websocket.TextMessage
	BinaryMessage WebsocketMessageType = websocket.BinaryMessage
	CloseMessage  WebsocketMessageType = websocket.CloseMessage
	PingMessage   WebsocketMessageType = websocket.PingMessage
	PongMessage   WebsocketMessageType = websocket.PongMessage
)

func (t WebsocketMessageType) String() string {
	switch t {
	case TextMessage:
		return "TextMessage"
	case BinaryMessage:
		return "BinaryMessage"
	case CloseMessage:
		return "CloseMessage"
	case PingMessage:
		return "PingMessage"
	case PongMessage:
		return "PongMessage"
	}
	return "unknown WebsocketMessageType"
}
