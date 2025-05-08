package main

import (
	"crypto/tls"
	"embed"
	"iter"
	"net/http"
	"strings"
	"time"

	"gioui.org/layout"
	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
	"github.com/ddkwork/golibrary/stream/net/httpClient"
	"github.com/ddkwork/mitmproxy/internal/mitmproxy"
	"github.com/ddkwork/mitmproxy/packet"
	"github.com/ddkwork/ux"
)

func main() {
	w := ux.NewWindow("mitmproxy")
	panel := ux.NewPanel(w)

	hPanel := ux.NewHPanel(w)
	panel.AddChild(hPanel)

	m := stream.ReadEmbedFileMap(myIcons, "asserts/bar")
	appBar = ux.InitAppBar(hPanel, func(yield func(*ux.TipIconButton) bool) {
		yield(ux.NewTooltipButton(m.GetMust("search.png"), "search", nil))
		yield(ux.NewTooltipButton(m.GetMust("cleaner.png"), "cleaner", nil))
		yield(ux.NewTooltipButton(m.GetMust("replay.png"), "replay", nil))
		yield(ux.NewTooltipButton(m.GetMust("edit.png"), "edit", nil))
		yield(ux.NewTooltipButton(m.GetMust("submit.png"), "submit", nil))
		yield(ux.NewTooltipButton(m.GetMust("rec.png"), "rec", nil))
		yield(ux.NewTooltipButton(m.GetMust("rootca.png"), "rootca", nil))
		yield(ux.NewTooltipButton(m.GetMust("ssl2.png"), "ssl2", nil))
		yield(ux.NewTooltipButton(m.GetMust("setting.png"), "setting", nil))
		yield(ux.NewTooltipButton(m.GetMust("Charles.png"), "Charles", nil))
		yield(ux.NewTooltipButton(m.GetMust("logView.png"), "logView", nil))
		yield(ux.NewTooltipButton(m.GetMust("script.png"), "script", nil))
		yield(ux.NewTooltipButton(m.GetMust("about.png"), "about", nil))
	}, "mitmproxy is a free and open source tool for debugging, testing, and analyzing HTTP/HTTPS traffic.")

	c := NewCodec()

	requestBodyDecoderTab := ux.NewTabView(layout.Horizontal)
	for _, bodyType := range HttpDumpType.EnumTypes() {
		switch bodyType {
		case HttpDumpType:
			requestBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Request.HttpDump))
		case HexDumpType:
			requestBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Request.PayloadHexDump))
		case SteamType:
			requestBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Request.Steam))
		case WebsocketType:
			requestBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Request.Websocket))
		case ProtoBufType:
			requestBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Request.ProtoBuf))
		case TdfType:
			requestBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Request.Tdf))
		case TafType:
			requestBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Request.Taf))
		case AccType:
			requestBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Request.Acc))
		case NotesType:
			requestBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Request.Notes))
		case MsgpackType:
			requestBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Request.Msgpack))
		case UnitTestType:
			requestBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Request.UnitTest))
		case GitProxyType:
			requestBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Request.GitProxy))
		}
	}

	responseBodyDecoderTab := ux.NewTabView(layout.Horizontal)
	for _, bodyType := range HttpDumpType.EnumTypes() {
		switch bodyType {
		case HttpDumpType:
			responseBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Response.HttpDump))
		case HexDumpType:
			responseBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Response.PayloadHexDump))
		case SteamType:
			responseBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Response.Steam))
		case WebsocketType:
			responseBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Response.Websocket))
		case ProtoBufType:
			responseBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Response.ProtoBuf))
		case TdfType:
			responseBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Response.Tdf))
		case TafType:
			responseBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Response.Taf))
		case AccType:
			responseBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Response.Acc))
		case NotesType:
			responseBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Response.Notes))
		case MsgpackType:
			responseBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Response.Msgpack))
		case UnitTestType:
			responseBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Response.UnitTest))
		case GitProxyType:
			responseBodyDecoderTab.AddTab(ux.NewTabItem(bodyType.String(), c.Response.GitProxy))
		}
	}

	spRight := ux.Split{
		Ratio:  0, // 布局比例，0 表示居中，-1 表示完全靠左，1 表示完全靠右
		Bar:    10,
		Axis:   layout.Vertical,
		First:  requestBodyDecoderTab.Layout,  // top 解码包请求 requestBodyDecoder
		Second: responseBodyDecoderTab.Layout, // bottom 解码包响应 responseBodyDecoder
	}

	sp := &ux.Split{
		Ratio:  0.3, // 布局比例，0 表示居中，-1 表示完全靠左，1 表示完全靠右
		Bar:    10,
		Axis:   layout.Horizontal,
		First:  NewTable().Layout, // left 表格
		Second: spRight.Layout,    // right row 包解码
	}

	panel.AddChild(sp)
	ux.Run(panel)
}

//go:embed asserts/bar
var myIcons embed.FS

func NewTable() ux.Widget {
	t := ux.NewTreeTable(packet.EditData{})
	t.TableContext = ux.TableContext[packet.EditData]{
		CustomContextMenuItems: func(gtx layout.Context, n *ux.Node[packet.EditData]) iter.Seq[ux.ContextMenuItem] {
			return func(yield func(ux.ContextMenuItem) bool) {
			}
		},
		MarshalRowCells: func(n *ux.Node[packet.EditData]) (cells []ux.CellData) {
			if n.Container() {
				n.SumChildren()
			}
			// var ImageBuffer []byte  //todo 包类型设置图标
			// switch n.Data.SchemerType {
			// case httpClient.TcpType:
			// 	ImageBuffer = tcpIcon
			// default:
			// 	// panic("unhandled default case")
			// }

			// return []ux.CellData{
			//	{ImageBuffer: ImageBuffer, Text: n.Data.SchemerType.String(), FgColor: 0},

			return ux.MarshalRow(n.Data, func(key string, field any) (value string) {
				return ""
			})
		},
		UnmarshalRowCells: func(n *ux.Node[packet.EditData], rows []ux.CellData) packet.EditData {
			return ux.UnmarshalRow[packet.EditData](rows, func(key, value string) (field any) {
				// mylog.Struct(values)
				// n.Data.SchemerType = httpClient.WebsocketTlsType.AssertBy(values[0]) // todo
				return nil
			})
		},
		RowSelectedCallback: func() {
			// row := t.SelectedNode //todo
			// requestBodyDecoder.HttpDump.SetCode(row.Data.ReqBodyDecoder.HttpDump)
			// requestBodyDecoder.PayloadHexDump.SetCode(row.Data.ReqBodyDecoder.PayloadHexDump)
			// requestBodyDecoder.UnitTest.SetCode(row.Data.ReqBodyDecoder.UnitTest)
			// requestBodyDecoder.SteamAesKey.SetCode(hex.Dump(row.Data.ReqBodyDecoder.SteamAesKey))
			// requestBodyDecoder.Steam.SetCode(row.Data.ReqBodyDecoder.Steam)
			// requestBodyDecoder.ProtoBuf.SetCode(row.Data.ReqBodyDecoder.ProtoBuf)
			// requestBodyDecoder.Tdf.SetCode(row.Data.ReqBodyDecoder.Tdf)
			// requestBodyDecoder.Taf.SetCode(row.Data.ReqBodyDecoder.Taf)
			// requestBodyDecoder.Acc.SetCode(row.Data.ReqBodyDecoder.Acc)
			// requestBodyDecoder.Websocket.SetCode(row.Data.ReqBodyDecoder.Websocket)
			// requestBodyDecoder.Msgpack.SetCode(row.Data.ReqBodyDecoder.Msgpack)
			//
			// responseBodyDecoder.HttpDump.SetCode(row.Data.RespBodyDecoder.HttpDump)
			// responseBodyDecoder.PayloadHexDump.SetCode(row.Data.RespBodyDecoder.PayloadHexDump)
			// responseBodyDecoder.UnitTest.SetCode(row.Data.RespBodyDecoder.UnitTest)
			// responseBodyDecoder.SteamAesKey.SetCode(hex.Dump(row.Data.RespBodyDecoder.SteamAesKey))
			// responseBodyDecoder.Steam.SetCode(row.Data.RespBodyDecoder.Steam)
			// responseBodyDecoder.ProtoBuf.SetCode(row.Data.RespBodyDecoder.ProtoBuf)
			// responseBodyDecoder.Tdf.SetCode(row.Data.RespBodyDecoder.Tdf)
			// responseBodyDecoder.Taf.SetCode(row.Data.RespBodyDecoder.Taf)
			// responseBodyDecoder.Acc.SetCode(row.Data.RespBodyDecoder.Acc)
			// responseBodyDecoder.Websocket.SetCode(row.Data.RespBodyDecoder.Websocket)
			// responseBodyDecoder.Msgpack.SetCode(row.Data.RespBodyDecoder.Msgpack)
		},
		RowDoubleClickCallback: func() {
		},
		SetRootRowsCallBack: func() {
			go func() {
				CreatItem := func(session *packet.Session) {
					go func() {
						time.Sleep(20 * time.Millisecond)
						// mylog.Struct(session.Packet.EditData)
						// ux.InvokeTaskAfter(func() {
						t.Root.AddChildByData(session.Packet.EditData)
						// t.ScrollRowIntoView(t.Root.LastChild())
						// }, 20*time.Millisecond)
					}()
				}
				mitmproxy.New("", func(session *packet.Session) {
					RequestURI := session.Request.RequestURI
					if strings.Contains(RequestURI, "github.com") {
						mylog.Warning("origin RequestURI", RequestURI)
						// RequestURI = strings.ReplaceAll(RequestURI, "github.com", "github.com")
						session.Request.RequestURI = RequestURI
						mylog.Warning("new RequestURI", RequestURI)
					}
					switch session.SchemerType {
					case httpClient.HttpType:
						// todo 请求失败必须强制发送事件，否则会丢包，需要检查源代码，所以入栈就不用发事件了
						// 总的老说就是，入栈成功，出栈也成功，则在出栈的时候发送事件，表现为请求成功，返回200
						// 总的老说就是，入栈失败，出栈一定失败，则在出栈的时候填充入栈信息并发送事件，具体表现为：请求失败
						if session.StreamDirection == packet.Outbound {
							// mylog.Response(session.Response, false)
							CreatItem(session)
							// //tableView.ScrollDimToContentEnd(mat32.Y)
							return
						}
						mylog.Request(session.Request, false)
					case httpClient.HttpsType:
						if session.StreamDirection == packet.Outbound {
							// mylog.Response(session.Response, false)
							CreatItem(session)

							// tableView.ScrollDimToContentEnd(mat32.Y)

							return
						}
						mylog.Request(session.Request, false)

					// todo s4-5是否需要建立容器节点?
					case httpClient.Socket4Type:
						switch session.StreamDirection {
						case packet.Inbound:

							CreatItem(session)

							// tableView.ScrollDimToContentEnd(mat32.Y)

							mylog.HexDump(session.SchemerType.String()+" "+session.StreamDirection.String(), session.ReqBodyDecoder.Payload)
						case packet.Outbound:

							CreatItem(session)

							// tableView.ScrollDimToContentEnd(mat32.Y)

							mylog.HexDump(session.SchemerType.String()+" "+session.StreamDirection.String(), session.RespBodyDecoder.Payload)
						}
					case httpClient.Socket5Type:
						switch session.StreamDirection {
						case packet.Inbound:

							CreatItem(session)

							// tableView.ScrollDimToContentEnd(mat32.Y)

							mylog.HexDump(session.SchemerType.String()+" "+session.StreamDirection.String(), session.ReqBodyDecoder.Payload)
						case packet.Outbound:

							CreatItem(session)

							// tableView.ScrollDimToContentEnd(mat32.Y)

							mylog.HexDump(session.SchemerType.String()+" "+session.StreamDirection.String(), session.RespBodyDecoder.Payload)
						}

					case httpClient.WebSocketType:
						// todo 多个网址都有tcp或者websocket的话如何区分并设置容器节点？ mock数据进行单元测试
						// 如果父级是tcp
						// host相同则添加到父节点的孩子
						// 否则新建容器节点
						//

						t.Root.AddContainerByData(session.Packet.Host, session.Packet.EditData) // todo test

						ss := stream.NewBuffer(session.StreamDirection.String() + " " + session.Request.URL.String())
						ss.Indent(1)
						ss.WriteString(session.WebsocketStatus)
						ss.Indent(1)
						switch session.StreamDirection {
						case packet.Inbound:
							mylog.HexDump(ss.String(), session.ReqBodyDecoder.Payload)
							for _, node := range t.Root.WalkContainer() {
								node.AddChildByData(session.Packet.EditData)
								// tableView.ScrollDimToContentEnd(mat32.Y)
							}
						case packet.Outbound:
							mylog.HexDump(ss.String(), session.RespBodyDecoder.Payload)
							for _, node := range t.Root.WalkContainer() {
								node.AddChildByData(session.Packet.EditData)
								// tableView.ScrollDimToContentEnd(mat32.Y)
							}
						}
					case httpClient.WebsocketTlsType:
						t.Root.AddContainerByData(session.Packet.Host, session.Packet.EditData) // todo test
						ss := stream.NewBuffer(session.StreamDirection.String() + " " + session.Request.URL.String())
						ss.Indent(1)
						ss.WriteString(session.WebsocketStatus)
						ss.Indent(1)
						switch session.StreamDirection {
						case packet.Inbound:
							mylog.HexDump(ss.String(), session.ReqBodyDecoder.Payload)
							for _, node := range t.Root.WalkContainer() {
								node.AddChildByData(session.Packet.EditData)
								// tableView.ScrollDimToContentEnd(mat32.Y)
							}
						case packet.Outbound:
							mylog.HexDump(ss.String(), session.RespBodyDecoder.Payload)
							for _, node := range t.Root.WalkContainer() {
								node.AddChildByData(session.Packet.EditData)
								// tableView.ScrollDimToContentEnd(mat32.Y)
							}
						}
					case httpClient.TcpType:
						t.Root.AddContainerByData(session.Packet.Host, session.Packet.EditData) // todo test
						switch session.StreamDirection {
						case packet.Inbound:
							mylog.HexDump(session.StreamDirection.String()+" "+session.Request.URL.String(), session.ReqBodyDecoder.Payload)
							for _, node := range t.Root.WalkContainer() {
								node.AddChildByData(session.Packet.EditData)
								// tableView.ScrollDimToContentEnd(mat32.Y)
							}
						case packet.Outbound:
							mylog.HexDump(session.StreamDirection.String()+" "+session.Request.URL.String(), session.RespBodyDecoder.Payload)
							for _, node := range t.Root.WalkContainer() {
								node.AddChildByData(session.Packet.EditData)
								// tableView.ScrollDimToContentEnd(mat32.Y)
							}
						}
					case httpClient.TcpTlsType:
						// 怎么防止第二个不同host的tcp包进来是插入到root还是新增一个容器节点？需要单元式，也许应该在上面顶一个一个tcp容器节点，
						// 然后比较host是否新建？这样才合理

						t.Root.AddContainerByData(session.Packet.Host, session.Packet.EditData)
						switch session.StreamDirection {
						case packet.Inbound:
							mylog.HexDump(session.StreamDirection.String()+" "+session.Request.URL.String(), session.ReqBodyDecoder.Payload)
							// 这里也一样，要判断选择哪个父节点
							// 如果第三个不同host的tcp进来呢？所以需要一个map来存放比较，然而无论多少个tcp容器节点，他们都应该插入到root的第一层下
							// 后续的tcp流只要找准它的父节点即可，只要就友好的区分开了n个tcp全双工的包了
							for _, node := range t.Root.WalkContainer() {
								node.AddChildByData(session.Packet.EditData)
								// tableView.ScrollDimToContentEnd(mat32.Y)
							}
						case packet.Outbound:
							mylog.HexDump(session.StreamDirection.String()+" "+session.Request.URL.String(), session.RespBodyDecoder.Payload)
							for _, node := range t.Root.WalkContainer() {
								node.AddChildByData(session.Packet.EditData)
								// tableView.ScrollDimToContentEnd(mat32.Y)
							}
						}
					case httpClient.UdpType:

						CreatItem(session)

						// tableView.ScrollDimToContentEnd(mat32.Y)

					case httpClient.KcpType:

						CreatItem(session)

						// tableView.ScrollDimToContentEnd(mat32.Y)

					case httpClient.PipeType:

						CreatItem(session)

						// tableView.ScrollDimToContentEnd(mat32.Y)

					case httpClient.QuicType:

						CreatItem(session)

						// tableView.ScrollDimToContentEnd(mat32.Y)

					case httpClient.RpcType:

						CreatItem(session)

						// tableView.ScrollDimToContentEnd(mat32.Y)

					case httpClient.SshType:

						CreatItem(session)

						// tableView.ScrollDimToContentEnd(mat32.Y)

					default:
						mylog.CheckIgnore(session.SchemerType.String())
					}
				}).ListenAndServe()
			}()
		},
		JsonName:   "mitmproxy",
		IsDocument: false,
	}
	return t
}

type (
	Codec struct {
		Request  BodyDecoder
		Response BodyDecoder
	}
	BodyDecoder struct {
		HttpDump *ux.CodeEditor
		// Payload        *ux.CodeView
		PayloadHexDump *ux.CodeEditor
		UnitTest       *ux.CodeEditor
		SteamAesKey    *ux.CodeEditor
		Steam          *ux.CodeEditor
		ProtoBuf       *ux.CodeEditor
		Tdf            *ux.CodeEditor
		Taf            *ux.CodeEditor
		Acc            *ux.CodeEditor
		Notes          *ux.CodeEditor
		Websocket      *ux.CodeEditor
		Msgpack        *ux.CodeEditor
		GitProxy       *ux.CodeEditor
	}
)

func NewCodec() *Codec {
	path := "main.go"
	return &Codec{
		Request: BodyDecoder{
			HttpDump:       ux.NewCodeEditor(path),
			PayloadHexDump: ux.NewCodeEditor(path),
			UnitTest:       ux.NewCodeEditor(path),
			SteamAesKey:    ux.NewCodeEditor(path),
			Steam:          ux.NewCodeEditor(path),
			ProtoBuf:       ux.NewCodeEditor(path),
			Tdf:            ux.NewCodeEditor(path),
			Taf:            ux.NewCodeEditor(path),
			Acc:            ux.NewCodeEditor(path),
			Notes:          ux.NewCodeEditor(path),
			Websocket:      ux.NewCodeEditor(path),
			Msgpack:        ux.NewCodeEditor(path),
			GitProxy:       ux.NewCodeEditor(path),
		},
		Response: BodyDecoder{
			HttpDump:       ux.NewCodeEditor(path),
			PayloadHexDump: ux.NewCodeEditor(path),
			UnitTest:       ux.NewCodeEditor(path),
			SteamAesKey:    ux.NewCodeEditor(path),
			Steam:          ux.NewCodeEditor(path),
			ProtoBuf:       ux.NewCodeEditor(path),
			Tdf:            ux.NewCodeEditor(path),
			Taf:            ux.NewCodeEditor(path),
			Acc:            ux.NewCodeEditor(path),
			Notes:          ux.NewCodeEditor(path),
			Websocket:      ux.NewCodeEditor(path),
			Msgpack:        ux.NewCodeEditor(path),
			GitProxy:       ux.NewCodeEditor(path),
		},
	}
}

var methods = []string{
	http.MethodGet,
	// http.MethodHead,
	http.MethodPost,
	// http.MethodPut,
	// http.MethodPatch,
	// http.MethodDelete,
	http.MethodConnect,
	// http.MethodOptions,
	// http.MethodTrace,
}

func getRandomMethod() string {
	return stream.RandomAnySlice(methods)
}

func getRandomLayer() httpClient.SchemerType {
	return stream.RandomAnySlice(httpClient.WebsocketTlsType.EnumTypes())
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

var (
	th     = ux.NewTheme()
	appBar *ux.AppBar
)
