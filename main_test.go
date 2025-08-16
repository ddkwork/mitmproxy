package main

import (
	"fmt"
	"iter"
	"net/http"
	"testing"

	"gioui.org/layout"
	"gioui.org/widget"
	"github.com/ddkwork/golibrary/std/mylog"
	"github.com/ddkwork/golibrary/std/safemap"
	"github.com/ddkwork/golibrary/std/stream"
	"github.com/ddkwork/golibrary/std/stream/net/httpClient"
	"github.com/ddkwork/mitmproxy/packet"
	"github.com/ddkwork/ux"
)

func TestGenBody(t *testing.T) {
	m := safemap.NewOrdered[string, string](func(yield func(string, string) bool) {
		yield("HttpDump", "HttpDump")
		yield("hexDump", "hexDump")
		yield("Steam", "Steam")
		yield("Websocket", "Websocket")
		yield("ProtoBuf", "ProtoBuf")
		yield("Tdf", "Tdf")
		yield("Taf", "Taf")
		yield("Acc", "Acc")
		yield("Notes", "Notes")
		yield("Msgpack", "Msgpack")
		yield("UnitTest", "UnitTest")
		yield("GitProxy", "GitProxy")
	})
	stream.NewGeneratedFile().SetPackageName("main").EnumTypes("body", m)
}

func TestName(t *testing.T) {
	table := ux.NewTreeTable(packet.EditData{})
	defer ux.Run("mitmproxy", table)
	table.TableContext = ux.TableContext[packet.EditData]{
		CustomContextMenuItems: func(gtx layout.Context, n *ux.Node[packet.EditData]) iter.Seq[ux.ContextMenuItem] {
			return func(yield func(ux.ContextMenuItem) bool) {
				yield(ux.ContextMenuItem{
					Title:         "NewItem",
					Icon:          nil,
					Can:           func() bool { return true },
					Do:            nil,
					AppendDivider: false,
					Clickable:     widget.Clickable{},
				})
			}
		},
		MarshalRowCells: func(n *ux.Node[packet.EditData]) (cells []ux.CellData) {
			if n.Container() {
				// todo 合并节点编辑的结构体视图，因为它没有容器节点特性显示到结构体
				// 需要嵌套结构体视图实现复用?类型约束不允许估计
				// todo sum and fill first column name,以及孩子节点计数显示
				n.SumChildren()
			}
			// var ImageBuffer []byte
			// switch n.Data.SchemerType {
			// case httpClient.TcpType:
			//	ImageBuffer = tcpIcon
			// default:
			//	// panic("unhandled default case")
			// }
			return ux.MarshalRow(n.Data, func(key string, field any) (value string) {
				return ""
			})
		},
		UnmarshalRowCells: func(n *ux.Node[packet.EditData], rows []ux.CellData) packet.EditData {
			// mylog.Struct(values)
			// n.Data.SchemerType = httpClient.WebsocketTlsType.AssertBy(values[0]) // todo bug
			// n.Data.Method = values[1]
			// n.Data.Host = values[2]
			// n.Data.Path = values[3]
			// n.Data.ContentType = values[4]
			// n.Data.ContentLength = mylog.Check2(strconv.Atoi(values[5]))
			// n.Data.Status = values[6]
			// n.Data.Note = values[7]
			// n.Data.Process = values[8]
			// n.Data.PadTime = mylog.Check2(time.ParseDuration(values[9]))
			return ux.UnmarshalRow[packet.EditData](rows, func(key, value string) (field any) {
				return nil
			})
		},
		RowSelectedCallback: func() {
			mylog.Struct(table.SelectedNode.Data) // todo use it show into http request and response
		},
		RowDoubleClickCallback: func() {
		},
		SetRootRowsCallBack: func() {
			containers := make([]*ux.Node[packet.EditData], 0)
			for i := range 100 {
				container := ux.NewContainerNode("node"+fmt.Sprint(i), packet.EditData{
					SchemerType:   httpClient.HttpType,
					Method:        http.MethodConnect,
					Host:          "www.gogole.com",
					Path:          "/cmsocket",
					ContentType:   "application/json",
					ContentLength: 10,
					Status:        http.StatusText(http.StatusOK),
					Note:          "this is steam",
					Process:       "strem.exe",
					PadTime:       10,
				})
				container.SetParent(table.Root)
				containers = append(containers, container)
			}
			table.Root.SetChildren(containers)

			for i, container := range containers {
				child := ux.NewNode(packet.EditData{
					SchemerType:   httpClient.TcpType,
					Method:        http.MethodConnect,
					Host:          "https://521github.com/gioui/gio-x/blob/main/component/README.md",
					Path:          "/cmsocket",
					ContentType:   "application/json",
					ContentLength: 10,
					Status:        http.StatusText(http.StatusOK),
					Note:          "this is steam",
					Process:       "strem.exe",
					PadTime:       10,
				})
				container.AddChild(child)

				child = ux.NewNode(packet.EditData{
					SchemerType:   httpClient.UdpType,
					Method:        http.MethodConnect,
					Host:          "www.gogole.com",
					Path:          "/cmsocket",
					ContentType:   "application/json",
					ContentLength: 10,
					Status:        http.StatusText(http.StatusOK),
					Note:          "this is steam",
					Process:       "strem.exe",
					PadTime:       10,
				})
				container.AddChild(child)

				child = ux.NewNode(packet.EditData{
					SchemerType:   httpClient.TcpTlsType,
					Method:        http.MethodConnect,
					Host:          "www.gogole.com",
					Path:          "/cmsocket",
					ContentType:   "application/json",
					ContentLength: 10,
					Status:        http.StatusText(http.StatusOK),
					Note:          "this is steam",
					Process:       "strem.exe",
					PadTime:       10,
				})
				container.AddChild(child)

				child = ux.NewNode(packet.EditData{
					SchemerType:   httpClient.HttpsType,
					Method:        http.MethodConnect,
					Host:          "https://521github.com/gioui/gio-x/blob/main/component/README.md",
					Path:          "/cmsocket",
					ContentType:   "application/json",
					ContentLength: i,
					Status:        http.StatusText(http.StatusOK),
					Note:          "this is steam",
					Process:       "strem.exe",
					PadTime:       10,
				})
				container.AddChild(child)
			}
		},
		JsonName:   "mitmproxy",
		IsDocument: false,
	}
}
