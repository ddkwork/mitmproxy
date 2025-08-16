package packet

import (
	"fmt"
	"go/format"
	"net"
	"net/http"
	"strconv"
	"testing"

	"github.com/ddkwork/golibrary/std/mylog"
	"github.com/ddkwork/golibrary/std/stream"
	"github.com/ddkwork/golibrary/std/stream/net/httpClient"
	"github.com/ddkwork/mitmproxy/internal/ca"
)

func Test_makeUnitTest(t *testing.T) {
	header := http.Header{"Connection": {"upgRade"}, "Upgrade": {"WebSocket"}}
	s := stream.NewBuffer(Import)
	s.NewLine()
	s.WriteStringLn("func UnitTest() {")
	s.WriteString("head:=")
	s.WriteStringLn(fmt.Sprintf("%#v", header))
	s.WriteStringLn("c := httpClient.newObject()")
	uri := ""
	proxyPort := ":8888"
	s.WriteString("if !c.Url(")
	s.WriteString(strconv.Quote(uri))
	s.WriteString(").ProxyHttp(")
	s.WriteString(strconv.Quote(proxyPort))
	s.WriteStringLn(").Row(Row).Post().SetHead(head).Request() {")
	s.WriteStringLn("return")
	s.WriteStringLn("}")
	s.WriteStringLn("}")
	source := mylog.Check2(format.Source(s.Bytes()))

	mylog.Success("UnitTest", string(source))
}

func UnitTest() {
	// www.baidu.com
	head := map[string]string{"Connection": "upgRade", "Upgrade": "WebSocket"}
	c := httpClient.New()
	c.Post("https://www.baidu.com").SetProxy(httpClient.HttpsType, net.JoinHostPort(httpClient.Localhost, ca.ProxyPort)).Body(httpClient.LogeventBuf).SetHead(head).Request()
}
