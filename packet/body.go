package packet

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
	"github.com/ddkwork/mitmproxy/internal/ca"
)

type bodyType int

const (
	bodyTypeJson bodyType = iota
	bodyTypeText
	bodyTypeHtml
	bodyTypeJavaScript
)

func (t bodyType) String() string {
	switch t {
	case bodyTypeJson:
		return "application/json"
	case bodyTypeText:
		return "application/text" // todo
	case bodyTypeHtml:
		return "application/html" // todo
	case bodyTypeJavaScript:
		return "application/javascript" // todo
	}
	return "known body type"
}

const Import = `
package UnitTest

import (
  "fmt"
  "go/format"
  "net/http"
  "strconv"
  "testing"
)
`

func makeUnitTest(Request *http.Request, body []byte) string {
	s := stream.NewBuffer(Import)
	s.NewLine()
	s.WriteStringLn("func UnitTest() {")
	s.WriteString("head:=")
	s.WriteStringLn(fmt.Sprintf("%#v", Request.Header))
	s.WriteStringLn("c := httpClient.newObject()")
	Body := fmt.Sprintf("Row:=%#v", body)
	s.WriteStringLn(Body)
	s.WriteString("if !c.Url(")
	s.WriteString(strconv.Quote(Request.URL.String()))
	s.WriteString(").ProxyHttp(")
	s.WriteString(strconv.Quote(ca.ProxyPort))
	s.WriteStringLn(").Row(Row)." + stream.ToCamelUpper(Request.Method) + "().SetHead(head).Request() {")
	s.WriteStringLn("return")
	s.WriteStringLn("}")
	s.WriteStringLn("}")
	source := mylog.Check2(format.Source(s.Bytes()))
	// mylog.Success("UnitTest", string(source))
	return string(source)
}

func decodeJavaScript(Request *http.Request, body []byte) string {
	return decodeBodyByContentType(Request, bodyTypeJavaScript, body)
}

func decodeHtml(Request *http.Request, body []byte) string {
	return decodeBodyByContentType(Request, bodyTypeHtml, body)
}

func decodeText(Request *http.Request, body []byte) string {
	return decodeBodyByContentType(Request, bodyTypeText, body)
}

func decodeJson(Request *http.Request, body []byte) string {
	return decodeBodyByContentType(Request, bodyTypeJson, body)
}

func decodeBodyByContentType(Request *http.Request, Type bodyType, body []byte) string {
	if strings.Contains(Request.Header.Get("Content-Type"), Type.String()) {
		jsonBody := new(bytes.Buffer)
		switch Type {
		case bodyTypeJson:
			mylog.Check(json.Indent(jsonBody, body, "", " "))
			return jsonBody.String()
		case bodyTypeText:
		case bodyTypeHtml:
		case bodyTypeJavaScript:
		}
	}
	return ""
}

func DrainBody(b io.ReadCloser) (body, backBody io.ReadCloser) {
	mylog.CheckNil(b)
	if b == http.NoBody {
		return http.NoBody, http.NoBody
	}
	var buf bytes.Buffer
	mylog.Check2(buf.ReadFrom(b))
	mylog.Check(b.Close())
	return io.NopCloser(&buf), io.NopCloser(bytes.NewReader(buf.Bytes()))
}

// // read all bytes from content body and create new stream using it.
//	var reqBody []byte
//
//	if request.Row != nil {
//		reqBody, err = io.ReadAll(request.Row)
//		if err != nil {
//			log.Panicln(err)
//		}
//		request.Row = io.NopCloser(bytes.NewBuffer(reqBody))
//	}

func ReadDecompressedBody(header http.Header, body io.Reader) []byte {
	if body == nil {
		return nil
	}
	if header.Get("Content-Encoding") == "gzip" {
		gzReader := mylog.Check2(gzip.NewReader(body))
		defer func() { mylog.Check(gzReader.Close()) }()
		return mylog.Check2(io.ReadAll(gzReader))
	}
	return mylog.Check2(io.ReadAll(body))
}
