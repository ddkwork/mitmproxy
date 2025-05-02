package packet

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ddkwork/golibrary/mylog"
)

func NewResponse(code int, body io.Reader, req *http.Request) *http.Response {
	if body == nil {
		body = &bytes.Buffer{}
	}
	rc, ok := body.(io.ReadCloser)
	if !ok {
		rc = io.NopCloser(body)
	}
	res := &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       rc,
		Request:    req,
	}
	if req != nil {
		res.Close = req.Close
		res.Proto = req.Proto
		res.ProtoMajor = req.ProtoMajor
		res.ProtoMinor = req.ProtoMinor
	}
	return res
}

func OkResponse() *http.Response {
	header := make(http.Header)
	res := &http.Response{
		Status:     "Ok",
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
	}
	return res
}

func ProxyUnauthorizedResponse() *http.Response {
	header := make(http.Header)
	header.Set("Proxy-Authenticate", `Basic realm="Restricted"`)
	res := &http.Response{
		Status:     "Proxy Authentication Required",
		StatusCode: 407,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
	}
	return res
}

func WriteResponse(Response *http.Response, ReadWriter *bufio.ReadWriter) {
	mylog.Call(func() {
		mylog.Check(Response.Write(ReadWriter))
		mylog.Check(ReadWriter.Flush())
	})
}

func NewErrorResponse(req *http.Request, err error) *http.Response {
	res := NewResponse(http.StatusBadGateway, nil, req)
	res.Close = true
	date := res.Header.Get("Date")
	if date == "" {
		date = time.Now().Format(http.TimeFormat)
	}
	w := fmt.Sprintf(`199 "mitmproxy" %q %q`, err.Error(), date)
	res.Header.Add("Warning", w)
	return res
}
