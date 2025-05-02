// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mitmproxy_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/ddkwork/golibrary/mylog"
)

func ExampleDumpRequest() {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dump := mylog.Check2(httputil.DumpRequest(r, true))

		fmt.Fprintf(w, "%q", dump)
	}))
	defer ts.Close()

	const body = "Go is a general-purpose language designed with systems programming in mind."
	req := mylog.Check2(http.NewRequest("POST", ts.URL, strings.NewReader(body)))

	req.Host = "www.example.org"
	resp := mylog.Check2(http.DefaultClient.Do(req))

	defer resp.Body.Close()

	b := mylog.Check2(io.ReadAll(resp.Body))

	fmt.Printf("%s", b)

	// Output:
	// "POST / HTTP/1.1\r\nHost: www.example.org\r\nAccept-Encoding: gzip\r\nContent-Length: 75\r\nUser-Agent: Go-http-client/1.1\r\n\r\nGo is a general-purpose language designed with systems programming in mind."
}

func ExampleDumpRequestOut() {
	const body = "Go is a general-purpose language designed with systems programming in mind."
	req := mylog.Check2(http.NewRequest("PUT", "http://www.example.org", strings.NewReader(body)))

	dump := mylog.Check2(httputil.DumpRequestOut(req, true))

	fmt.Printf("%q", dump)

	// Output:
	// "PUT / HTTP/1.1\r\nHost: www.example.org\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 75\r\nAccept-Encoding: gzip\r\n\r\nGo is a general-purpose language designed with systems programming in mind."
}

func ExampleDumpResponse() {
	const body = "Go is a general-purpose language designed with systems programming in mind."
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", "Wed, 19 Jul 1972 19:00:00 GMT")
		fmt.Fprintln(w, body)
	}))
	defer ts.Close()

	resp := mylog.Check2(http.Get(ts.URL))

	defer resp.Body.Close()

	dump := mylog.Check2(httputil.DumpResponse(resp, true))

	fmt.Printf("%q", dump)

	// Output:
	// "HTTP/1.1 200 Ok\r\nContent-Length: 76\r\nContent-Type: text/plain; charset=utf-8\r\nDate: Wed, 19 Jul 1972 19:00:00 GMT\r\n\r\nGo is a general-purpose language designed with systems programming in mind.\n"
}

func ExampleReverseProxy() {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "this call was relayed by the reverse proxy")
	}))
	defer backendServer.Close()

	rpURL := mylog.Check2(url.Parse(backendServer.URL))

	frontendProxy := httptest.NewServer(&httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetXForwarded()
			r.SetURL(rpURL)
		},
	})
	defer frontendProxy.Close()

	resp := mylog.Check2(http.Get(frontendProxy.URL))

	b := mylog.Check2(io.ReadAll(resp.Body))

	fmt.Printf("%s", b)

	// Output:
	// this call was relayed by the reverse proxy
}
