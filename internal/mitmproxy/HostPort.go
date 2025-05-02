package mitmproxy

import (
	"net"
	"net/http"
	"strings"

	"github.com/ddkwork/golibrary/mylog"
)

func RemoveExtraHTTPHostPort(req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if pHost, port, e := net.SplitHostPort(host); e == nil && port == "80" {
		host = pHost
	}
	req.Host = host
	req.URL.Host = host
}

func hasPort(host string) bool {
	colons := strings.Count(host, ":")
	if colons == 0 {
		return false
	}
	if colons == 1 {
		return true
	}
	return host[0] == '[' && strings.Contains(host, "]:")
}

func CanonicalHost(host string) string {
	host = strings.ToLower(host)
	if hasPort(host) {
		port, _ := mylog.Check3(net.SplitHostPort(host))
		host = port
	}
	host = strings.TrimSuffix(host, ".")
	return host
}
