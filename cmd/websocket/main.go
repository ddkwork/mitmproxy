package main

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/ddkwork/mitmproxy/internal/mitmproxy"

	"github.com/ddkwork/websocket"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
	"github.com/ddkwork/golibrary/stream/net/httpClient"
	"github.com/ddkwork/mitmproxy/internal/ca"
)

//go:generate  go run -x .

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		http.HandleFunc("/", echo)
		mylog.Check(http.ListenAndServeTLS("localhost:12345", ca.CertFile, ca.KeyFile, nil))
	}()
	go mitmproxy.New(ca.ProxyPort, nil).ListenAndServe()

	endpointURL := "wss://localhost:12345"
	// proxyURL := "http://localhost:6666"
	proxyURL := "http://" + net.JoinHostPort(httpClient.Localhost, ca.ProxyPort)

	surl := mylog.Check2(url.Parse(proxyURL))
	dialer := websocket.Dialer{
		NetDial:           nil,
		NetDialContext:    nil,
		NetDialTLSContext: nil,
		Proxy:             http.ProxyURL(surl),
		TLSClientConfig:   ca.MitmCfg.NewTlsConfigForHost(httpClient.Localhost),
		// TLSClientConfig:   ca.MitmCfg.NewTlsConfigForHost("localhost"),
		HandshakeTimeout:  0,
		ReadBufferSize:    0,
		WriteBufferSize:   0,
		WriteBufferPool:   nil,
		Subprotocols:      []string{"p1"},
		EnableCompression: false,
		Jar:               nil,
	}

	c, res := mylog.Check3(dialer.Dial(endpointURL, nil))

	defer func() {
		mylog.Check(res.Body.Close())
		mylog.Check(c.Close())
	}()

	done := make(chan struct{})

	go func() {
		defer func() { mylog.Check(c.Close()) }()
		defer close(done)
		for {
			mylog.Check3(c.ReadMessage())
			// log.Printf("recv: %s", replay.Payload())
		}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case t := <-ticker.C:
			s := "send " + t.String()
			mylog.Check(c.WriteMessage(websocket.TextMessage, []byte(s)))
		case <-interrupt:
			log.Println("interrupt")
			// To cleanly close a connection, a client should send a close
			// frame and wait for the server to close the connection.
			mylog.Check(c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")))
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			mylog.Check(c.Close())
			return
		}
	}
}

func echo(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	c := mylog.Check2(upgrader.Upgrade(w, r, nil))
	mylog.CheckNil(c)
	defer func() { mylog.Check(c.Close()) }()
	for {
		mt, message := mylog.Check3(c.ReadMessage())
		replay := stream.NewBuffer("recv ")
		mylog.Check2(replay.Write(message))
		mylog.Check(c.WriteMessage(mt, replay.Bytes()))
	}
}
