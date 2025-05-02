package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/mitmproxy/internal/ca"

	"github.com/hupe1980/socks"
)

func StartHTTPServer(wg *sync.WaitGroup) {
	log.Println("Starting HTTP server")

	go func() {
		http.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
			fmt.Fprint(rw, "Hello World")
		})
		mylog.Check(http.ListenAndServe("localhost:8080", nil))
	}()

	wg.Done()
}

func StartSocksServer(wg *sync.WaitGroup) {
	log.Println("Starting socks server")

	go func() {
		log.Fatal(socks.ListenAndServe(":1080"))
	}()

	wg.Done()
}

func main() {
	wg := &sync.WaitGroup{}
	// wg.Add(2)
	wg.Add(1)

	StartHTTPServer(wg)
	// StartSocksServer(wg)

	wg.Wait()

	client := http.Client{
		Transport: &http.Transport{
			Proxy: func(request *http.Request) (*url.URL, error) {
				return url.Parse("socks5://" + ca.ProxyServeAddress())
				return url.Parse("socks5://localhost:1080")
			},
		},
	}

	resp := mylog.Check2(client.Get("http://localhost:8080"))

	defer resp.Body.Close()

	body := mylog.Check2(io.ReadAll(resp.Body))

	log.Printf("[%s] %s", resp.Status, body)
}
