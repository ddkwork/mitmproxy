package packet_test

import (
	"testing"

	"github.com/ddkwork/mitmproxy/packet"
)

func TestFindProcessPath(t *testing.T) {
	packet.FindProcessPath(packet.TCP, "127.0.0.1:11447", "127.0.0.1:33669")
}
