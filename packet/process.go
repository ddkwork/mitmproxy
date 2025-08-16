package packet

import (
	"net/netip"
	"strings"

	"github.com/Dreamacro/clash/component/process"

	"github.com/ddkwork/golibrary/std/mylog"
)

const (
	TCP = process.TCP
	UDP = process.UDP
)

func FindProcessPath(network, from, to string) (processPath string) { // todo bug
	return "xxxxxxxxxxxxxxxxxxx"
	path := mylog.Check2Ignore(process.FindProcessPath(network, netip.MustParseAddrPort(from), netip.MustParseAddrPort(to)))
	mylog.Warning("processPath", path)
	lastIndex := strings.LastIndex(path, `\`)
	processPath = path[lastIndex+1:]
	return
}
