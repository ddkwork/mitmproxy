package socks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/mitmproxy/packet"
)

type Socks4Handler struct {
	*packet.Session
	Conn     *Conn
	Dialer   Dialer
	listener Listener
	ident    IdentFunc
}

func (h *Socks4Handler) Handle() error {
	req := &Socks4Request{}
	mylog.Check(h.Conn.Read(req))

	if h.ident != nil {
		mylog.Check(h.ident(context.Background(), h.Conn, req))
	}

	switch req.CMD {
	case ConnectCommand:
		return h.handleConnect(req)
	case BindCommand:
		return h.handleBind(req)
	case AssociateCommand:
		fallthrough
	default:
		mylog.Check(h.Conn.Write(&Socks4Response{
			Status: Socks4StatusRejected,
		}))
	}

	return nil
}

func (h *Socks4Handler) handleConnect(req *Socks4Request) error {
	target := mylog.Check2(h.Dialer.DialContext(context.Background(), "tcp", req.Addr))
	//if err != nil {
	//	writeErr := h.Conn.Write(&Socks4Response{
	//		Status: Socks4StatusRejected,
	//	})
	//	if writeErr != nil {
	//		return writeErr
	//	}
	//	return err
	//}

	defer func() {
		mylog.Check(target.Close())
	}()

	mylog.Check(h.Conn.Write(&Socks4Response{
		Status: Socks4StatusGranted,
		Addr:   "",
	}))
	h.Conn.Session = h.Session
	return h.Conn.Tunnel(target)
}

func (h *Socks4Handler) handleBind(req *Socks4Request) error {
	listener := mylog.Check2(h.listener.Listen(context.Background(), "tcp", ":0")) // use a free port
	//if err != nil {
	//	writeErr := h.Conn.Write(&Socks4Response{
	//		Status: Socks4StatusRejected,
	//	})
	//	if writeErr != nil {
	//		return writeErr
	//	}
	//	return err
	//}

	mylog.Check(h.Conn.Write(&Socks4Response{
		Status: Socks4StatusGranted,
		Addr:   listener.Addr().String(),
	}))

	conn := mylog.Check2(listener.Accept())
	//if err != nil {
	//	writeErr := h.Conn.Write(&Socks4Response{
	//		Status: Socks4StatusRejected,
	//		Addr:   conn.RemoteAddr().String(),
	//	})
	//	if writeErr != nil {
	//		return writeErr
	//	}
	//	return err
	//}

	mylog.Check(listener.Close())

	// The SOCKS server checks the IP address of the originating host against
	// the value of DSTIP specified in the client's BIND request.
	mylog.Check(checkIPAddr(req.Addr, conn.RemoteAddr().String()))
	//if err != nil {
	//	mylog.Check(conn.Close())
	//	writeErr := h.Conn.Write(&Socks4Response{
	//		Status: Socks4StatusRejected,
	//	})
	//	if writeErr != nil {
	//		return writeErr
	//	}
	//	return nil
	//}

	// The SOCKS server sends a second reply packet to the client when the
	// anticipated connection from the application server is established.
	mylog.Check(h.Conn.Write(&Socks4Response{
		Status: Socks4StatusGranted,
		Addr:   "",
	}))
	h.Conn.Session = h.Session
	return h.Conn.Tunnel(conn)
}

type Socks5Handler struct {
	*packet.Session
	Conn         *Conn
	Dialer       Dialer
	listener     Listener
	AuthMethods  []AuthMethod
	Authenticate AuthenticateFunc
}

func (h *Socks5Handler) Handle() error {
	methodSelectReq := &MethodSelectRequest{}
	mylog.Check(h.Conn.Read(methodSelectReq))

	method := h.selectAuthMethod(methodSelectReq.Methods)

	mylog.Check(h.Conn.Write(&MethodSelectResponse{
		Method: method,
	}))

	if method == AuthMethodNoAcceptableMethods { // todo
		return errors.New("no supported authentication method")
	}

	if h.Authenticate != nil {
		mylog.Check(h.Authenticate(context.Background(), h.Conn, method))
	}

	req := &Socks5Request{}
	mylog.Check(h.Conn.Read(req))

	switch req.CMD {
	case ConnectCommand:
		return h.handleConnect(req)
	case BindCommand:
		return h.handleBind(req)
	case AssociateCommand:
		fallthrough
	default:
		mylog.Check(h.Conn.Write(&Socks5Response{
			Status: Socks5StatusCMDNotSupported,
		}))
	}
	return nil
}

func (h *Socks5Handler) selectAuthMethod(authMethods []AuthMethod) AuthMethod {
	for _, dm := range authMethods {
		if slices.Contains(h.AuthMethods, dm) {
			return dm
		}
	}

	return AuthMethodNoAcceptableMethods
}

func (h *Socks5Handler) handleConnect(req *Socks5Request) error {
	target := mylog.Check2(h.Dialer.DialContext(context.Background(), "tcp", req.Addr))
	//if err != nil {
	//	msg := err.Error()
	//	status := Socks5StatusHostUnreachable
	//
	//	if strings.Has(msg, "refused") {
	//		status = Socks5StatusConnectionRefused
	//	} else if strings.Has(msg, "network is unreachable") {
	//		status = Socks5StatusNetworkUnreaachable
	//	}
	//
	//	writeErr := h.Conn.Write(&Socks5Response{Status: status})
	//	if writeErr != nil {
	//		return writeErr
	//	}
	//
	//	mylog.Warning("Connect to %v failed: %v", req.Addr, err)
	//
	//	return err
	//}

	defer func() { mylog.Check(target.Close()) }()

	mylog.Check(h.Conn.Write(&Socks5Response{
		Status: Socks5StatusGranted,
		// In the reply to a CONNECT, BND.PORT contains the port number that the
		// server assigned to connect to the target host, while BND.ADDR
		// contains the associated IP address.
		Addr: target.LocalAddr().String(),
	}))
	h.Conn.Session = h.Session
	return h.Conn.Tunnel(target)
}

func (h *Socks5Handler) handleBind(req *Socks5Request) error {
	listener := mylog.Check2(h.listener.Listen(context.Background(), "tcp", ":0"))
	//if err != nil {
	//	writeErr := h.Conn.Write(&Socks5Response{
	//		Status: Socks5StatusFailure,
	//	})
	//	if writeErr != nil {
	//		return writeErr
	//	}
	//
	//	return err
	//}

	mylog.Check(h.Conn.Write(&Socks5Response{
		Status: Socks5StatusGranted,
		Addr:   listener.Addr().String(),
	}))

	conn := mylog.Check2(listener.Accept())
	//if err != nil {
	//	writeErr := h.Conn.Write(&Socks5Response{
	//		Status: Socks5StatusFailure,
	//	})
	//	if writeErr != nil {
	//		return writeErr
	//	}
	//
	//	return err
	//}

	mylog.Check(listener.Close())

	mylog.Check(checkIPAddr(req.Addr, conn.RemoteAddr().String()))
	//if err != nil {
	//	_ = conn.Close()
	//	writeErr := h.Conn.Write(&Socks5Response{
	//		Status: Socks5StatusFailure,
	//	})
	//	if writeErr != nil {
	//		return writeErr
	//	}
	//
	//	return err
	//}

	mylog.Check(h.Conn.Write(&Socks5Response{
		Status: Socks5StatusGranted,
		Addr:   conn.RemoteAddr().String(),
	}))
	h.Conn.Session = h.Session
	return h.Conn.Tunnel(conn)
}

func (h *Socks5Handler) handleAssociate(req *Socks5Request) error {
	var lc net.ListenConfig
	udpConn := mylog.Check2(lc.ListenPacket(context.Background(), "udp", ":0"))
	//if err != nil {
	//	writeErr := h.Conn.Write(&Socks5Response{
	//		Status: Socks5StatusFailure,
	//	})
	//	if writeErr != nil {
	//		return writeErr
	//	}
	//
	//	return err
	//}

	defer func() {
		mylog.Check(udpConn.Close())
	}()

	mylog.Check(h.Conn.Write(&Socks5Response{
		Status: Socks5StatusGranted,
		Addr:   udpConn.LocalAddr().String(),
	}))

	// A UDP association terminates when the TCP connection that the UDP
	// ASSOCIATE request arrived on terminates.
	go func() {
		h.Conn.WaitForClose()
		mylog.Check(udpConn.Close())
	}()

	// TODO

	return nil
}

func checkIPAddr(expected, actual string) error {
	expectedIP, _ := mylog.Check3(net.SplitHostPort(expected))
	actualIP, _ := mylog.Check3(net.SplitHostPort(actual))
	if expectedIP != actualIP {
		return fmt.Errorf("ip mismatch. Expected %s. Got %s", expectedIP, actualIP)
	}
	return nil
}
