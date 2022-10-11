package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gamexg/proxylib/goio"

	"github.com/gamexg/proxylib/mempool"
)

type ServerConfig struct {
	// socks5 握手超时时间
	Socks5ShakeHandsTimeout time.Duration

	ForwardTimeout time.Duration
	// 默认值 32*1024
	ForwardBufSize int
	// 快速转发
	// true 时，不等到远程网站连接建立成功就返回 socks5 连接已成功 cmdR 包
	// 使得 socks5 客户端可以立刻发出之后的请求(例如 http 请求)。
	FastForward bool

	// udp cmd addr 兼容
	// 按照 rfc1928 标准，当 cmd 命令提供 addr 字段时，表明 socks5 客户端只会从这个地址向 socks5 服务端发出 udp 包，服务器要丢弃其他
	// 地址发出的 udp 包。但是有些 socks5 客户端实现错误，会将目标网站的地址填入 cmd addr 字段内，造成 socks5 udp 无法工作。
	// 本选项 UdpAssociateCmdAddrCompatibility 设置为 true 时，将忽略 cmd addr 字段设置，允许 socks5 客户端使用任意地址发出请求。
	UdpAssociateCmdAddrCompatibility bool

	// 向 目标网站 建立 tcp 连接使用的函数
	SiteTcpDialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// 连接超时
	SiteTcpDialContextDialTimeout time.Duration
	// 向 目标网站 建立 udp 连接使用的函数
	SiteUdpListen func(ctx context.Context) (net.PacketConn, error)
	// SiteUdpListen 曹氏时间
	SiteUdpListenTimeout time.Duration

	// 向 socks5 客户端建立监听使用的函数
	Socks5ClientUdpListen func(ctx context.Context, network string) (net.PacketConn, error)
	// 向 socks5 客户端建立 udp 连接时使用的函数
	// 为空则使用 Socks5ClientUdpListen ,并忽略来源检查
	Socks5ClientUdpDial func(ctx context.Context, network, addr string) (net.PacketConn, error)
	// Socks5ClientUdpListen、Socks5ClientUdpDial 超时时间
	Socks5ClientUdpListenAndDialTimeout time.Duration

	Socks5AuthCheckMethod          func(a []Socks5AuthMethodType) Socks5AuthMethodType
	Socks5AuthCheckUserAndPassword func(user, password string) error
}

func (c *ServerConfig) Default() {
	dial := net.Dialer{}

	*c = ServerConfig{
		Socks5ShakeHandsTimeout:          10 * time.Second,
		ForwardTimeout:                   2 * 60 * time.Second,
		ForwardBufSize:                   32 * 1024,
		FastForward:                      false,
		UdpAssociateCmdAddrCompatibility: false,
		SiteTcpDialContext:               dial.DialContext,
		SiteTcpDialContextDialTimeout:    10 * time.Second,
		SiteUdpListen: func(ctx context.Context) (net.PacketConn, error) {
			return net.ListenPacket("udp", ":0")
		},
		SiteUdpListenTimeout: 10 * time.Second,
		Socks5ClientUdpListen: func(ctx context.Context, network string) (net.PacketConn, error) {
			return net.ListenPacket(network, ":0")
		},
		Socks5ClientUdpDial: func(ctx context.Context, network, addr string) (net.PacketConn, error) {
			d := net.Dialer{}
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			udpConn, _ := c.(*net.UDPConn)
			if udpConn == nil {
				return nil, fmt.Errorf("非预期的 net.UDPConn 类型, %#v", c)
			}

			return udpConn, nil
		},
		Socks5ClientUdpListenAndDialTimeout: 10 * time.Second,
		Socks5AuthCheckMethod: func(a []Socks5AuthMethodType) Socks5AuthMethodType {
			for _, v := range a {
				if v == Socks5AuthMethodTypeNone {
					return Socks5AuthMethodTypeNone
				}
			}

			return Socks5AuthMethodTypeErr
		},
		Socks5AuthCheckUserAndPassword: func(user, password string) error {
			return fmt.Errorf("not support")
		},
	}
}

// 本连接会负责 c 和 dial新建的连接
func ServeConn(ctx context.Context, c net.Conn, conf *ServerConfig) error {
	lCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(conf.Socks5ShakeHandsTimeout))

	// 读取 auth
	auth := Socks5AuthPack{}
	err := auth.Read(c)
	if err != nil {
		return fmt.Errorf("auth.Read, %v", err)
	}

	// 检查
	method := conf.Socks5AuthCheckMethod(auth.Methods)

	// 发送 authR 回应
	authR := Socks5AuthRPack{
		Ver:    5,
		Method: method,
	}
	err = authR.Write(c)
	if err != nil {
		return fmt.Errorf("authR.Write, %v", err)
	}

	switch method {
	case Socks5AuthMethodTypeNone:
		break
	case Socks5AuthMethodTypePassword:
		err := serverConnAuthPassword(c, conf)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("authR.method: %v", method)
	}

	cmd := Socks5CmdPack{}
	err = cmd.Read(c)
	if err != nil {
		return fmt.Errorf("cmd.Read, %v", err)
	}
	cmdR := Socks5CmdPack{
		Ver:  5,
		Cmd:  0,
		Rsv:  0,
		Atyp: Socks5CmdAtypTypeIP4,
		Host: []byte{0, 0, 0, 0},
		Port: 0,
	}

	switch cmd.Cmd {
	case Socks5CmdTypeConnect:
		err := serverConnConnect(lCtx, c, conf, &cmd, &cmdR)
		if err != nil {
			return err
		}

	case Socks5CmdTypeUdpAssociate:
		err = serverConnUdpAssociate(lCtx, c, conf, &cmd, &cmdR)
		if err != nil {
			return err
		}

		//case CSocks5Bind:
	default:
		cmdR.Cmd = Socks5CmdReplyCommandNotSupported
		_ = cmdR.Write(c)
		return fmt.Errorf("cmd %v is not supported", cmd.Cmd)
	}

	return nil
}

// 建立到 socks5 客户端的 udp 连接
// 如果 src 为空，则内部使用 listen
func serverConnUdpSocks5ClientDial(ctx context.Context, conf *ServerConfig, socks5ClientSrcAddr *net.UDPAddr, tpcConn net.Conn) (net.PacketConn, bool, error) {
	if conf.Socks5ClientUdpDial == nil {
		socks5ClientSrcAddr = nil
	}

	// dial
	if socks5ClientSrcAddr != nil {
		packConn, err := conf.Socks5ClientUdpDial(ctx, "udp", socks5ClientSrcAddr.String())
		if err != nil {
			return nil, true, err
		}

		return packConn, true, nil
	}

	// listen
	if conf.Socks5ClientUdpListen == nil {
		return nil, false, fmt.Errorf("conf.Socks5ClientUdpListen")
	}

	packConn, err := conf.Socks5ClientUdpListen(ctx, "udp")
	if err != nil {
		return nil, false, fmt.Errorf("Socks5ClientUdpListen, %v", err)
	}

	return packConn, false, nil
}

// 处理 udp 请求
func serverConnUdpAssociate(ctx context.Context, clientConn net.Conn, conf *ServerConfig, cmd *Socks5CmdPack, cmdR *Socks5CmdPack) error {
	s := newUdpServer(ctx, conf, clientConn, cmd, cmdR)
	return s.Serve()
}

func getSocks5ListenUdpAddr(clientConn net.Conn, udpConn net.PacketConn) (*net.UDPAddr, error) {
	localAddr := udpConn.LocalAddr()

	localUdpAddr, _ := localAddr.(*net.UDPAddr)
	if localUdpAddr == nil {
		return nil, fmt.Errorf("localUdpAddr==nil, %#v", localAddr)
	}

	// 如果 udp 连接绑定了 ip，则直接使用
	// todo: 检查 listen 不同情况下 ip 地址区别
	if ip := localUdpAddr.IP; len(ip) != 0 &&
		net.IPv4zero.Equal(ip) == false &&
		net.IPv6zero.Equal(ip) == false {
		return localUdpAddr, nil
	}

	localTcpAddr, _ := clientConn.LocalAddr().(*net.TCPAddr)
	if localTcpAddr == nil {
		return nil, fmt.Errorf("非预期的 tcp 本地地址， %#v", localTcpAddr)
	}

	localUdpAddr.IP = localTcpAddr.IP

	return localUdpAddr, nil
}

// 判断 conn 是否是 ipv6 协议
func ConnIsIpv6(c net.Conn) (bool, error) {
	remoteAddr := c.RemoteAddr()

	var ip net.IP
	switch remoteAddr.(type) {
	case *net.TCPAddr:
		addr, _ := (remoteAddr).(*net.TCPAddr)
		if addr == nil {
			return false, fmt.Errorf("addr == nil")
		}
		ip = addr.IP
	case *net.UDPAddr:
		addr, _ := (remoteAddr).(*net.UDPAddr)
		if addr == nil {
			return false, fmt.Errorf("addr == nil")
		}
		ip = addr.IP
	default:
		return false, fmt.Errorf("remoteAddr 非预期地址类型 ,%#v", remoteAddr)
	}

	ipv4 := ip.To4()
	if len(ipv4) == net.IPv4len {
		return false, nil
	}

	ipv6 := ip.To16()
	if len(ipv6) == net.IPv6len {
		return true, nil
	}

	return false, fmt.Errorf("非预期的 ip 地址类型, %#v", ip)
}

func serverConnConnect(ctx context.Context, clientConn net.Conn, conf *ServerConfig, cmd *Socks5CmdPack, cmdR *Socks5CmdPack) error {
	if conf.FastForward {
		err := cmdR.Write(clientConn)
		if err != nil {
			return fmt.Errorf("cmdR.Write, %v", err)
		}
	}

	dialTimeout := conf.SiteTcpDialContextDialTimeout
	if dialTimeout == 0 {
		dialTimeout = 60 * time.Second
	}
	dialCtx, dialCtxCancel := context.WithTimeout(ctx, dialTimeout)
	defer dialCtxCancel()

	rAddr, err := cmd.GetAddrString()
	if err != nil {
		// 不支持请求中的 atyp
		cmdR.Cmd = 0x08
		_ = cmdR.Write(clientConn)
		return fmt.Errorf("cmd.GetAddrString, %v", err)
	}

	siteConn, err := conf.SiteTcpDialContext(dialCtx, "tcp", rAddr)
	if err != nil {
		// 主机不可达
		cmdR.Cmd = 0x04
		_ = cmdR.Write(clientConn)
		return fmt.Errorf("SiteTcpDialContext, %v", err)
	}
	defer siteConn.Close()

	if !conf.FastForward {
		err := cmdR.Write(clientConn)
		if err != nil {
			return fmt.Errorf("cmdR.Write, %v", err)
		}
	}

	var forwardErr error
	var forwardM sync.Mutex
	setForwardErr := func(err error) {
		forwardM.Lock()
		defer forwardM.Unlock()

		if forwardErr == nil {
			forwardErr = err
		}
	}
	getForwardErr := func() error {
		forwardM.Lock()
		defer forwardM.Unlock()

		return forwardErr
	}

	forward := func(srcConn, dstConn net.Conn, srcName, dstName string) {
		buf := mempool.Get(conf.ForwardBufSize)
		defer mempool.Put(buf)

		for {
			select {
			case <-ctx.Done():
				setForwardErr(ctx.Err())
				return
			default:
				break
			}

			deadline := time.Now().Add(conf.ForwardTimeout)
			_ = srcConn.SetDeadline(deadline)
			_ = dstConn.SetDeadline(deadline)

			n, err := srcConn.Read(buf)
			if err != nil {
				setForwardErr(fmt.Errorf("%v.Read, %v", srcName, err))
				return
			}

			select {
			case <-ctx.Done():
				setForwardErr(ctx.Err())
				return
			default:
				break
			}

			data := buf[:n]

			_, err = goio.WriteAll(dstConn, data)
			if err != nil {
				setForwardErr(fmt.Errorf("%v.Write, %v", dstName, err))
				return
			}
		}
	}

	// 将 siteConn 的数据发送给 clientConn
	go forward(siteConn, clientConn, "siteConn", "clientConn")

	// 将 clientConn 的数据转发给 siteConn
	forward(clientConn, siteConn, "clientConn", "siteConn")

	return getForwardErr()
}

func serverConnAuthPassword(c io.ReadWriter, conf *ServerConfig) error {
	// 读取账密
	authPassword := Socks5AuthPasswordPack{}
	err := authPassword.Read(c)
	if err != nil {
		return fmt.Errorf("authPassword.Read, %v", err)
	}

	authPasswordR := Socks5AuthPasswordRPack{
		Ver:    1,
		Status: 0,
	}

	err = conf.Socks5AuthCheckUserAndPassword(authPassword.Username, authPassword.Password)
	if err != nil {
		authPasswordR.Status = 1
		_ = authPasswordR.Write(c)
		return fmt.Errorf("Socks5AuthCheckUserAndPassword, %v", err)
	}
	// 写回应
	err = authPasswordR.Write(c)
	if err != nil {
		return fmt.Errorf("authPasswordR.Write, %v", err)
	}
	return nil
}

func ServerLinsten(ctx context.Context, ln net.Listener, conf *ServerConfig) error {
	defer ln.Close()

	lCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-lCtx.Done()
		_ = ln.Close()
	}()

	var tempDelay time.Duration
	for {
		c, e := ln.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				//	log.Warn("Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0

		//	log.Debug("已收到 %v 的请求，开始处理...", c.RemoteAddr())
		go func() {
			err := ServeConn(lCtx, c, conf)
			if err != nil {
				//
			}
		}()
	}
}

func ServeAddr(ctx context.Context, network, addr string, conf *ServerConfig) error {
	lCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ln, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("net.Listen, %v", err)
	}
	defer ln.Close()

	return ServerLinsten(lCtx, ln, conf)
}
