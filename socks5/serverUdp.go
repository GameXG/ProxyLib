package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
)

// 处理 socks5 udp支持
type udpServer struct {
	ctx                context.Context
	cancel             context.CancelFunc
	conf               *ServerConfig
	socks5ClienTcpConn net.Conn
	cmd                *Socks5CmdPack
	cmdR               *Socks5CmdPack

	// socks5 客户端 cmd 提供的 udp 地址
	// 如果客户端未提供，则为 nil
	socks5ClientCmdUdpAddr *net.UDPAddr

	// 到 socks5 客户端的连接是否为 dial 建立的
	socks5ClientIsDial bool

	udpSiteConn        net.PacketConn
	socks5CliteUdpConn net.PacketConn

	// socks5 客户端的udp地址
	socks5ClientAddr atomic.Value
}

func newUdpServer(ctx context.Context, conf *ServerConfig,
	sock5ClientTcpConn net.Conn, cmd *Socks5CmdPack,
	cmdR *Socks5CmdPack) *udpServer {
	ctx, cancel := context.WithCancel(ctx)

	srv := udpServer{
		ctx:                ctx,
		cancel:             cancel,
		conf:               conf,
		socks5ClienTcpConn: sock5ClientTcpConn,
		cmd:                cmd,
		cmdR:               cmdR,
	}

	return &srv
}

func (s *udpServer) Serve() (err error) {
	conf := s.conf
	cmd := s.cmd
	cmdR := s.cmdR
	ctx := s.ctx
	ctxCancel := s.cancel
	socks5ClienTcpConn := s.socks5ClienTcpConn
	defer socks5ClienTcpConn.Close()
	defer ctxCancel()

	cmdR.Cmd = Socks5CmdReplyGeneralSocksServerFailure
	sendCmdR := false
	defer func() {
		if err != nil && sendCmdR == false {
			_ = cmdR.Write(socks5ClienTcpConn)
		}
	}()

	// 向站点建立udp连接的函数
	siteUdpListen := conf.SiteUdpListen
	if siteUdpListen == nil {
		cmdR.Cmd = Socks5CmdReplyInternalError
		return fmt.Errorf("siteUdpListen == nil")
	}

	// 建立到 socks5 客户端的连接的函数
	socks5ClientListen := conf.Socks5ClientUdpListen
	if socks5ClientListen == nil {
		cmdR.Cmd = Socks5CmdReplyInternalError
		return fmt.Errorf("socks5ClientListen == nil")
	}

	// socks5 客户端发出 socks5 udp 请求的源地址
	// 为 nil 表示不限制，否则需要检查来源。
	var socks5ClientCmdUdpAddr *net.UDPAddr

	// 获取 socks5 客户端的 udp 源地址
	// 这里简单只检查 port 不能为 0(客户端要求限制的情况)
	if conf.UdpAssociateCmdAddrCompatibility != true && cmd.Port != 0 {
		ip, err := cmd.GetHostIp()
		if err != nil {
			cmdR.Cmd = Socks5CmdReplyAddressTypeNotSupported
			return fmt.Errorf("cmd.GetHostIp, %V", err)
		}

		socks5ClientCmdUdpAddr = &net.UDPAddr{IP: ip, Port: int(cmd.Port)}
		s.socks5ClientCmdUdpAddr = socks5ClientCmdUdpAddr
	}

	// 到客户端的连接
	// 根据情况，可能是 dial 直接建立的到客户端的 udp 连接
	// 可能能是 listen 建立的连接
	dialClientCtx, dialClientCtxCancel := context.WithTimeout(ctx, conf.Socks5ClientUdpListenAndDialTimeout)
	defer dialClientCtxCancel()
	socks5ClientUdpConn, isDial, err := serverConnUdpSocks5ClientDial(dialClientCtx, conf, socks5ClientCmdUdpAddr, socks5ClienTcpConn)
	if err != nil {
		cmdR.Cmd = Socks5CmdReplyHostUnreachable
		return fmt.Errorf("serverConnUdpSocks5ClientDial, %v", err)
	}
	defer socks5ClientUdpConn.Close()
	s.socks5CliteUdpConn = socks5ClientUdpConn
	s.socks5ClientIsDial = isDial

	// 获得 socks5 客户端建立连接时连接到的服务器 udp 地址
	socks5ClientAddr, err := getSocks5ListenUdpAddr(socks5ClienTcpConn, socks5ClientUdpConn)
	if err != nil {
		cmdR.Cmd = Socks5CmdReplyInternalError
		return fmt.Errorf("getSocks5ListenUdpAddr, %v", err)
	}

	err = cmdR.SetHostIp(socks5ClientAddr.IP)
	if err != nil {
		cmdR.Cmd = Socks5CmdReplyInternalError
		return fmt.Errorf("cmdR.SetHostIp, %v", err)
	}
	cmdR.Port = uint16(socks5ClientAddr.Port)

	if conf.FastForward {
		sendCmdR = true
		err := cmdR.Write(socks5ClienTcpConn)
		if err != nil {
			return fmt.Errorf("cmdR.Write, %v", err)
		}
	}

	// 开始建立到目标网站的连接
	SiteUdpListenCtx, SiteUdpListenCtxCancel := context.WithTimeout(ctx, conf.SiteUdpListenTimeout)
	defer SiteUdpListenCtxCancel()
	siteConn, err := conf.SiteUdpListen(SiteUdpListenCtx)
	if err != nil {
		cmdR.Cmd = Socks5CmdReplyGeneralSocksServerFailure
		return fmt.Errorf("SiteUdpListen, %v", err)
	}
	defer siteConn.Close()

	s.udpSiteConn = siteConn

	if conf.FastForward == false {
		sendCmdR = true
		err := cmdR.Write(socks5ClienTcpConn)
		if err != nil {
			return fmt.Errorf("cmdR.Write, %v", err)
		}
	}

	// 启动线程， udp 连接包
	go s.udpSend2Client()
	go s.udpSend2Site()

	//等待 tcp 连接终止
	buf := make([]byte, 1)
	for {
		_, err = socks5ClienTcpConn.Read(buf)
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:

		}
		if err != nil && err != io.EOF {
			return err
		}
		return nil
	}
}

func (s *udpServer) udpSend2Client() {
	ctx := s.ctx
	siteConn := s.udpSiteConn
	socks5CliteUdpConn := s.socks5CliteUdpConn

	readBuf := make([]byte, 2048)
	writeBuf := make([]byte, 2048)
	udpPack := Socks5UdpPack{}
	for {
		n, addr, err := siteConn.ReadFrom(readBuf)
		select {
		case <-ctx.Done():
			return
		default:
			break
		}
		if err != nil {
			return
		}

		udpPack.Data = readBuf[:n]

		err = udpPack.SetAddr(addr)
		if err != nil {
			continue
		}

		_, err = udpPack.To(writeBuf)
		if err != nil {
			continue
		}

		socks5ClientUdpAddr := s.getSocks5ClientAddr()
		if socks5ClientUdpAddr == nil {
			continue
		}

		_, err = socks5CliteUdpConn.WriteTo(writeBuf, socks5ClientUdpAddr)
		if err != nil {
			continue
		}
	}
}

func (s *udpServer) udpSend2Site() {
	ctx := s.ctx
	socks5CliteUdpConn := s.socks5CliteUdpConn
	udpSiteConn := s.udpSiteConn

	udpPack := Socks5UdpPack{}
	readBuf := make([]byte, 2048)

	for {
		n, addr, err := socks5CliteUdpConn.ReadFrom(readBuf)
		select {
		case <-ctx.Done():
			return
		default:
			break
		}

		if err != nil {
			continue
		}

		udpAddr, _ := addr.(*net.UDPAddr)
		if udpAddr == nil {
			continue
		}

		// 过滤非预期来源的包
		if a := s.socks5ClientCmdUdpAddr; a != nil && s.socks5ClientIsDial == false {
			// 客户端指定了 udp 地址，但是由于使用者未提供 udp的 dial 函数，所以使用的 listen
			// 需要手动过滤地址不正确的请求

			if udpAddr.Port != a.Port || udpAddr.IP.Equal(a.IP) == false {
				// 来源地址不正确
				continue
			}
		}

		data := readBuf[:n]
		err = udpPack.Parse(data)
		if err != nil {
			continue
		}

		udpPackAddr, err := udpPack.GetUdpAddr()
		if err != nil {
			continue
		}

		s.setSocks5ClientUdpAddr(udpAddr)

		_, err = udpSiteConn.WriteTo(udpPack.Data, udpPackAddr)
		if err != nil {
			return
		}
	}
}

func (s *udpServer) Close() {
	if f := s.cancel; f != nil {
		f()
	}

	if c := s.socks5ClienTcpConn; c != nil {
		c.Close()
	}

	if c := s.udpSiteConn; c != nil {
		_ = c.Close()
	}

	if c := s.socks5CliteUdpConn; c != nil {
		_ = c.Close()
	}
}

func (s *udpServer) getSocks5ClientAddr() *net.UDPAddr {
	if addr := s.socks5ClientCmdUdpAddr; addr != nil {
		return addr
	}

	return s.socks5ClientAddr.Load().(*net.UDPAddr)
}

func (s *udpServer) setSocks5ClientUdpAddr(addr *net.UDPAddr) {
	if s.socks5ClientCmdUdpAddr == nil {
		s.socks5ClientAddr.Store(addr)
	}
}
