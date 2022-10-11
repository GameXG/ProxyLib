package socks5

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// echo 服务
// 一般是测试需求
type EchoServer struct {
	conf *EchoServerConfig

	tcpLn   *net.TCPListener
	udpConn *net.UDPConn
}

type EchoServerConfig struct {
	TcpAddr string
	UdpAddr string
}

func NewEchoServer(conf *EchoServerConfig) *EchoServer {
	return &EchoServer{
		conf: conf,
	}
}

func (s *EchoServer) Listen() (rErr error) {
	conf := s.conf

	if s.tcpLn != nil {
		return fmt.Errorf("tcpLn!=nil")
	}

	if s.udpConn != nil {
		return fmt.Errorf("")
	}

	if addr := strings.TrimSpace(conf.TcpAddr); len(addr) != 0 {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("net.Listen, %v", err)
		}
		defer func() {
			if rErr != nil {
				_ = ln.Close()
			}
		}()

		tcpLn, _ := ln.(*net.TCPListener)
		if tcpLn == nil {
			return fmt.Errorf("非预期的 ln %t", ln)
		}

		s.tcpLn = tcpLn
	}

	if addr := strings.TrimSpace(conf.UdpAddr); len(addr) != 0 {
		ln, err := net.ListenPacket("udp", addr)
		if err != nil {
			return fmt.Errorf("net.Listen. %v", err)
		}
		defer func() {
			if rErr != nil {
				_ = ln.Close()
			}
		}()

		udpLn, _ := ln.(*net.UDPConn)
		if udpLn == nil {
			return fmt.Errorf("非预期的 ln %t", ln)
		}

		s.udpConn = udpLn
	}

	return nil
}

func (s *EchoServer) Serve() error {
	tcpLn := s.tcpLn
	udpLn := s.udpConn

	if tcpLn == nil && udpLn == nil {
		return fmt.Errorf("ln==nil")
	}

	defer s.Close()

	respChan := make(chan error, 2)

	if ln := s.tcpLn; ln != nil {
		go func() {
			err := s.TcpServer(ln)
			if err != nil {
				respChan <- err
			}
		}()
	}

	if ln := s.udpConn; ln != nil {
		go func() {
			err := s.UdpServer(ln)
			if err != nil {
				respChan <- err
			}
		}()
	}

	err := <-respChan
	return err
}

func (s *EchoServer) Close() {
	if ln := s.tcpLn; ln != nil {
		_ = ln.Close()
	}

	if ln := s.udpConn; ln != nil {
		_ = ln.Close()
	}
}

func (s *EchoServer) TcpServer(ln *net.TCPListener) error {
	defer ln.Close()

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
			defer c.Close()

			buf := make([]byte, 4096)

			n, err := c.Read(buf)
			if err != nil {
				return
			}

			_, _ = c.Write(buf[:n])
		}()
	}
}

func (s *EchoServer) UdpServer(ln *net.UDPConn) error {
	defer ln.Close()

	buf := make([]byte, 2048)

	for {
		n, addr, err := ln.ReadFrom(buf)
		if err != nil {
			return err
		}

		_, _ = ln.WriteTo(buf[:n], addr)
	}
}
