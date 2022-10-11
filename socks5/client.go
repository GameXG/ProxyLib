package socks5

import (
	"context"
	"fmt"
	"io"
	"time"
)

type ClientConfig struct {
	// socks5 服务器用户名、密码
	// 都为空则表示不使用用户名密码登录
	Socks5AuthUsername string
	Socks5AuthPassword string

	// socks5 协议握手超时
	Socks5ShakeHandsTimeout time.Duration

	// cmdr 回复超时
	// 指的 socks5 服务器建立到网站连接的耗时时间
	Socks5CmdRTimeout time.Duration
}

// 使用到服务器的连接建立
func ClientTcpConn(ctx context.Context, conf *ClientConfig,
	socks5ServerConn io.ReadWriter, network string, addr string) error {

	switch network {
	//case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("unexpected network %v", network)
	}

	if len(addr) == 0 {
		return fmt.Errorf("addr cannot be empty")
	}

	// 提前检查 addr 格式
	cmd := Socks5CmdPack{
		Ver:  5,
		Cmd:  Socks5CmdTypeConnect,
		Rsv:  0,
		Atyp: 0,
		Host: nil,
		Port: 0,
	}

	err := cmd.SetAddrAuto(addr)
	if err != nil {
		return fmt.Errorf("addr is incorrect, %v", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	//if conf.Socks5ShakeHandsTimeout != 0 {
	//	_ = socks5ServerConn.SetDeadline(time.Now().Add(conf.Socks5ShakeHandsTimeout))
	//}

	auth := Socks5AuthPack{
		Ver:     5,
		Methods: nil,
	}
	if len(conf.Socks5AuthUsername) != 0 || len(conf.Socks5AuthPassword) != 0 {
		auth.Methods = []Socks5AuthMethodType{Socks5AuthMethodTypePassword, Socks5AuthMethodTypeNone}
	} else {
		auth.Methods = []Socks5AuthMethodType{Socks5AuthMethodTypeNone}
	}

	err = auth.Write(socks5ServerConn)
	if err != nil {
		return fmt.Errorf("auth.Write, %v", err)
	}

	authR := Socks5AuthRPack{}

	err = authR.Read(socks5ServerConn)
	if err != nil {
		return fmt.Errorf("authR.Read, %v", err)
	}

	switch authR.Method {
	case Socks5AuthMethodTypeErr:
		return fmt.Errorf("server does not support auth method %#v", auth.Methods)
	case Socks5AuthMethodTypeNone:
		break
	case Socks5AuthMethodTypePassword:
		if len(conf.Socks5AuthUsername) == 0 && len(conf.Socks5AuthPassword) == 0 {
			return fmt.Errorf("server asks for the account password")
		}

		p := Socks5AuthPasswordPack{
			Ver:      1,
			Username: conf.Socks5AuthUsername,
			Password: conf.Socks5AuthPassword,
		}
		err := p.Write(socks5ServerConn)
		if err != nil {
			return fmt.Errorf("Socks5AuthPassword.write, %v", err)
		}

		rP := Socks5AuthPasswordRPack{}
		err = rP.Read(socks5ServerConn)
		if err != nil {
			return fmt.Errorf("Socks5AuthPasswordR.read, %v", err)
		}

		if rP.Status != 0 {
			return fmt.Errorf("server rejected the account password, status=%v", rP.Status)
		}
	}

	err = cmd.Write(socks5ServerConn)
	if err != nil {
		return fmt.Errorf("cmd.write, %v", err)
	}

	cmdR := Socks5CmdPack{}
	err = cmdR.Read(socks5ServerConn)
	if err != nil {
		return fmt.Errorf("cmdR.read, %v", err)
	}

	switch cmdR.Cmd {
	case Socks5CmdReplySucceeded:
		return nil
	default:
		return fmt.Errorf("the server failed to connect to %v, status = %v", addr, cmdR.Cmd)
	}
}
