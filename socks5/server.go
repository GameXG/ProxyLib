package socks5

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gamexg/goio"

	"github.com/gamexg/go-mempool"
)

type Dial interface {
}

type Config struct {
	Socks5ShakeHandsTimeout time.Duration
	DialTimeout             time.Duration
	ForwardTimeout          time.Duration
	// 32*1024
	ForwardBufSize int
	// 快速转发
	// true 时，不等到远程网站连接建立成功就返回 socks5连接已成功 cmdR 包
	FastForward bool

	DialContext func(ctx context.Context, network, address string) (net.Conn, error)

	Socks5AuthCheckMethod          func(a []Socks5AuthMethodType) Socks5AuthMethodType
	Socks5AuthCheckUserAndPassword func(user, password string) error
}

func (c *Config) Default() {
	dial := net.Dialer{}

	*c = Config{
		Socks5ShakeHandsTimeout: 10 * time.Second,
		DialTimeout:             10 * time.Second,
		ForwardTimeout:          2 * 60 * time.Second,
		ForwardBufSize:          32 * 1024,
		FastForward:             false,
		DialContext:             dial.DialContext,
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
func ServeConn(ctx context.Context, c net.Conn, conf *Config) error {
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

	// 暂时只支持 connect 命令
	//case CSocks5Bind:
	//case Socks5CmdTypeUdpAssociate:
	default:
		cmdR.Cmd = Socks5CmdReplyCommandNotSupported
		_ = cmdR.Write(c)
		return fmt.Errorf("cmd %v is not supported", cmd.Cmd)
	}

	return nil
}

func serverConnConnect(ctx context.Context, clientConn net.Conn, conf *Config, cmd *Socks5CmdPack, cmdR *Socks5CmdPack) error {
	if conf.FastForward {
		err := cmdR.Write(clientConn)
		if err != nil {
			return fmt.Errorf("cmdR.Write, %v", err)
		}
	}

	dialTimeout := conf.DialTimeout
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

	siteConn, err := conf.DialContext(dialCtx, "tcp", rAddr)
	if err != nil {
		// 主机不可达
		cmdR.Cmd = 0x04
		_ = cmdR.Write(clientConn)
		return fmt.Errorf("DialContext, %v", err)
	}

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

func serverConnAuthPassword(c net.Conn, conf *Config) error {
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
