package socks5

import (
	"bytes"
	"context"
	"math/rand"
	"net"
	"testing"

	"github.com/gamexg/proxyclient"
)

func TestConnIsIpv6(t *testing.T) {
	t.Run("ipv4-tcp", func(t *testing.T) {
		c, err := net.Dial("tcp4", "httpbin.org:80")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()

	})
}

func TestServeConn(t *testing.T) {
	// 固定随机数种子
	// 使得每次调试随机结果一致
	rand.Seed(1245688666)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf := ServerConfig{}
	conf.Default()

	go func() {
		err := ServeAddr(ctx, "tcp", "127.0.0.1:14523", &conf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				t.Fatal(err)
			}
		}
	}()

	// echo 服务器
	echoServerConf := EchoServerConfig{
		TcpAddr: "127.0.0.1:4521",
		UdpAddr: "127.0.0.1:4521",
	}
	echoServer := NewEchoServer(&echoServerConf)
	func() {
		err := echoServer.Listen()
		if err != nil {
			t.Fatal(err)
		}
		defer echoServer.Close()

		go func() {
			err := echoServer.Serve()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					t.Errorf("echoServer.Serve, %v", err)
				}
			}
		}()
	}()

	proxyClient, err := proxyclient.NewProxyClient("socks5://127.0.0.1:14523")
	if err != nil {
		t.Fatal(err)
	}

	// 测试 tcp
	func() {
		c, err := proxyClient.Dial("tcp", "127.0.0.1:4521")
		if err != nil {
			return
		}
		defer c.Close()

		// 准备随机数据
		dataList := make([][]byte, 0, 10)
		for i := 0; i < 10; i++ {
			data := make([]byte, rand.Int31n(5000))
			_, _ = rand.Read(data)

			dataList = append(dataList, data)
		}

		go func() {
			defer c.Close()
			for _, v := range dataList {
				_, err := c.Write(v)
				if err != nil {
					t.Fatal(err)
				}
			}
		}()

		for _, v := range dataList {
			buf := make([]byte, len(v))

			n, err := c.Read(buf)
			if err != nil {
				t.Fatal(err)
			}

			data := buf[:n]

			if bytes.Equal(data, v) == false {
				t.Fatal("!=")
			}
		}
	}()

	// 测试 udp
	func() {
		t.Skip("还未实现 udp 测试")

	}()

}
