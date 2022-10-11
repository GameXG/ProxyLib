package socks5

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"proxylib/mempool"
)

// socks5 udp 客户端库
// 方便其他地方使用

type UdpClient struct {
	proxyType string // 只支持  socks5
	proxyAddr string
}

type UdpConn struct {
	tcpConn net.Conn
	udpConn *net.UDPConn
	hasDst  bool   // 客户使用 Dial 提供目标地址时为 true，并在 dst 内保存目标地址。
	dstHost string // 客户提供的目标地址，可能是ip
	dstIp   net.IP // 当客户提供的目标地址是ip时本值存在，可以保证ipv4是4位。
	dstPort int
}

func NewUdpClient(proxyType, proxyAddr string) (*UdpClient, error) {
	switch proxyType {
	case "socks5":
		break
	default:
		return nil, fmt.Errorf("不支持的 proxyType %v 。", proxyType)
	}

	return &UdpClient{
		proxyType: proxyType,
		proxyAddr: proxyAddr,
	}, nil
}

// todo read 现在未拦截不正确的 addr 来源的包
func (c *UdpClient) Dial(network, addr string) (*UdpConn, error) {
	// 建立 tcp连接，完成握手
	// 然后本地建立端口
	// 返回给客户结构体。

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(host)

	if ip != nil {
		if ipv4 := ip.To4(); len(ipv4) == net.IPv4len {
			ip = ipv4
		}
	}

	conn, err := c.Listen(network)
	if err != nil {
		return nil, err
	}

	conn.hasDst = true
	conn.dstHost = host
	conn.dstIp = ip
	conn.dstPort = portInt

	return conn, nil
}

func (c *UdpClient) Listen(network string) (*UdpConn, error) {
	switch network {
	case "udp", "udp4":
		break
	default:
		return nil, fmt.Errorf("不支持的 network %v 。", network)
	}

	switch c.proxyType {
	case "socks5":
		break
	default:
		return nil, fmt.Errorf("不支持的 proxyType %v。", c.proxyType)
	}

	proxyServerConn, err := net.Dial("tcp", c.proxyAddr)
	if err != nil {
		return nil, err
	}
	cancel := true
	defer func() {
		if cancel == true {
			proxyServerConn.Close()
		}
	}()

	proxyServerTcpConn, _ := proxyServerConn.(*net.TCPConn)
	if proxyServerTcpConn == nil {
		return nil, fmt.Errorf("proxyServerTcpConn  == nil")
	}

	_ = proxyServerTcpConn.SetDeadline(time.Now().Add(10 * time.Second))

	//发送 socks5鉴定 + cmd
	auth := Socks5AuthPack{
		Ver:     Socks5Version,
		Methods: []Socks5AuthMethodType{Socks5AuthMethodTypeNone},
	}

	cmd := Socks5CmdPack{
		Ver:  Socks5Version,
		Cmd:  Socks5CmdTypeUdpAssociate,
		Rsv:  0,
		Atyp: Socks5CmdAtypTypeIP4,
		Host: []byte{0, 0, 0, 0},
		Port: 0,
	}

	err = auth.Write(proxyServerTcpConn)
	if err != nil {
		return nil, err
	}

	err = cmd.Write(proxyServerTcpConn)
	if err != nil {
		return nil, err
	}

	authR := Socks5AuthRPack{}

	err = authR.Read(proxyServerTcpConn)
	if err != nil {
		return nil, err
	}

	if authR.Method != Socks5AuthMethodTypeNone {
		return nil, fmt.Errorf("不支持服务端的鉴定方法 %v 。", authR.Method)
	}

	cmdR := Socks5CmdPack{}

	err = cmdR.Read(proxyServerTcpConn)
	if err != nil {
		return nil, err
	}

	if cmdR.Cmd != Socks5CmdReplySucceeded {
		return nil, fmt.Errorf("服务器回复 cmd:%v", cmdR.Cmd)
	}

	cmdRAddr, err := cmdR.GetAddrString()
	if err != nil {
		return nil, fmt.Errorf("cmdR.GetAddrString, %v", err)
	}

	udpConn, err := net.Dial("udp", cmdRAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		_ = proxyServerTcpConn.SetKeepAlivePeriod(2 * time.Minute)
		_ = proxyServerTcpConn.SetKeepAlive(true)
		_ = proxyServerTcpConn.SetDeadline(time.Time{})

		buf := make([]byte, 1)
		_, err := proxyServerTcpConn.Read(buf)
		if err != nil {
			_ = udpConn.Close()
			_ = proxyServerTcpConn.Close()
			return
		}
	}()

	cancel = false
	return &UdpConn{
		tcpConn: proxyServerTcpConn,
		udpConn: udpConn.(*net.UDPConn),
		hasDst:  false,
	}, nil
}

func (c *UdpConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	buf := mempool.Get(2048)
	defer mempool.Put(buf)

	n, err := c.udpConn.Read(buf)
	if err != nil {
		return 0, nil, err
	}

	pack := Socks5UdpPack{}

	err = pack.Parse(buf[:n])
	if err != nil {
		return 0, nil, err
	}

	// 将域名转换为 ip
	// 如果域名、ip都没有，那么 addr 结果是 nil
	if len(pack.Ip) == 0 && len(pack.Host) != 0 {
		ips, err := net.LookupIP(pack.Host)
		if err == nil && len(ips) > 0 {
			pack.Ip = ips[0]
		}
	}

	udpAddr := net.UDPAddr{
		IP:   pack.Ip,
		Port: int(pack.Port),
	}

	size := len(pack.Data)
	if size > len(b) {
		size = len(b)
	}

	copy(b[:size], pack.Data[:size])

	return size, &udpAddr, nil
}
func (c *UdpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.ReadFromUDP(b)
}

func (c *UdpConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	atyp := Socks5AtypType(Socks5CmdAtypTypeIP6)
	ip := addr.IP
	if ipv4 := addr.IP.To4(); len(ipv4) == net.IPv4len {
		atyp = Socks5CmdAtypTypeIP4
		ip = ipv4
	}

	pack := Socks5UdpPack{
		Rsv:  0,
		FRAG: 0,
		ATYP: atyp,
		Host: "",
		Ip:   ip,
		Port: uint16(addr.Port),
		Data: b,
	}

	buf := mempool.Get(2048)
	defer mempool.Put(buf)

	n, err := pack.To(buf)
	if err != nil {
		return 0, err
	}

	_, err = c.udpConn.Write(buf[:n])
	if err != nil {
		return 0, err
	}
	return n, nil
}
func (c *UdpConn) WriteToDomain(b []byte, host string, port uint16) (int, error) {
	pack := Socks5UdpPack{
		Rsv:  0,
		FRAG: 0,
		ATYP: Socks5CmdAtypTypeDomain, // 这里由于库使用处需要强制性发送 domain 格式，不能使用 auto
		Host: host,
		Port: port,
		Data: b,
	}

	buf := mempool.Get(2048)
	defer mempool.Put(buf)

	n, err := pack.To(buf)
	if err != nil {
		return 0, err
	}

	_, err = c.udpConn.Write(buf[:n])
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (c *UdpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("addr 不是udpAddr。")
	}

	return c.WriteToUDP(b, udpAddr)
}

func (c *UdpConn) Close() error {
	if c == nil {
		return nil
	}

	if tcpConn := c.tcpConn; tcpConn != nil {
		_ = tcpConn.Close()
	}
	if udpConn := c.udpConn; udpConn != nil {
		_ = udpConn.Close()
	}

	return nil
}
