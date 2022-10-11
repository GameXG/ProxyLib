package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/gamexg/proxylib/mempool"
)

// socks5 版本号
const Socks5Version byte = 0x05

// socks5 鉴定方式
// 无需鉴定 和 用户名密码鉴定
type Socks5AuthMethodType byte

const (
	Socks5AuthMethodTypeNone     Socks5AuthMethodType = 0x00
	Socks5AuthMethodTypePassword Socks5AuthMethodType = 0x02
	// 当服务端不支持客户端的鉴定方式时，返回这个类型
	// 客户端需要立刻关闭连接
	Socks5AuthMethodTypeErr Socks5AuthMethodType = 0xFF
)

// socks5 请求类型 ，socks5 cmd 状态回复
// socks5 请求类型有：tcp 传出连接、 tcp 传入连接 或 udp 连接
// socks5 回复状态有： 成功、一般性失败、规则不允许转发、主机不可达、atyp不支持、cmd命令不支持 等
type Socks5CmdType byte

const (
	Socks5CmdTypeConnect      Socks5CmdType = 0x01
	Socks5CmdTypeBind         Socks5CmdType = 0x02
	Socks5CmdTypeUdpAssociate Socks5CmdType = 0x3

	// cmd 回复，成功
	Socks5CmdReplySucceeded Socks5CmdType = 0x00

	// cmd 回复，普通SOCKS服务器连接失败
	Socks5CmdReplyGeneralSocksServerFailure Socks5CmdType = 0x01

	// cmd 回复，规则不允许
	Socks5CmdReplyConnectionNotAllowedByRuleset Socks5CmdType = 0x02

	// cmd 回复，网络不可达
	Socks5CmdReplyNetworkUnreachable Socks5CmdType = 0x03

	// cmd 回复，主机不可达
	Socks5CmdReplyHostUnreachable Socks5CmdType = 0x04

	// cmd 回复，连接被拒绝
	Socks5CmdReplyConnectionRefused Socks5CmdType = 0x05

	// cmd 回复，ttl超时
	Socks5CmdReplyTtlExpired Socks5CmdType = 0x06

	// cmd 回复，不支持的命令
	Socks5CmdReplyCommandNotSupported Socks5CmdType = 0x07

	// cmd 回复，不支持的地址类型
	Socks5CmdReplyAddressTypeNotSupported Socks5CmdType = 0x08

	// 用户自定义范围 0x09- 0xFF

	// 自定义，内部错误
	Socks5CmdReplyInternalError Socks5CmdType = 0x010
)

// socks 5 cmd 命令 Atyp 类型
type Socks5AtypType byte

const (
	//内部使用，根据 cmd.host、cmd.Ip 内容自动确定 atyp 值
	Socks5CmdAtypTypeAuto Socks5AtypType = 0x00

	Socks5CmdAtypTypeIP4    Socks5AtypType = 0x01
	Socks5CmdAtypTypeDomain Socks5AtypType = 0x03
	Socks5CmdAtypTypeIP6    Socks5AtypType = 0x04
)

type Socks5AuthPasswordRStatusType byte

const (
	// 用户名、密码正确
	Socks5AuthPasswordRStatusTypeSucceeded Socks5AuthPasswordRStatusType = 0x00
	// 用户名、密码错误
	Socks5AuthPasswordRStatusTypeErr Socks5AuthPasswordRStatusType = 0x01
)

// 鉴定请求
type Socks5AuthPack struct {
	Ver     byte // 版本5
	Methods []Socks5AuthMethodType
}

// 鉴定回应
type Socks5AuthRPack struct {
	Ver    byte // 版本 5
	Method Socks5AuthMethodType
}

// 命令及回应
type Socks5CmdPack struct {
	Ver  byte // 版本 5
	Cmd  Socks5CmdType
	Rsv  byte
	Atyp Socks5AtypType
	Host []byte
	Port uint16
}

// 用户名、密码
type Socks5AuthPasswordPack struct {
	Ver      byte //目前版本为 1
	Username string
	Password string
}

type Socks5AuthPasswordRPack struct {
	Ver    byte                          //目前版本为 1
	Status Socks5AuthPasswordRStatusType // 0 成功  1失败
}

func (auth *Socks5AuthPack) Read(r io.Reader) error {
	buf := mempool.Get(1024)
	defer mempool.Put(buf)

	b := buf[:2]

	if _, err := io.ReadFull(r, b); err != nil {
		return fmt.Errorf("failed to read socks5 auth head, %v", err)
	}
	auth.Ver = b[0]
	nmethods := b[1]

	if auth.Ver != 5 {
		return fmt.Errorf("ver %v is incorrect", auth.Ver)
	}

	b = buf[:uint8(nmethods)]
	if _, err := io.ReadFull(r, b); err != nil {
		return fmt.Errorf("failed to read socks5 auth methods, %v", err)
	}

	methods := make([]Socks5AuthMethodType, len(b))
	for i := range methods {
		methods[i] = Socks5AuthMethodType(b[i])
	}
	auth.Methods = methods

	return nil
}

func (auth *Socks5AuthPack) HasMethod(m Socks5AuthMethodType) bool {
	for _, v := range auth.Methods {
		if v == m {
			return true
		}
	}
	return false
}

// 读取鉴定
// 注意，所有这种类型的操作都是阻塞的，需要自己设置超时机制
// 内部会检查协议版本等参数。
func ReadAuth(r io.Reader) (*Socks5AuthPack, error) {
	auth := Socks5AuthPack{}

	err := auth.Read(r)
	if err != nil {
		return nil, err
	}

	return &auth, nil
}

func (auth *Socks5AuthPack) Write(w io.Writer) error {
	buf := mempool.Get(1024)
	defer mempool.Put(buf)

	buf = buf[:2]
	buf[0] = 5
	buf[1] = uint8(len(auth.Methods))
	for _, v := range auth.Methods {
		buf = append(buf, byte(v))
	}

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("w.write，%v", err)
	}

	return nil

}

func WriteAuth(w io.Writer, auth *Socks5AuthPack) error {
	if auth == nil {
		return fmt.Errorf("auth is nil")
	}
	return auth.Write(w)
}

func ReadSocks5AuthR(r io.Reader) (*Socks5AuthRPack, error) {
	ar := Socks5AuthRPack{}
	err := ar.Read(r)
	if err != nil {
		return nil, err
	}
	return &ar, err
}

func (ar *Socks5AuthRPack) Read(r io.Reader) error {
	buf := mempool.Get(1024)
	defer mempool.Put(buf)

	buf = buf[:2]
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	ar.Ver = buf[0]
	ar.Method = Socks5AuthMethodType(buf[1])
	if ar.Ver != 5 {
		return fmt.Errorf("ver %v is incorrect", buf[0])
	}

	return nil
}

func WriteSocks5AuthR(w io.Writer, cmd *Socks5AuthRPack) error {
	if cmd == nil {
		return fmt.Errorf("cmd is nil")
	}
	return cmd.Write(w)
}

func (cmd *Socks5AuthRPack) Write(w io.Writer) error {
	if _, err := w.Write([]byte{cmd.Ver, byte(cmd.Method)}); err != nil {
		return fmt.Errorf("w.write, %v", err)
	}
	return nil
}

func WriteSocks5Cmd(w io.Writer, cmd *Socks5CmdPack) error {
	if cmd == nil {
		return fmt.Errorf("cmd is nil")
	}
	return cmd.Write(w)

}
func (cmd *Socks5CmdPack) Write(w io.Writer) error {
	hostSize := len(cmd.Host)
	if cmd.Atyp == Socks5CmdAtypTypeDomain && hostSize > 255 {
		return fmt.Errorf("domain %v is too long", cmd.Host)
	}

	buf := mempool.Get(1024)
	defer mempool.Put(buf)

	port := [2]byte{0}
	binary.BigEndian.PutUint16(port[:], cmd.Port)

	buf[0] = cmd.Ver
	buf[1] = byte(cmd.Cmd)
	buf[2] = cmd.Rsv
	buf[3] = byte(cmd.Atyp)
	buf = buf[:4]

	switch cmd.Atyp {
	case Socks5CmdAtypTypeIP4, Socks5CmdAtypTypeIP6:
		buf = append(buf, cmd.Host...)
	case Socks5CmdAtypTypeDomain:
		buf = append(buf, uint8(len(cmd.Host)))
		buf = append(buf, []byte(cmd.Host)...)
	default:
		return fmt.Errorf("unknown atyp %v type", cmd.Atyp)
	}

	buf = append(buf, port[0], port[1])

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("w.write, %v", err)
	}
	return nil
}

func ReadSocks5Cmd(r io.Reader) (*Socks5CmdPack, error) {
	cmd := Socks5CmdPack{}
	err := cmd.Read(r)
	if err != nil {
		return nil, err
	}
	return &cmd, nil
}

// 请确定 cmd.Host 指向的内容未被其他位置使用，本函数会复用 cmd.Host 空间
func (cmd *Socks5CmdPack) Read(r io.Reader) error {

	buf := mempool.Get(1024)
	defer mempool.Put(buf)

	buf = buf[:4]

	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("failed to read socks 5 command head, %v", err)
	}

	cmd.Ver = buf[0]
	cmd.Cmd = Socks5CmdType(buf[1])
	cmd.Rsv = buf[2]
	cmd.Atyp = Socks5AtypType(buf[3])

	if cmd.Ver != 5 {
		return fmt.Errorf("unexpected protocol version %v ", cmd.Ver)
	}
	/* 这个不应该由这里判断。
	 		if cmd.Cmd != 0x01 && cmd.Cmd != 0x02 && cmd.Cmd != 0x03 {
				return nil, fmt.Errorf("未知的命令，cmd:%v。", cmd.Cmd)
			}*/

	/*if cmd.atyp == Socks5CmdAtypTypeIP4 {
	    buf = buf[:net.IPv4len]
	}else */

	switch cmd.Atyp {
	case Socks5CmdAtypTypeIP4:
		buf = buf[:net.IPv4len]
	case Socks5CmdAtypTypeIP6:
		buf = buf[:net.IPv6len]
	case Socks5CmdAtypTypeDomain:
		buf = buf[:1]
	default:
		return fmt.Errorf("unexpected address type %v", cmd.Atyp)
	}

	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("failed to read socks5 cmd.Host, %v", err)
	}

	switch cmd.Atyp {
	case Socks5CmdAtypTypeIP4, Socks5CmdAtypTypeIP6:
		cmd.Host = append(cmd.Host[:0], buf...)
	case Socks5CmdAtypTypeDomain:
		buf = buf[:buf[0]]
		if _, err := io.ReadFull(r, buf); err != nil {
			return fmt.Errorf("failed to read socks5 cmd.Host, %v", err)
		}
		cmd.Host = append(cmd.Host, buf...)
	}

	buf = buf[:2]
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("failed to read socks5 cmd.Port, %v", err)
	}
	cmd.Port = binary.BigEndian.Uint16(buf)

	return nil
}

func (s *Socks5CmdPack) GetHostString() (string, error) {
	switch s.Atyp {
	case Socks5CmdAtypTypeIP4:
		ip := net.IP(s.Host)
		ip = ip.To4()

		if len(ip) != net.IPv4len {
			return "", fmt.Errorf("%v is not ipv4 address", s.Host)
		}

		return ip.String(), nil

	case Socks5CmdAtypTypeIP6:
		ip := net.IP(s.Host)
		ip = ip.To16()

		if len(ip) != net.IPv6len {
			return "", fmt.Errorf("%v is not ipv6 address", s.Host)
		}

		return ip.String(), nil

	case Socks5CmdAtypTypeDomain:
		return string(s.Host), nil

	default:
		return "", fmt.Errorf("unexpected atyp %v", s.Atyp)
	}
}

func (s *Socks5CmdPack) GetAddrString() (string, error) {
	host, err := s.GetHostString()
	if err != nil {
		return "", err
	}

	return net.JoinHostPort(host, strconv.Itoa(int(s.Port))), nil
}

func (s *Socks5CmdPack) SetAddrAuto(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	if port < 0 || port > 0xFFFF {
		return fmt.Errorf("port %v < 0 || port %v > 0xFFFF", port, port)
	}

	s.SetHostAuto(host)
	s.Port = uint16(port)

	return nil
}

func (s *Socks5CmdPack) GetHostIp() (net.IP, error) {
	var ip net.IP

	switch s.Atyp {
	case Socks5CmdAtypTypeIP4, Socks5CmdAtypTypeIP6:
		ip = net.IP(s.Host)
		return ip, nil
	case Socks5CmdAtypTypeDomain:
		ip = net.ParseIP(string(s.Host))

		if len(ip) == 0 {
			return nil, fmt.Errorf("%v is not ip address", s.Host)
		}

		ipv4 := ip.To4()
		if len(ipv4) == net.IPv4len {
			return ipv4, nil
		}

		ipv6 := ip.To16()
		if len(ipv6) == net.IPv6len {
			return ipv6, nil
		}

		return nil, fmt.Errorf("%v is not ipv4 or ipv6 address", s.Host)

	default:
		return nil, fmt.Errorf("unexpected atyp %v", s.Atyp)
	}
}

func (s *Socks5CmdPack) SetHostAuto(v string) {
	ip := net.ParseIP(v)

	if len(ip) != 0 {
		ipv4 := ip.To4()
		if len(ipv4) == net.IPv4len {
			s.Atyp = Socks5CmdAtypTypeIP4
			s.Host = []byte(ipv4)
			return
		}

		ipv6 := ip.To16()
		if len(ipv6) == net.IPv6len {
			s.Atyp = Socks5CmdAtypTypeIP6
			s.Host = []byte(ipv6)
			return
		}
	}

	s.Atyp = Socks5CmdAtypTypeDomain
	s.Host = []byte(v)
	return
}

func (s *Socks5CmdPack) SetHostDomain(domain string) {
	s.Atyp = Socks5CmdAtypTypeDomain
	s.Host = []byte(domain)
}

func (s *Socks5CmdPack) SetHostIp(ip net.IP) error {
	ipv4 := ip.To4()

	if len(ipv4) == net.IPv4len {
		s.Atyp = Socks5CmdAtypTypeIP4
		s.Host = []byte(ipv4)
		return nil
	}

	ipv6 := ip.To16()
	if len(ipv6) == net.IPv6len {
		s.Atyp = Socks5CmdAtypTypeIP6
		s.Host = []byte(ipv6)
		return nil
	}

	return fmt.Errorf("%v is not ipv4 or ipv6 address", ip)
}

func ReadSocks5AuthPassword(r io.Reader) (*Socks5AuthPasswordPack, error) {
	p := Socks5AuthPasswordPack{}
	err := p.Read(r)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Socks5AuthPasswordPack) Read(r io.Reader) error {

	buf := mempool.Get(1024)
	defer mempool.Put(buf)

	buf = buf[:2]
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("failed to read socks 5 auth head, %v", err)
	}

	p.Ver = buf[0]
	l := buf[1]
	if p.Ver != 1 {
		return fmt.Errorf("unexpected protocol version %v", p.Ver)
	}

	buf = buf[:l+1]
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("failed to read socks 5 auth.Username, %v", err)
	}
	p.Username = string(buf[:len(buf)-1])

	buf = buf[:buf[len(buf)-1]]
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("failed to read socks 5 auth.Password, %v", err)
	}
	p.Password = string(buf)

	return nil
}

func WriteSocks5AuthPassword(w io.Writer, pass *Socks5AuthPasswordPack) error {
	if pass == nil {
		return fmt.Errorf("pass is nil")
	}

	return pass.Write(w)
}

func (pass *Socks5AuthPasswordPack) Write(w io.Writer) error {

	if len(pass.Username) > 0xFF || len(pass.Username) > 0xFF {
		return fmt.Errorf("username or password is too long")
	}

	buf := mempool.Get(1024)
	defer mempool.Put(buf)

	buf = buf[:2]
	buf[0] = pass.Ver
	buf[1] = uint8(len(pass.Username))
	buf = append(buf, []byte(pass.Username)...)
	buf = append(buf, uint8(len(pass.Password)))
	buf = append(buf, pass.Password...)

	if _, err := w.Write(buf); err != nil {
		return err
	}

	return nil
}

func ReadSocks5AuthPasswordR(r io.Reader) (*Socks5AuthPasswordRPack, error) {
	pr := Socks5AuthPasswordRPack{}
	err := pr.Read(r)
	if err != nil {
		return nil, err
	}
	return &pr, nil
}
func (pr *Socks5AuthPasswordRPack) Read(r io.Reader) error {
	buf := mempool.Get(1024)
	defer mempool.Put(buf)

	buf = buf[:2]
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	pr.Ver = buf[0]
	pr.Status = Socks5AuthPasswordRStatusType(buf[1])
	if pr.Ver != 1 {
		return fmt.Errorf("unexpected protocol version %v", pr.Ver)
	}

	return nil
}

func WriteSocks5AuthPasswordR(w io.Writer, r *Socks5AuthPasswordRPack) error {
	if r == nil {
		return fmt.Errorf("r is nil")
	}

	return r.Write(w)
}
func (r *Socks5AuthPasswordRPack) Write(w io.Writer) error {
	buf := mempool.Get(1024)
	defer mempool.Put(buf)

	buf = buf[:2]
	buf[0] = r.Ver
	buf[1] = byte(r.Status)

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("w.write, %v", err)
	}
	return nil
}

type Socks5UdpPack struct {
	Rsv  uint16
	FRAG byte
	ATYP Socks5AtypType
	Host string
	Ip   net.IP
	Port uint16
	Data []byte
}

func (p *Socks5UdpPack) Parse(data []byte) error {
	if len(data) < 11 {
		return fmt.Errorf("data length is too short")
	}

	rsv := binary.BigEndian.Uint16(data)
	frag := data[2]
	atyp := Socks5AtypType(data[3])
	ip := p.Ip[:0]
	host := ""
	portData := data

	switch Socks5AtypType(atyp) {
	case Socks5CmdAtypTypeIP4:
		ip = append(ip, data[4:4+net.IPv4len]...)
		portData = data[4+net.IPv4len:]

	case Socks5CmdAtypTypeIP6:
		if len(data) < 23 {
			return fmt.Errorf("data length is too short")
		}
		ip = append(ip, data[4:4+net.IPv6len]...)
		portData = data[4+net.IPv6len:]

	case Socks5CmdAtypTypeDomain:
		l := int(data[4])
		if len(data) < 7+l {
			return fmt.Errorf("data length is too short")
		}

		host = string(data[5 : 5+l])
		portData = data[5+l:]
	default:
		return fmt.Errorf("unexpected atyp %v", atyp)
	}

	*p = Socks5UdpPack{}

	port := binary.BigEndian.Uint16(portData[:2])
	udpData := portData[2:]

	p.Rsv = rsv
	p.FRAG = frag
	p.ATYP = atyp
	p.Host = host
	p.Ip = append(p.Ip[:0], ip...)
	p.Port = port
	p.Data = append(p.Data[:0], udpData...)

	return nil
}

func (p *Socks5UdpPack) To(data []byte) (int, error) {
	atyp := Socks5AtypType(p.ATYP)
	ip := p.Ip
	host := []byte(p.Host)
	hostSize := 0
	port := p.Port

	if atyp == Socks5CmdAtypTypeAuto {
		if len(ip) == 0 {
			ip = net.ParseIP(p.Host)
		}

		if len(ip) == 0 {
			atyp = Socks5CmdAtypTypeDomain
		} else {
			if ipv4 := ip.To4(); len(ipv4) == net.IPv4len {
				ip = ipv4
			}

			switch len(ip) {
			case net.IPv4len:
				atyp = Socks5CmdAtypTypeIP4
				ip = ip
			case net.IPv6len:
				atyp = Socks5CmdAtypTypeIP6
			default:
				return 0, fmt.Errorf("ip %v length is incorrect", ip)
			}
		}
	}

	switch atyp {
	case Socks5CmdAtypTypeIP4:
		ip = ip.To4()
		if len(ip) != net.IPv4len {
			return 0, fmt.Errorf("ipv4 %v length is incorrect", ip)
		}
		hostSize = net.IPv4len
	case Socks5CmdAtypTypeIP6:
		if len(ip) != net.IPv6len {
			return 0, fmt.Errorf("ipv6 %v length is incorrect", ip)
		}
		hostSize = net.IPv6len
	case Socks5CmdAtypTypeDomain:
		if len(host) > 0xFF {
			return 0, fmt.Errorf("host %v is too long", host)
		}
		hostSize = len(host) + 1
	default:
		return 0, fmt.Errorf("unexpected atyp %v", atyp)
	}

	mustSize := 6 + hostSize + len(p.Data)
	if len(data) < mustSize {
		return mustSize, fmt.Errorf("not enough space")
	}

	binary.BigEndian.PutUint16(data, p.Rsv)
	data[2] = p.FRAG
	data[3] = byte(atyp)

	switch atyp {
	case Socks5CmdAtypTypeIP4, Socks5CmdAtypTypeIP6:
		copy(data[4:4+hostSize], ip)
	case Socks5CmdAtypTypeDomain:
		data[4] = byte(len(host))
		copy(data[4+1:4+hostSize], host)
	}

	binary.BigEndian.PutUint16(data[4+hostSize:], port)

	copy(data[4+hostSize+2:], p.Data)

	return mustSize, nil
}

func (p *Socks5UdpPack) SetAddr(addr net.Addr) error {
	udpAddr, _ := addr.(*net.UDPAddr)
	if udpAddr == nil {
		return fmt.Errorf("非预期的 udpAddr 格式, %v", addr)
	}

	err := p.SetAddrWIp(udpAddr.IP)
	if err != nil {
		return fmt.Errorf("SetAddrWIp,%v", err)
	}

	p.SetAddrWPort(udpAddr.Port)

	return nil
}

func (p *Socks5UdpPack) SetAddrWIp(ip net.IP) error {
	ipv4 := ip.To4()
	if len(ipv4) == net.IPv4len {
		p.Ip = ipv4
		p.ATYP = Socks5CmdAtypTypeIP4
		return nil
	}

	ipv6 := ip.To16()
	if len(ipv6) != net.IPv6len {
		p.Ip = ipv6
		p.ATYP = Socks5CmdAtypTypeIP6
		return nil
	}

	return fmt.Errorf("非预期的 ip 版本,%v", ip)
}

func (p *Socks5UdpPack) SetAddrWPort(port int) {
	p.Port = uint16(port)
}

func (p *Socks5UdpPack) GetUdpAddr() (*net.UDPAddr, error) {

	switch p.ATYP {
	case Socks5CmdAtypTypeIP4, Socks5CmdAtypTypeIP6:
		return &net.UDPAddr{
			IP:   p.Ip,
			Port: int(p.Port),
			Zone: "",
		}, nil

	default:
		return nil, fmt.Errorf("非预期的地址类型")
	}

}
