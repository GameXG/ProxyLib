package socks5

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestReadAuth(t *testing.T) {
	r := bytes.NewReader([]byte{0x05, 0x01, 0x00, 0x02})
	if a, err := ReadAuth(r); err != nil {
		t.Error()
	} else {
		if a.Ver != Socks5Version || reflect.DeepEqual(a.Methods, []Socks5AuthMethodType{Socks5AuthMethodTypeNone}) != true {
			t.Error()
		}
	}
	r = bytes.NewReader([]byte{0x05, 0x01, 0x02, 0x00})
	if a, err := ReadAuth(r); err != nil {
		t.Error()
	} else {
		if a.Ver != Socks5Version || reflect.DeepEqual(a.Methods, []Socks5AuthMethodType{Socks5AuthMethodTypePassword}) != true {
			t.Error()
		}
	}
	r = bytes.NewReader([]byte{0x05, 0x02, 0x00, 0x02, 0x03, 0x04})
	if a, err := ReadAuth(r); err != nil {
		t.Error()
	} else {
		if a.Ver != Socks5Version || reflect.DeepEqual(a.Methods, []Socks5AuthMethodType{Socks5AuthMethodTypeNone, Socks5AuthMethodTypePassword}) != true {
			t.Error()
		}
	}
}
func TestWriteSocks5AuthR(t *testing.T) {
	buf := new(bytes.Buffer)

	a := Socks5AuthRPack{Socks5Version, 0x02}

	if err := WriteSocks5AuthR(buf, &a); err != nil {
		t.Error(err)
	} else if bytes.Compare(buf.Bytes(), []byte{0x05, byte(Socks5AuthMethodTypePassword)}) != 0 {
		t.Error()
	}
}
func TestWriteSocks5Cmd(t *testing.T) {
	buf := new(bytes.Buffer)

	cmd := Socks5CmdPack{}
	cmd.Ver = Socks5Version
	cmd.Cmd = Socks5CmdTypeConnect
	cmd.Rsv = 0
	cmd.Atyp = Socks5CmdAtypTypeIP4
	cmd.Host = net.IPv4(123, 221, 147, 253).To4()
	cmd.Port = 1234

	if err := WriteSocks5Cmd(buf, &cmd); err != nil {
		t.Error("WriteSocks5Cmd:", err)
	} else if bytes.Compare(buf.Bytes(), []byte{0x05, 0x01, 0x00, 0x01, 123, 221, 147, 253, 0x4, 0xd2}) != 0 {
		t.Error()
	}

	buf.Reset()
	cmd.Atyp = Socks5CmdAtypTypeIP6
	cmd.Host = net.ParseIP("2001:DB8:2de:0:0:0:0:e13")
	if err := WriteSocks5Cmd(buf, &cmd); err != nil {
		t.Error("WriteSocks5Cmd:", err)
	} else if b := buf.Bytes(); bytes.Compare(b, []byte{0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0x02, 0xde, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e, 0x13, 0x4, 0xd2}) != 0 {
		t.Error(b)
	}

	buf.Reset()
	cmd.Atyp = Socks5CmdAtypTypeDomain
	cmd.Host = []byte("www.123.com")
	if err := WriteSocks5Cmd(buf, &cmd); err != nil {
		t.Error("WriteSocks5Cmd:", err)
	} else {
		if b := buf.Bytes(); bytes.Compare(b, []byte{0x05, 0x01, 0x00, 3, 11, 119, 119, 119, 46, 49, 50, 51, 46, 99, 111, 109, 0x4, 0xd2}) != 0 {
			t.Error(b)
		}
	}
}

func TestReadSocks5Cmd(t *testing.T) {
	r := bytes.NewReader([]byte{0x05, 0x01, 0x00, 0x01, 123, 221, 147, 253, 0x4, 0xd2, 123, 123, 123, 123, 123})
	if cmd, err := ReadSocks5Cmd(r); err != nil {
		t.Error(err)
	} else {
		if cmd.Ver != Socks5Version || cmd.Cmd != Socks5CmdTypeConnect || cmd.Rsv != 0 || cmd.Atyp != Socks5CmdAtypTypeIP4 || net.IP(cmd.Host).String() != "123.221.147.253" || cmd.Port != 1234 {
			t.Error(cmd)
		}
	}

	r = bytes.NewReader([]byte{0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0x02, 0xde, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e, 0x13, 0x4, 0xd2, 123, 123, 123, 123, 123})
	if cmd, err := ReadSocks5Cmd(r); err != nil {
		t.Error(err)
	} else {
		if cmd.Ver != Socks5Version || cmd.Cmd != Socks5CmdTypeConnect || cmd.Rsv != 0 || cmd.Atyp != Socks5CmdAtypTypeIP6 || net.IP(cmd.Host).String() != "2001:db8:2de::e13" || cmd.Port != 1234 {
			t.Error(cmd)
		}
	}

	r = bytes.NewReader([]byte{0x05, 0x01, 0x00, 3, 11, 119, 119, 119, 46, 49, 50, 51, 46, 99, 111, 109, 0x4, 0xd2, 123, 123, 123, 123, 123})
	if cmd, err := ReadSocks5Cmd(r); err != nil {
		t.Error(err)
	} else {
		if cmd.Ver != Socks5Version || cmd.Cmd != Socks5CmdTypeConnect || cmd.Rsv != 0 || cmd.Atyp != Socks5CmdAtypTypeDomain || string(cmd.Host) != "www.123.com" || cmd.Port != 1234 {
			t.Error(cmd)
		}
	}

}

func TestReadSocks5AuthPassword(t *testing.T) {
	r := bytes.NewReader([]byte{0x01, 0x03, 119, 119, 119, 0x02, 99, 109})
	if p, err := ReadSocks5AuthPassword(r); err != nil {
		t.Error(err)
	} else {
		if p.Ver != 0x01 || p.Username != "www" || p.Password != "cm" {
			t.Error(p)
		}
	}
}

func TestWriteAuth(t *testing.T) {
	w := new(bytes.Buffer)

	if err := WriteAuth(w, &Socks5AuthPack{
		Ver:     Socks5Version,
		Methods: []Socks5AuthMethodType{Socks5AuthMethodTypeNone, Socks5AuthMethodTypePassword},
	}); err != nil {
		t.Errorf(err.Error())
	}
	if bytes.Compare(w.Bytes(), []byte{0x05, 2, 0, 2}) != 0 {
		t.Errorf("错误")
	}

	w.Reset()
	if err := WriteAuth(w, &Socks5AuthPack{
		Ver:     Socks5Version,
		Methods: []Socks5AuthMethodType{Socks5AuthMethodTypeNone},
	}); err != nil {
		t.Errorf(err.Error())
	}
	if bytes.Compare(w.Bytes(), []byte{0x05, 1, 0}) != 0 {
		t.Errorf("错误")
	}
}

func TestReadSocks5AuthR(t *testing.T) {
	r := bytes.NewReader([]byte{5, 0})
	if ar, err := ReadSocks5AuthR(r); err != nil {
		t.Errorf(err.Error())
	} else {
		if ar.Ver != 5 || ar.Method != 0 {
			t.Errorf("错误")
		}
	}

	r = bytes.NewReader([]byte{5, 2})
	if ar, err := ReadSocks5AuthR(r); err != nil {
		t.Errorf(err.Error())
	} else {
		if ar.Ver != 5 || ar.Method != 2 {
			t.Errorf("错误")
		}
	}
}

func TestWriteSocks5AuthPassword(t *testing.T) {
	w := new(bytes.Buffer)

	if err := WriteSocks5AuthPassword(w, &Socks5AuthPasswordPack{
		Ver:      1,
		Username: "abc",
		Password: "123456",
	}); err != nil {
		t.Errorf(err.Error())
	} else if bytes.Compare(w.Bytes(), []byte{1, 3, 97, 98, 99, 6, 49, 50, 51, 52, 53, 54}) != 0 {
		t.Errorf("错误")
	}
}

func TestReadSocks5AuthPasswordR(t *testing.T) {
	r := bytes.NewReader([]byte{1, 1})
	if pr, err := ReadSocks5AuthPasswordR(r); err != nil {
		t.Errorf(err.Error())
	} else if pr.Ver != 1 || pr.Status != 1 {
		t.Error("错误")
	}

	r = bytes.NewReader([]byte{1, 0})
	if pr, err := ReadSocks5AuthPasswordR(r); err != nil {
		t.Errorf(err.Error())
	} else if pr.Ver != 1 || pr.Status != 0 {
		t.Error("错误")
	}
}

func TestWriteSocks5AuthPasswordR(t *testing.T) {
	w := new(bytes.Buffer)

	if err := WriteSocks5AuthPasswordR(w, &Socks5AuthPasswordRPack{1, 0}); err != nil {
		t.Error(err.Error())
	} else if bytes.Compare(w.Bytes(), []byte{1, 0}) != 0 {
		t.Error("错误")
	}

	w.Reset()
	if err := WriteSocks5AuthPasswordR(w, &Socks5AuthPasswordRPack{1, 1}); err != nil {
		t.Error(err.Error())
	} else if bytes.Compare(w.Bytes(), []byte{1, 1}) != 0 {
		t.Error("错误")
	}
}

func TestSocks5UdpPack_Ipv4(t *testing.T) {
	data := []byte{
		1, 2, //RSV
		3, // FRAG 碎片
		1, //ipv4
		192,
		168,
		1,
		100,
		0x34,
		0x56,
		9, 8, 7, 4, 3, 2, 1, //data
	}

	udpPack := Socks5UdpPack{}

	err := udpPack.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	if udpPack.Rsv != 0x0102 || //200
		udpPack.FRAG != 3 ||
		udpPack.ATYP != Socks5CmdAtypTypeIP4 ||
		bytes.Equal(udpPack.Ip, []byte{192, 168, 1, 100}) != true ||
		udpPack.Port != 0x3456 || //5634
		bytes.Equal(udpPack.Data, []byte{9, 8, 7, 4, 3, 2, 1}) != true {
		t.Fatal("err")
	}

	buf := make([]byte, 1024)

	n, err := udpPack.To(buf)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(buf[:n], data) == false {
		t.Fatal("!=")
	}
}
func TestSocks5UdpPack_Ipv6(t *testing.T) {
	data := []byte{
		1, 2, //RSV
		3, // FRAG 碎片
		4, //ipv6
		1,
		2,
		3,
		4,
		5,
		6,
		7,
		8,
		9,
		10,
		11,
		12,
		13,
		14,
		15,
		16,
		0x34,
		0x56,
		9, 8, 7, 4, 3, 2, 1, //data
	}

	udpPack := Socks5UdpPack{}

	err := udpPack.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	if udpPack.Rsv != 0x0102 || //200
		udpPack.FRAG != 3 ||
		udpPack.ATYP != Socks5CmdAtypTypeIP6 ||
		bytes.Equal(udpPack.Ip, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}) != true ||
		udpPack.Port != 0x3456 || //5634
		bytes.Equal(udpPack.Data, []byte{9, 8, 7, 4, 3, 2, 1}) != true {
		t.Fatal("err")
	}

	buf := make([]byte, 1024)

	n, err := udpPack.To(buf)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(buf[:n], data) == false {
		t.Fatal("!=")
	}
}
func TestSocks5UdpPack_Domain(t *testing.T) {
	data := []byte{
		1, 2, //RSV
		3, // FRAG 碎片
		3, //domain
		11,
		0x77, 0x77, 0x77, 0x2e, 0x61, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x6d, //www.abc.com
		0x34,
		0x56,
		9, 8, 7, 4, 3, 2, 1, //data
	}

	udpPack := Socks5UdpPack{}

	err := udpPack.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	if udpPack.Rsv != 0x0102 || //200
		udpPack.FRAG != 3 ||
		udpPack.ATYP != Socks5CmdAtypTypeDomain ||
		udpPack.Host != "www.abc.com" ||
		bytes.Equal(udpPack.Ip, []byte{}) != true ||
		udpPack.Port != 0x3456 || //5634
		bytes.Equal(udpPack.Data, []byte{9, 8, 7, 4, 3, 2, 1}) != true {
		t.Fatal("err")
	}

	buf := make([]byte, 1024)

	n, err := udpPack.To(buf)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(buf[:n], data) == false {
		t.Fatal("!=")
	}
}

// 测试自动 + ip 字段为 ipv4
func TestSocks5UdpPack_AutoIpv4(t *testing.T) {
	data := []byte{
		1, 2, //RSV
		3, // FRAG 碎片
		1, //ipv4
		192,
		168,
		1,
		100,
		0x34,
		0x56,
		9, 8, 7, 4, 3, 2, 1, //data
	}

	udpPack := Socks5UdpPack{}

	err := udpPack.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	if udpPack.Rsv != 0x0102 || //200
		udpPack.FRAG != 3 ||
		udpPack.ATYP != Socks5CmdAtypTypeIP4 ||
		bytes.Equal(udpPack.Ip, []byte{192, 168, 1, 100}) != true ||
		udpPack.Port != 0x3456 || //5634
		bytes.Equal(udpPack.Data, []byte{9, 8, 7, 4, 3, 2, 1}) != true {
		t.Fatal("err")
	}

	buf := make([]byte, 1024)

	udpPack.ATYP = Socks5CmdAtypTypeAuto
	n, err := udpPack.To(buf)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(buf[:n], data) == false {
		t.Fatal("!=")
	}
}

// 测试自动 + ip 字段为 ipv4（ipv6长度）
func TestSocks5UdpPack_AutoIpv42(t *testing.T) {
	data := []byte{
		1, 2, //RSV
		3, // FRAG 碎片
		1, //ipv4
		192,
		168,
		1,
		100,
		0x34,
		0x56,
		9, 8, 7, 4, 3, 2, 1, //data
	}

	udpPack := Socks5UdpPack{}

	err := udpPack.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	if udpPack.Rsv != 0x0102 || //200
		udpPack.FRAG != 3 ||
		udpPack.ATYP != Socks5CmdAtypTypeIP4 ||
		bytes.Equal(udpPack.Ip, []byte{192, 168, 1, 100}) != true ||
		udpPack.Port != 0x3456 || //5634
		bytes.Equal(udpPack.Data, []byte{9, 8, 7, 4, 3, 2, 1}) != true {
		t.Fatal("err")
	}

	buf := make([]byte, 1024)

	udpPack.ATYP = Socks5CmdAtypTypeAuto
	udpPack.Ip = udpPack.Ip.To16()

	n, err := udpPack.To(buf)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(buf[:n], data) == false {
		t.Fatal("!=")
	}
}

// 测试自动 + domain 字段为 ipv4
func TestSocks5UdpPack_AutoIpv43(t *testing.T) {
	data := []byte{
		1, 2, //RSV
		3, // FRAG 碎片
		1, //ipv4
		192,
		168,
		1,
		100,
		0x34,
		0x56,
		9, 8, 7, 4, 3, 2, 1, //data
	}

	udpPack := Socks5UdpPack{}

	err := udpPack.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	if udpPack.Rsv != 0x0102 || //200
		udpPack.FRAG != 3 ||
		udpPack.ATYP != Socks5CmdAtypTypeIP4 ||
		bytes.Equal(udpPack.Ip, []byte{192, 168, 1, 100}) != true ||
		udpPack.Port != 0x3456 || //5634
		bytes.Equal(udpPack.Data, []byte{9, 8, 7, 4, 3, 2, 1}) != true {
		t.Fatal("err")
	}

	buf := make([]byte, 1024)

	udpPack.ATYP = Socks5CmdAtypTypeAuto
	udpPack.Host = "192.168.1.100"
	udpPack.Ip = nil
	n, err := udpPack.To(buf)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(buf[:n], data) == false {
		t.Fatal("!=")
	}
}

func TestSocks5UdpPack_AutoIpv6(t *testing.T) {
	data := []byte{
		1, 2, //RSV
		3, // FRAG 碎片
		4, //ipv6
		1,
		2,
		3,
		4,
		5,
		6,
		7,
		8,
		9,
		10,
		11,
		12,
		13,
		14,
		15,
		16,
		0x34,
		0x56,
		9, 8, 7, 4, 3, 2, 1, //data
	}

	udpPack := Socks5UdpPack{}

	err := udpPack.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	if udpPack.Rsv != 0x0102 || //200
		udpPack.FRAG != 3 ||
		udpPack.ATYP != Socks5CmdAtypTypeIP6 ||
		bytes.Equal(udpPack.Ip, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}) != true ||
		udpPack.Port != 0x3456 || //5634
		bytes.Equal(udpPack.Data, []byte{9, 8, 7, 4, 3, 2, 1}) != true {
		t.Fatal("err")
	}

	buf := make([]byte, 1024)

	udpPack.ATYP = Socks5CmdAtypTypeAuto

	n, err := udpPack.To(buf)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(buf[:n], data) == false {
		t.Fatal("!=")
	}
}

func TestSocks5UdpPack_AutoIpv6_2(t *testing.T) {
	data := []byte{
		1, 2, //RSV
		3, // FRAG 碎片
		4, //ipv6
		1,
		2,
		3,
		4,
		5,
		6,
		7,
		8,
		9,
		10,
		11,
		12,
		13,
		14,
		15,
		16,
		0x34,
		0x56,
		9, 8, 7, 4, 3, 2, 1, //data
	}

	udpPack := Socks5UdpPack{}

	err := udpPack.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	if udpPack.Rsv != 0x0102 || //200
		udpPack.FRAG != 3 ||
		udpPack.ATYP != Socks5CmdAtypTypeIP6 ||
		bytes.Equal(udpPack.Ip, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}) != true ||
		udpPack.Port != 0x3456 || //5634
		bytes.Equal(udpPack.Data, []byte{9, 8, 7, 4, 3, 2, 1}) != true {
		t.Fatal("err")
	}

	buf := make([]byte, 1024)

	udpPack.ATYP = Socks5CmdAtypTypeAuto
	udpPack.Host = udpPack.Ip.String()
	udpPack.Ip = nil

	n, err := udpPack.To(buf)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(buf[:n], data) == false {
		t.Fatal("!=")
	}
}
func TestSocks5UdpPack_AutoDomain(t *testing.T) {
	data := []byte{
		1, 2, //RSV
		3, // FRAG 碎片
		3, //domain
		11,
		0x77, 0x77, 0x77, 0x2e, 0x61, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x6d, //www.abc.com
		0x34,
		0x56,
		9, 8, 7, 4, 3, 2, 1, //data
	}

	udpPack := Socks5UdpPack{}

	err := udpPack.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	if udpPack.Rsv != 0x0102 || //200
		udpPack.FRAG != 3 ||
		udpPack.ATYP != Socks5CmdAtypTypeDomain ||
		udpPack.Host != "www.abc.com" ||
		bytes.Equal(udpPack.Ip, []byte{}) != true ||
		udpPack.Port != 0x3456 || //5634
		bytes.Equal(udpPack.Data, []byte{9, 8, 7, 4, 3, 2, 1}) != true {
		t.Fatal("err")
	}

	buf := make([]byte, 1024)

	udpPack.ATYP = Socks5CmdAtypTypeAuto

	n, err := udpPack.To(buf)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(buf[:n], data) == false {
		t.Fatal("!=")
	}
}
