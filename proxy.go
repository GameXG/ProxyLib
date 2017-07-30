package ProxyLib

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

/*
// ProxyUDPConn 用来表示通过代理访问的TCP连接
type ProxyUDPConn interface {
	UDPConn
	ProxyClient() ProxyClient // 获得所属的代理
}*/

// ProxyClient 仿 net 库接口的代理客户端
// 支持级联代理功能，可以通过 SetUpProxy 设置上级代理。
// 这个是对库使用者公开的接口
type ProxyClient interface {

	// 如果代理服务器支持远端DNS解析，那么会使用远端DNS解析。
	Dial(network, address string) (net.Conn, error)

	DialContext(ctx context.Context, network, address string) (Conn, error)

	// 使用现存连接
	// 不保证所有协议支持，需要考虑怎么告知库使用者
	//Client(conn net.Conn, network, address string) (net.Conn, error)
	// 使用现存连接
	// 不保证所有协议支持，需要考虑怎么告知库使用者
	//ClientContext(conn net.Conn, ctx context.Context, network, address string) (net.Conn, error)

	// 获得 Proxy 代理地址的 Query
	// 为了大小写兼容，key全部是转换成小写的。
	GetProxyAddrQuery() map[string][]string

	// 返回本代理的上层级联代理
	UpProxy() ProxyClient
	// 设置本代理的上层代理
	SetUpProxy(upProxy ProxyClient) error
}

//服务接口
type Handler interface {
	String() string
	// Handler 是实际处理请求的函数
	// 注意：如果返回那么连接就会被关闭。
	// 注意：默认设置了10分钟后连接超时，如需修改请自行处理。
	Handle() error
}

// 服务接口
// Newer 是创建处理器接口
// 如果处理器识别到当前连接可以处理，那么就会返回创建的处理器，否则返回 nil
type HandlerNewer interface {
	// New 创建处理器
	// 有可能由于协议不正确会创建失败，这时 h==nil , error 可以返回详细信息
	// 在创建处理器失败时调用方负责回退已经从 stream 读取的数据
	// 在创建处理器成功时根据reset的值确定是否复位预读。true 复位预读的数据，flase不复位预读的数据。
	// 注意：函数内部不允许调用会引起副作用的方法，例如 close、 write 等函数 。
	New(conn net.Conn) (h Handler, rePre bool, err error)
}

// NewProxyClient 用来创建代理客户端
//
// 参数格式：允许使用 ?参数名1=参数值1&参数名2=参数值2指定参数
// 例如：https://123.123.123.123:8088?insecureskipverify=true
//     全体协议可选参数： upProxy=http://145.2.1.3:8080 用于指定代理的上层代理，即代理嵌套。默认值：direct://0.0.0.0:0000
//
// http 代理 http://123.123.123.123:8088
//     可选功能： 用户认证功能。格式：http://user:password@123.123.123:8080
//     可选参数：standardheader=false true表示 CONNNET 请求包含标准的 Accept、Accept-Encoding、Accept-Language、User-Agent等头。默认值：false
//
// https 代理 https://123.123.123.123:8088
//     可选功能： 用户认证功能，同 http 代理。
//     可选参数：standardheader=false 同上 http 代理
//     可选参数：insecureskipverify=false true表示跳过 https 证书验证。默认false。
//     可选参数：domain=域名 指定https验证证书时使用的域名，默认为 host:port
//
// socks4 代理 socks4://123.123.123.123:5050
//     注意：socks4 协议不支持远端 dns 解析
//
// socks4a 代理 socks4a://123.123.123.123:5050
//
// socks5 代理 socks5://123.123.123.123:5050
//     可选功能：用户认证功能。支持无认证、用户名密码认证，格式同 http 代理。
//
// ss 代理 ss://method:passowd@123.123.123:5050
//
// 直连 direct://0.0.0.0:0000
//     可选参数： LocalAddr=0.0.0.0:0 表示tcp连接绑定的本地ip及端口，默认值 0.0.0.0:0。
//     可选参数： SplitHttp=false true 表示拆分 http 请求(分多个tcp包发送)，可以解决简单的运营商 http 劫持。默认值：false 。
//              原理是：当发现目标地址为 80 端口，发送的内容包含 GET、POST、HTTP、HOST 等关键字时，会将关键字拆分到两个包在发送出去。
//              注意： Web 防火墙类软件、设备可能会重组 HTTP 包，造成拆分无效。目前已知 ESET Smart Security 会造成这个功能无效，即使暂停防火墙也一样无效。
//              G|ET /pa|th H|TTTP/1.0
//              HO|ST:www.aa|dd.com
//     可选参数： sleep=0  建立连接后延迟多少毫秒发送数据，配合 ttl 反劫持系统时建议设置为10置50。默认值 0 .

func NewProxyClient(addr string) (ProxyClient, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, errors.New("addr 错误的格式")
	}

	// 将 query key 转换成为小写
	_query := u.Query()
	query := make(map[string][]string, len(_query))
	for k, v := range _query {
		query[strings.ToLower(k)] = v
	}

	queryGet := func(key string) string {
		if query == nil {
			return ""
		}
		v, ok := query[key]
		if !ok || len(v) == 0 {
			return ""
		}
		return v[0]
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))

	var upProxy ProxyClient
	if up, ok := query["upproxy"]; ok == true {
		if upProxy, err = NewProxyClient(up[0]); err != nil {
			return nil, fmt.Errorf("upProxy 创建失败：%v", err)
		}
	}
	_ = query
	_ = queryGet
	_ = scheme
	_ = upProxy

	// 最简单的实现：
	// 调用上一级代理新建连接
	// 调用当前代理的Client并返回

	/*
		switch scheme {
		case "direct":
			localAddr := queryGet("localaddr")
			if localAddr == "" {
				localAddr = ":0"
			}

			splitHttp := false
			if strings.ToLower(queryGet("splithttp")) == "true" {
				splitHttp = true
			}

			sleep := 0 * time.Millisecond
			if queryGet("sleep") != "" {
				if s, err := strconv.Atoi(queryGet("sleep")); err != nil {
					return nil, fmt.Errorf("sleep 参数错误：%v", err)
				} else {
					sleep = time.Duration(s) * time.Millisecond
				}
			}

			return newDriectProxyClient(localAddr, splitHttp, sleep, query)

		case "socks4", "socks4a", "socks5":
			username := ""
			password := ""
			if u.User != nil {
				username = u.User.Username()
				password, _ = u.User.Password()
			}

			return newSocksProxyClient(scheme, u.Host, username, password, upProxy, query)
		case "http", "https":
			auth := ""
			if u.User != nil {
				auth = u.User.String()
			}

			standardHeader := false
			if strings.ToLower(queryGet("standardheader")) == "true" {
				standardHeader = true
			}

			insecureSkipVerify := false
			if strings.ToLower(queryGet("insecureskipverify")) == "true" {
				insecureSkipVerify = true
			}

			domain := queryGet("domain")

			return newHTTPProxyClient(scheme, u.Host, domain, auth, insecureSkipVerify, standardHeader, upProxy, query)
		case "ss":
			password, ok := u.User.Password()
			if ok == false {
				return nil, fmt.Errorf("ss 代理 method, password 格式错误。")
			}
			return newSsProxyClient(u.Host, u.User.Username(), password, upProxy, query)
		default:
			return nil, fmt.Errorf("未识别的代理类型：%v", scheme)
		}*/

	panic("")
}
