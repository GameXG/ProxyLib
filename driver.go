package ProxyLib

import (
	"context"
	"net"
	"net/url"
	"sort"
	"sync"
)

var (
	protocolsMu sync.RWMutex
	protocols   = make(map[string]ProxyProtocol)
)

// 协议实现

// 本来计划客户端只实现 ClientContext 接口，其余的由库本身实现。
// socks5 等等用这种方式是没问题的，但是如果存在连接复用之类的情况就不可行了。

// 那么比较好的解决办法是提供 Dial 函数指针，具体新建不新建连接由库自己决定。但是这就和目前的实现没什么区别了。
// 并且这种使得直接使用外部其他协议的连接不友好了。
// 而且无法用在预连接池等功能。

// Dial + 预连接池
// Dial 方案预连接池计划使用中间代理实现，中间代理拦截到 Dial 请求后会建立多个连接，多余的连接备用。

// 基本决定了，使用双接口策略
// 大部分都是用 Client 接口，当协议限制不支持 Client 时实现 Dial 接口。
// 然后由外部系统同意封装为 Dial 接口。
// 工厂会使用类型转换的方式探测 协议 支持哪种，优先 Client 模式。

// 思考下库后期需要支持的特征：
// 嵌套代理  -- 很简单
// 预连接   -- 原始方案可以通过增加一个中间代理来实现预连接管理。 Client 方案会碰到不清楚 addr 的问题
// 使用现存连接   -- 库使用者可能由特殊需求，例如特殊的连接
// 端口范围，随机端口
// 多连接同时负载一个连接，或udp负载等等 全局连接的问题

// 现在感觉 Client 功能只有协议实现者才需要，那么这个功能就不需要多易用了，需要的时更多的功能。

// 我考虑下协议只实现 DialContext，由工厂类实现 DialContext 是否有麻烦：
// 协议目前服务器地址都是同一的，可以自动提取。
// 但是部分随机端口范围的无法自动提取，另外还不知道协议的端口号。
// 允许可以通过协议提供一个接口返回目标地址的方式工作？
// 这么扭曲工作的目的是为了实现预连接等功能。
// 考虑一下实际工作的流程图
// 发起请求 -> 框架 -> 协议实现类.GetAddr() -> 创建创建连接 -> 协议实现类.Client()
// 这种思想方式对于常规应用是可以实现全部功能的，而且这样预连接一类需求也可以由框架实现了。

// 对于需要自己维护连接池等情况的协议，对方不实现 Client 接口，只实现老的接口即可。框架会自动使用老式实现，由协议管理连接等。
//

// 代理协议需要实现的基本接口
type ProxyProtocol interface {

	// 这个实现并没有什么特别的意义
	// 主要是为了区别
	ProxyProtocolName() string
}

// 代理协议的客户端实现接口
// 如果代理协议支持客户端实现，不只需要实现 ProxyProtocol ，还需要实现这个接口。
type ProxyProtocolNewClient interface {
	// 新建一个 client 实现
	NewProxyClient(url *url.URL, lowQuery map[string][]string, rawUrl string) (ProxyProtocolClient, error)
}

// 代理协议的客户端实现
type ProxyProtocolClient interface {
}

// 如果代理协议不需要自己管理连接池，则应该实现这个接口
type ProxyProtocolClientClient interface {
	ClientContext(conn net.Conn, ctx context.Context, network, address string) (net.Conn, error)

	// 获得服务器地址
	GetServerAddr() (network, address string, err error)
}

// 如果代理协议不是一个到代理服务器的连接对应一个浏览器连接，那么就需要实现这个接口，而不要实现 ProxyProtocolClient 接口。
type ProxyProtocolClientDial interface {
	// 这里是否可以增加一个预连接功能？
	// 只包含和代理服务器握手，不包含cmd命令部分？

	// 考虑下，一个连接有3个步骤
	// 1.建立到代理的tcp连接
	// 2.完成登陆等操作
	// 3.完成到实际网站的连接
	// 虽然存在udp协议等情况，但是也可以映射到这3步。

	// 这种操作基本可以适应全部情况，但是唯一的缺陷是不支持 Client 了。

	// 可能接口又需要修改，需要实现快速请求机制，socks5例子：
	// 连续发出 鉴定、命令、http 请求，命令回应则异步读取。
	// 不过注意：部分socks5代理服务器(ss C#版本)实现有问题，会丢弃一部分数据，所以使用前需要测试代理服务器是否有这个bug。

	DialContext(ctx context.Context, network, address string) (Conn, error)
}

// 注册协议
func Register(name string, protocol ProxyProtocol) {
	protocolsMu.Lock()
	defer protocolsMu.Unlock()
	if protocol == nil {
		panic("Register driver is nil")
	}
	if _, dup := protocols[name]; dup {
		panic("Register called twice for driver " + name)
	}
	protocols[name] = protocol
}

func unregisterAllDrivers() {
	protocolsMu.Lock()
	defer protocolsMu.Unlock()
	protocols = make(map[string]ProxyProtocol)
}

func Protocols() []string {
	protocolsMu.RLock()
	defer protocolsMu.RUnlock()
	var list []string
	for name := range protocols {
		list = append(list, name)
	}
	sort.Strings(list)
	return list
}

func queryGet(query map[string][]string, key string) string {
	if query == nil {
		return ""
	}
	v, ok := query[key]
	if !ok || len(v) == 0 {
		return ""
	}
	return v[0]
}
