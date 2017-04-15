# 代理库

代理库意图实现各种代理，接口尽可能的兼容标准库。


# 客户端部分

net 标准库有 Dialer struct ，这个实现了 func (d *Dialer) Dial(network, address string) (Conn, error) 及 
func (d *Dialer) DialContext(ctx context.Context, network, address string) (Conn, error) 函数。

不过这个是一个结构，并不是太好的选择。

然后 https://godoc.org/golang.org/x/net/proxy#Dialer 有个 Dialer interface ，实现了 Dial ，但是没实现新版本的 Context 。

http 部分 Transport struct 允许通过函数指针的方式设置 Dial 及 DialContext。然后 Transport struct 又实现了 RoundTripper 接口。

对于http代理，后期可以尝试提供 RoundTripper 接口，不过实际感觉这个没必要，connect 还可以防止代理做缓存。


# 服务端部分

这个就需要再看看了，不过大体还是直接实现 net 库。

仔细想了一下，服务端就是接受请求并对外发起连接，那么其实还是 Dial 接口，只不过变成了调用 Dial 接口。也就是一样，服务端部分提供个 
Dial 函数指针即可。

# https 专用代理

计划实现个http专用代理，这个远端剥离 tls 协议，本地在套上 tls ，使用自签证书。
远端剥离证书时发现证书错误，那么将不执行剥离，直接改为tcp纯转发，防止被攻击。

其实也可以试试 http2 ，这个也很好玩。

这次重写的目的是抽象出通用的代码来实现服务器部分。


# http 协议部分

这个版本计划处理到 http 级别，目的是支持http请求响应重写。https 也将会被剥离 tls。

标准库有 RoundTripper接口，用来处理单个http请求，长连接可以通过 Hijacker 接口直接获取底层连接(不使用框架时不需要)。

然后是 http2 和websocket 不兼容的问题，目前看起来还没一个固定的规范，所以目前只能在http1下实现 websocket。
参考：
Will WebSocket survive HTTP/2?  https://www.infoq.com/articles/websocket-and-http2-coexist
【译】NO WEBSOCKETS OVER HTTP/2 https://segmentfault.com/a/1190000005794488
现在的WebSocket还不能用于HTTP2.0的链路上。协议还在设计。 https://www.zhihu.com/question/32039008

Server-sent events 这个是纯 http 协议，看起来可以当作无长度的响应，不用单独处理。

# 实际工作

主要目的支持多个线路及代理，根据规则选择线路。

其中规则可能是自动线路选择器。

计划软件工作的步骤是(GET请求)：

* 同时建立多个连接
* 使用第一个建立的连接,后期建立的连接保留一段时间
* 通过第一个发出 http 请求
* 接收响应，暂时不转交给浏览器
* 判断响应是否正确，例如https证书是否正确？是否是黑名单的响应？
* 判断网速是否正常，响应尺寸/下载速度 > 0.5秒会执行一些检查，否则直接放过
* 判断是否是大文件，如果是大文件对网速要求更严格写
* 如果响应正常就继续使用这个连接
* 如果响应不对，就尝试启用之前保留的备用连接，重新发起新的请求


大文件特别处理：

* 当检查到响应的尺寸大于一定大小
* 尝试多来源同时下载，可以根据大小(etag 不太可靠)及故意多下载的交叠的一部分数据来判断是否正确
