package ProxyLib

import "net"

// Conn 用来表示连接
type Conn interface {
	net.Conn
}

// TCPConn 用来表示 TCP 连接
// 提供 net.TcpConn 结构的全部方法
// 但是部分方法由于代理协议的限制可能不能获得正确的结果。例如：LocalAddr 、RemoteAddr 方法不被很多代理协议支持。
type TCPConn interface {
	Conn

	/*
		SetLinger设定当连接中仍有数据等待发送或接受时的Close方法的行为。
		如果sec < 0（默认），Close方法立即返回，操作系统停止后台数据发送；如果 sec == 0，Close立刻返回，操作系统丢弃任何未发送或未接收的数据；如果sec > 0，Close方法阻塞最多sec秒，等待数据发送或者接收，在一些操作系统中，在超时后，任何未发送的数据会被丢弃。
	*/
	SetLinger(sec int) error

	// SetNoDelay设定操作系统是否应该延迟数据包传递，以便发送更少的数据包（Nagle's算法）。默认为真，即数据应该在Write方法后立刻发送。
	SetNoDelay(noDelay bool) error

	//SetReadBuffer设置该连接的系统接收缓冲
	SetReadBuffer(bytes int) error

	//SetWriteBuffer设置该连接的系统发送缓冲
	SetWriteBuffer(bytes int) error
}

/*
// ProxyTCPConn 用来表示通过代理访问的TCP连接
type ProxyTCPConn interface {
	TCPConn
	ProxyClient() ProxyClient // 获得所属的代理
}*/

// UDPConn 表示 UDP 连接
type UDPConn interface {
	Conn
}
