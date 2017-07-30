package ProxyLib

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type DirectProtocol struct {
}

func (DirectProtocol) ProxyProtocolName() string {
	return "Direct"
}

type DirectProtocolClient struct {
	TCPLocalAddr *net.TCPAddr
	UDPLocalAddr *net.UDPAddr
	splitHttp    bool
	sleep        time.Duration
	query        map[string][]string
}

func (d *DirectProtocol) NewProxyClient(url *url.URL, lowQuery map[string][]string, rawUrl string) (ProxyProtocolClient, error) {
	localAddr := queryGet(lowQuery, "localaddr")
	if localAddr == "" {
		localAddr = ":0"
	}

	splitHttp := false
	if strings.ToLower(queryGet(lowQuery, "splithttp")) == "true" {
		splitHttp = true
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", localAddr)
	if err != nil {
		return nil, errors.New("LocalAddr 错误的格式")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, errors.New("LocalAddr 错误的格式")
	}

	sleep := 0 * time.Millisecond
	sleepStr := queryGet(lowQuery, "sleep")
	if sleepStr != "" {
		if s, err := strconv.Atoi(sleepStr); err != nil {
			return nil, fmt.Errorf("sleep 参数错误：%v", err)
		} else {
			sleep = time.Duration(s) * time.Millisecond
		}
	}

	return &DirectProtocolClient{
		TCPLocalAddr: tcpAddr,
		UDPLocalAddr: udpAddr,
		sleep:        sleep,
		splitHttp:    splitHttp,
	}, nil
}


func (d *DirectProtocolClient) DialContext(ctx context.Context, network, address string) (Conn, error){

}
