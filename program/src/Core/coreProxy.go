/**
  Author: JiaCheng Yang && Wenkai Zheng
  This file is used for Proxy struct
  All constructor, methods and setter getter are defined in here
**/
package Core

import (
	"encoding/binary"
	"errors"
	"net"
)

/**
   Local Proxy need to have both localhost and server/remote host
   Device is used for distinguishing server or local
**/
type Proxy struct {
	localHost  *net.TCPAddr
	serverHost *net.TCPAddr
	device     int // 1 is server 0 is local
}

/**
   This is the constructor for ServerProxy
   It just have local tcp addr because it hasn't know
   the remote tcp addr yet
**/
func NewServerProxy(local string) (*Proxy, error) {
	// as a server we don't need ip address just port
	addr0, err := net.ResolveTCPAddr("tcp4", local)
	if err != nil {
		return nil, err
	}
	return &Proxy{localHost: addr0, serverHost: nil, device: Server}, nil
}

/**
   This is the constructor for LocalProxy
   It has both local and remote/server tcp addr
   Local is for user application and server is for server proxy
**/
func NewLocalProxy(local, server string) (*Proxy, error) {
	//rand.Seed(0)
	// as a server we don't need ip address just port
	addr0, err := net.ResolveTCPAddr("tcp", local)
	if err != nil {
		return nil, err
	}
	// as a client we need both ip address and port
	addr1, err := net.ResolveTCPAddr("tcp", server)
	if err != nil {
		return nil, err
	}
	return &Proxy{localHost: addr0, serverHost: addr1, device: Local}, nil
}

/**
   Simple getter for localhost
**/
func (p Proxy) GetLocalHost() *net.TCPAddr {
	return p.localHost
}

/**
   Simple getter for serverhost
**/
func (p Proxy) GetServerHost() *net.TCPAddr {
	if p.serverHost == nil || p.device == Server {
		return nil
	}
	return p.serverHost
}

/**
    Simple setter for serverhost
**/
func (p *Proxy) SetServerHost(copy *net.TCPAddr) error {
	if p.device == Server {
		return errors.New("") //todo some error
	}
	p.serverHost = copy
	return nil
}

/**
	Simple setter for localhost
**/
func (p *Proxy) SetLocalHost(copy *net.TCPAddr) error {
	p.localHost = copy
	return nil
}

/**
    Return this proxy is local or server
**/
func (p Proxy) GetDevice() int {
	return p.device
}

/**
  This function help server proxy to connect to real server
  The last two bytes is port number
  First to get ATYP either ipv4, ipv6 or Domain name
  For ipv4 and ipv6 it starts from 4 to it's length
  For domain name it starts from 5 until first byte of port
  (starts from 5 because 4 is used for indicating length)
**/
func (p *Proxy) ConnectToRealServer(request []byte, length int) *net.TCPAddr {
	port := int(binary.BigEndian.Uint16(request[length-2:]))
	var ip []byte
	if request[3] == 0x1 {
		ip = request[4 : 4+net.IPv4len]
	} else if request[3] == 0x3 {
		ip1, err := net.ResolveIPAddr("ip", string(request[5:length-2]))
		if err != nil {
			return nil
		}
		ip = ip1.IP
	} else if request[3] == 0x4 {
		ip = request[4 : 4+net.IPv6len]
	}
	return &net.TCPAddr{
		IP:   ip,
		Port: port}
}
