/**
  Author: JiaCheng Yang && Wenkai Zheng
  This file is used for running main thread for server
  each network sessions are created in this file
**/
package Server

import (
	"Authentication"
	"Core"
	"Logging"
	"net"
	"strings"
	"sync"
)

var DataPath = "./data.csv"
/**
  This function is used for getting ip from x.x.x.x:n
  x.x.x.x is ip and n is port
  we used it to distinguish differnt sessions
**/
func calculateKey(localTcpConn *net.TCPConn) (ip string) {
	ip = localTcpConn.RemoteAddr().String()
	ip = strings.Split(ip, ":")[0]
	return
}
/**
   This function is used for waiting other requests except first time
   For different IP, we need to construct a new session 
   If we have a new session which means we need to sign in and send 
   encryption table again, and all requests need to go through shake hands
   functions for socks protocol,each request will be store in each session
   according to IP
**/
func waitForNewConnection(proxy *Core.Proxy, tcpListener *net.TCPListener) {
	var ip string
	var session *Session
	var ipMap sync.Map
	for {
		localTcpConn, err := tcpListener.AcceptTCP()
		Logging.NormalLogger.Println("ACCEPT TCP")
		if err != nil {
			Logging.NormalLogger.Println("encounter error when accepting TCP")
			Logging.ErrorLogger.Println(err)
			return
		}
		ip = calculateKey(localTcpConn)
		result, ok := ipMap.Load(ip)
		if !ok {
			session = newSession(proxy, localTcpConn, &ipMap)
			if rc, err := session.signInUser(localTcpConn); rc == false || err != nil {
				Logging.NormalLogger.Println("could not sign in user")
				Logging.ErrorLogger.Println(err)
				continue
			}
			if err := session.readEncryptionTable(localTcpConn); err != nil {
				Logging.NormalLogger.Println("could not get encryption table")
				Logging.ErrorLogger.Println(err)
				continue
			}
			go session.receiveHeartBeat(localTcpConn)
			continue
		}
		session = result.(*Session)

		go func() {
			if err := session.shakeHand(localTcpConn); err != nil {
				Logging.NormalLogger.Println("could not shake hands")
				Logging.ErrorLogger.Println(err)
			}
		}()
	}
}

func Run() {
	Logging.NormalLogger.Println("server is running")
	Authentication.LoadCSV(DataPath)
	proxy, err := Core.NewServerProxy(":6204") // todo may need to read from file
	if err != nil {
		Logging.NormalLogger.Println("encounter a error when starting server proxy")
		return
	}

	// as a server for localhost
	tcpListener, err := net.ListenTCP("tcp", proxy.GetLocalHost())
	if err != nil {
		Logging.NormalLogger.Println("encounter error when opening TCP")
		Logging.ErrorLogger.Println(err)
		return
	}

	// add defer close
	defer func() {
		if err := tcpListener.Close(); err != nil {
			Logging.NormalLogger.Println("cannot close tcp listener")
			Logging.ErrorLogger.Println(err)
		}
	}()

	waitForNewConnection(proxy, tcpListener)

}
