/**
  Author: JiaCheng Yang && Wenkai Zheng
  This file is used for declaring main methods for local proxy
  All method is used in other files
**/
package main

import (
	"Authentication"
	"Core"
	"Encryption"
	"FileParser"
	"Local.main/Local"
	"Logging"
	"net"
	"time"
)

/**
   Path for config file
**/
var ConfigPath = "./config.json"
/**
  This function read json from config file
  And get basic setup info
  For future connection usage
**/
func readJson(serverInfo *Local.ServerInfo) {
	Logging.NormalLogger.Println("Going to read Json")
	if err := FileParser.GetJasonConfig(ConfigPath, serverInfo); err != nil {
		Logging.ErrorLogger.Fatal("encounter a error when reading Json file")
	}
}
/**
  This function will read all info and 
  Encode sending infos to serverproxy for verification
  and it expects a message from serverproxy which means
  Success or Fail
**/
func signIn(serverInfo Local.ServerInfo, serverTcpConn *net.TCPConn) {
	// we need to send user name and key to verify
	// we need to make sure decode and encode table will be sent
	// also we need to send key and password as verify
	Logging.NormalLogger.Println("going to send username")
	EncodeName := Core.ConvertStringTOByte(Authentication.EncodeUsername(serverInfo.GetUserName()))
	check1, check2 := Core.WriteAll(EncodeName, serverTcpConn, 128)
	if check1 == -1 && check2 != nil {
		Logging.ErrorLogger.Fatal("encounter a error when sending username")
	}

	Logging.NormalLogger.Println("going to send password")
	EncodeKey := Core.ConvertStringTOByte(Authentication.EncodePassword(serverInfo.GetPassword()))
	check1, check2 = Core.WriteAll(EncodeKey, serverTcpConn, 128)
	if check1 == -1 && check2 != nil {
		Logging.ErrorLogger.Fatal("encounter a error when sending password")
	}
	// we expect the reply from
	verification := make([]byte, 3, 3)
	check1, check2 = Core.ReadAll(verification, serverTcpConn, 3)
	if check1 == -1 && check2 != nil {
		Logging.ErrorLogger.Fatal("encounter a error when sending password")
	}
	if !(Core.ByteArrEqual(verification, Core.SUCCESS)) {
		Logging.ErrorLogger.Fatal("wrong username and password")
	}
	Logging.NormalLogger.Println("correct")
}
/**
   This function will send encryption table to server proxy
   Same session will use same encode and decode table
   The encryption table will be used as future transmissions
**/
func sendEncryptionTable(table *Encryption.Table, serverTcpConn *net.TCPConn) {
	Logging.NormalLogger.Println("going to send encode arr")
	encode := table.GetEncodeArr()
	check1, check2 := Core.WriteAll(encode, serverTcpConn, 256)
	if check1 == -1 && check2 != nil {
		Logging.ErrorLogger.Fatal("encounter a error when sending encode arr")
	}

	Logging.NormalLogger.Println("going to send decode arr")
	decode := table.GetDecodeArr()
	check1, check2 = Core.WriteAll(decode, serverTcpConn, 256)
	if check1 == -1 && check2 != nil {
		Logging.ErrorLogger.Fatal("encounter a error when sending decode arr")
	}
}
/**
  This function will listen 5209 port for user application
  Once there is any new request, it need to connects with server proxy
  construt a new connection handler
  And go into Transfer data part
**/
func listenConnection(proxy *Core.Proxy, tcpListener *net.TCPListener, table *Encryption.Table) {
	Logging.NormalLogger.Println("local is waiting for connection")
	for {
		localTcpConn, _ := tcpListener.AcceptTCP()
		serverTcpConn, err := net.DialTCP("tcp", nil, proxy.GetServerHost())
		if err != nil {
			Logging.ErrorLogger.Fatal("terminating: server is not running")
		}

		Logging.NormalLogger.Println("accepted a connection")
		Logging.NormalLogger.Printf(localTcpConn.LocalAddr().String())
		Logging.NormalLogger.Printf(serverTcpConn.LocalAddr().String())
		Logging.NormalLogger.Printf(localTcpConn.RemoteAddr().String())
		Logging.NormalLogger.Printf(serverTcpConn.RemoteAddr().String())
		connection := Core.NewConnectionHandler(localTcpConn, serverTcpConn, proxy.GetDevice(), table)
		go connection.TransferData()
	}
}
/**
  This function sends a heartbeat message every 5 seconds
  This mechanism will keep detect life cycle for 
  One session (By IP) 
**/
func sendHeartBeat(serverTcpConn *net.TCPConn) {
	var check1 int
	var check2 error
	for {
		// send a message
		check1, check2 = serverTcpConn.Write(Core.BEAT)
		if check1 == -1 && check2 != nil {
			Logging.ErrorLogger.Fatal("Local Proxy write has problem")
		}
		time.Sleep(Core.HeartBeatRate * time.Second)
	}
}
/**
  Construct a new local proxy 
  Main function for pre connect with server proxy
  Send username, password, and encode, decode table
  And then goto listen for multiple requests 
  Also keep heartbeat mechanism to detect life cycle
**/
func main() {
	// should be get in configuration
	var serverInfo Local.ServerInfo
	readJson(&serverInfo)

	Logging.NormalLogger.Println("starting local proxy")
	// we need to encode this key and password
	proxy, err := Core.NewLocalProxy(serverInfo.GetLocalAddr(), serverInfo.GetServerAddr())
	if err != nil {
		Logging.ErrorLogger.Fatal("encounter a error when starting local proxy")
	}

	serverTcpConn, err := net.DialTCP("tcp", nil, proxy.GetServerHost())
	if err != nil {
		Logging.ErrorLogger.Fatal("terminating: server is not running")
	}

	signIn(serverInfo, serverTcpConn)

	encryptionTable := Encryption.NewEncryptionTable()
	sendEncryptionTable(encryptionTable, serverTcpConn)

	go sendHeartBeat(serverTcpConn)

	Logging.NormalLogger.Printf("going to listen: %s:%d\n", proxy.GetLocalHost().IP.String(), proxy.GetLocalHost().Port)
	// as a server for localhost
	tcpListener, _ := net.ListenTCP("tcp", proxy.GetLocalHost()) // todo why ignore error?
	// add defer close
	defer func() {
		if err := tcpListener.Close(); err != nil {
			Logging.NormalLogger.Println("cannot close tcp listener")
			Logging.ErrorLogger.Println(err)
		}
	}()

	listenConnection(proxy, tcpListener, encryptionTable)
}