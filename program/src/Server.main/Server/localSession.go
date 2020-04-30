/**
  Author: JiaCheng Yang && Wenkai Zheng
  This file is used for running main thread for server
  each network sessions are created in this file
**/
package Server

import (
	"Authentication"
	"Core"
	"Encryption"
	"Logging"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

/**
   Session struct will contain username password from user
   IsRunning means the life cycle
   KeyInmap means IP address from users
   Proxy is either local and server proxy
   Connections is established tcp between two proxy
   Encrption table is for encode and decode
   ipMap is for putting itself into this ipMap(in server.go)
**/

type Session struct {
	username        string
	password        string
	isRunning       int32
	keyInMap        string
	proxy           *Core.Proxy
	connections     sync.Map
	encryptionTable *Encryption.Table
	ipMap           *sync.Map
}

/**
   Simple constructor for Session
**/
func newSession(proxy *Core.Proxy, localTcpConn *net.TCPConn, ipMap *sync.Map) *Session {
	var connMap sync.Map
	return &Session{
		username:        "",
		password:        "",
		isRunning:       1,
		keyInMap:        calculateKey(localTcpConn),
		proxy:           proxy,
		connections:     connMap,
		encryptionTable: Encryption.NewEmptyEncryptionTable(),
		ipMap:           ipMap,
	}
}

/**
   This function will read password and user name
   And then verify those datas between our CSV database
   It will send message to indicate success or fail
   This is guraantee read write because length is defined already
**/
func (s *Session) signInUser(localTcpConn *net.TCPConn) (bool, error) {
	if s.isRunning != 1 {
		return false, errors.New("The server proxy is not running") 
	}
	name := make([]byte, 128)
	key := make([]byte, 128)
	// read password and name first and then read decode , encode
	check1, check2 := Core.ReadAll(name, localTcpConn, 128)
	if (check1 == -1 && check2 != nil) || (check1 == 0 && check2 == nil) {
		return false, errors.New("Username transfer is not successful")  
	}
	s.username = Core.ConvertByteTOString(name)
	check1, check2 = Core.ReadAll(key, localTcpConn, 128)
	if (check1 == -1 && check2 != nil) || (check1 == 0 && check2 == nil) {
		return false, errors.New("Password transfer is not successful")  
	}
	s.password = Core.ConvertByteTOString(key)
	var ok bool
	var err error
	ok, err = Authentication.Verify(s.username, s.password)
	if ok == false || err != nil {
		check1, check2 = Core.WriteAll(Core.FAIL, localTcpConn, 3) 
		if check1 == -1 && check2 != nil {
			return false, errors.New("Write encouters problem when reply response")  
		}

	} else {
		check1, check2  = Core.WriteAll(Core.SUCCESS, localTcpConn, 3) 
		if check1 == -1 && check2 != nil {
			return false, errors.New("Write encouters problem when reply response")  
		}
		s.ipMap.Store(s.keyInMap, s)
	}
	return ok, err
}

/**
	This function will read encode table and decode table
	And save both tables for future transmissions
	this is guraantee read write because length is defined already
**/
func (s *Session) readEncryptionTable(localTcpConn *net.TCPConn) error {
	if s.isRunning != 1 {
		return errors.New("The server proxy is not running") 
	}
	encode := make([]byte, 256)
	decode := make([]byte, 256)
	check1, check2 := Core.ReadAll(encode, localTcpConn, 256)
	if (check1 == -1 && check2 != nil) || (check1 == 0 && check2 == nil) {
		s.ipMap.Delete(s.keyInMap)
		return errors.New("Read encounters problem when read encode table")
	}
	s.encryptionTable.SetEncodeArr(encode)
	check1, check2 = Core.ReadAll(decode, localTcpConn, 256)
	if (check1 == -1 && check2 != nil) || (check1 == 0 && check2 == nil) {
		s.ipMap.Delete(s.keyInMap)
		return errors.New("Read encounters problem when read decode table")
	}
	s.encryptionTable.SetDecodeArr(decode)
	return nil 
}

/**
   This function will unpack socks5 protocol and send reply
   It will help server proxy to get connect with realy server
   The incoming pakcet from user application will contain those
   informations. We need to get and save them for future transmission
**/
func (s *Session) shakeHand(localTcpConn *net.TCPConn) error {
	if s.isRunning != 1 {
		return errors.New("The server proxy is not running")
	}
	var serverTcpConn *net.TCPConn
	request := make([]byte, 262)
	// now we expect socks5 protocol, first step is confirm socks5
	//readLength, err := localTcpConn.Read(request)
	readLength, err := localTcpConn.Read(request)
	// we need to use proxy to
	if err != nil {
		Logging.NormalLogger.Println("encounter error when reading")
		return err
	}

	decodedRequest := s.encryptionTable.Decode(request[0:readLength])
	// we need to use proxy to
	if decodedRequest[0] != 0x5 {
		return errors.New("The protocol setting is not proxy5")
	}

	Logging.NormalLogger.Println("1st request", decodedRequest, "length'", readLength)

	// give response to local and do not need key and password
	encodeResponse := s.encryptionTable.Encode([]byte{0x5, 0x0})
	Logging.NormalLogger.Println("going to write response")
	_, err = localTcpConn.Write(encodeResponse)
	if err!= nil{
		return err
	}
	/**
		+----+-----+-------+------+----------+----------+
	        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	        +----+-----+-------+------+----------+----------+
	        | 1  |  1  | X'00' |  1   | Variable |    2     |
	        +----+-----+-------+------+----------+----------+
		**/
	Logging.NormalLogger.Println("waiting for new package")
	// clean the buffer
	request = make([]byte, 262)
	readLength, err = localTcpConn.Read(request)
	if err != nil {
		return err
	}
	if readLength < 7 {
		Logging.NormalLogger.Println("It should be at least seven bytes")
		return errors.New("The packet should be at least seven bytes")
	}
	decodedRequest = s.encryptionTable.Decode(request[0:readLength])
	Logging.NormalLogger.Println("request", decodedRequest, "length'", readLength)

	// only support connect as method
	if decodedRequest[1] != 0x1 {
		return errors.New("Connect is only support method")
		
	}

	tcpAddress := s.proxy.ConnectToRealServer(decodedRequest, readLength)
	serverTcpConn, err = net.DialTCP("tcp", nil, tcpAddress)
	if err != nil {
		return err
	}

	response2 := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	encodeResponse = s.encryptionTable.Encode(response2)
	//localTcpConn.Core.WriteAll(encodeResponse)
	_, err = localTcpConn.Write(encodeResponse)
	if err != nil {
		return err
	}

	connection := Core.NewConnectionHandler(localTcpConn, serverTcpConn, s.proxy.GetDevice(), s.encryptionTable)
	s.connections.Store(&connection, &connection)
	go func() {
		connection.TransferData()
		s.connections.Delete(&connection)
	}()

	return err
}

/**
  This function handles a thread control and
  Read from localproxy every 5 seconds
  If there is no responses about heartbeat we need to close this session
**/
func (s *Session) receiveHeartBeat(localTcpConn *net.TCPConn) {
	mes := make([]byte, 3, 3)
	for {
		//todo need jiacheng confirm
		if s.isRunning != 1 {
			return
		}
		if err := localTcpConn.SetReadDeadline(time.Now().Add(Core.HeartBeatTimeout * time.Second)); err != nil {
			Logging.ErrorLogger.Println("Encounter an error when set heart beat timeout")
			break
		}
		check1, check2 := localTcpConn.Read(mes)
		if check1 == -1 && check2 != nil {
			Logging.ErrorLogger.Println("encounter a error read a message")
			break
		}
		if !(Core.ByteArrEqual(mes, Core.BEAT)) {
			Logging.ErrorLogger.Println("Server Proxy did not receive heart message")
			break
		}
		Logging.NormalLogger.Println("receive heart beat")
		mes = make([]byte, 3, 3)
		time.Sleep(Core.HeartBeatRate * time.Second)
	}
	s.closeSession()
}

/**
  This function will close session which means
  Delete key from map(all conections)
  And Remove itself from IPmap
**/
func (s *Session) closeSession() {
	atomic.StoreInt32(&(s.isRunning), 0)
	s.connections.Range(closeConnection)
	s.ipMap.Delete(s.keyInMap)
	Logging.NormalLogger.Println("Session closed")
}

/**
  This call back function will go through all key in connection map
  and call abort for it
  it will stop when the key is nil (no more)
**/
func closeConnection(key interface{}, value interface{}) bool {
	if key == nil {
		return false
	}
	if v, ok := key.(*Core.ConnectionHandler); ok {
		v.Abort()
		return true
	}
	return false
}
