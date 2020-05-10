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
	if (check1 == -1 && check2 != nil) {
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
	request := make([]byte, 2)
	// now we expect socks5 protocol, first step is confirm socks5
	//readLength, err := localTcpConn.Read(request)
	readLength, err := Core.ReadAll(request,localTcpConn ,2)
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
	nextReadByte := int(decodedRequest[1])
	request = make([]byte, nextReadByte)
	readLength, err = Core.ReadAll(request,localTcpConn ,nextReadByte)
	// we need to use proxy to
	if err != nil {
		Logging.NormalLogger.Println("encounter error when reading method")
		return err
	}
	Logging.NormalLogger.Println("1st request", decodedRequest, "length'", readLength)

	// give response to local and do not need key and password
	encodeResponse := s.encryptionTable.Encode([]byte{0x5, 0x0})
	Logging.NormalLogger.Println("going to write response")
	_, err = Core.WriteAll(encodeResponse, localTcpConn, 2)
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
	request = make([]byte, 4)
	// second step is get the domain name and ip address from local
	//readLength, err = localTcpConn.Read(request)
	readLength, err = Core.ReadAll(request,localTcpConn ,4)
	if err != nil {
		return err
	}
	length := 4
	decodedRequest = s.encryptionTable.Decode(request[0:4])
	// only support connect as method
	if decodedRequest[1] != 0x1 {
		return  errors.New("100th connect is only support method")
	}
	if decodedRequest[3]==Core.IpV4{
		// v4
		length += 6
		firstRequest := make([]byte, 6)
		readLength, err = Core.ReadAll(firstRequest,localTcpConn ,6)
		if err != nil {
			return err
		}
		decodedRequest1 := s.encryptionTable.Decode(firstRequest[0:6])
		realRequest := make([]byte, length)
		j:=0
		for i:=0;i<4;i++{
			realRequest[j] = decodedRequest[i]
			j+=1
		}
		for i:=0;i<6;i++{
			realRequest[j]= decodedRequest1[i]
			j+=1
		}
		tcpAddress := s.proxy.ConnectToRealServer(realRequest, length)
		serverTcpConns, err := net.DialTCP("tcp", nil, tcpAddress)
		
		if err != nil {
			return err
		}
		serverTcpConn = serverTcpConns

	
	}else if decodedRequest[3]==Core.DomainName{
		// domain name
		firstRequest := make([]byte, 1)
		// read domain's length
		readLength, err = Core.ReadAll(firstRequest,localTcpConn ,1)
		if err != nil {
			return err
		}
		length +=1
		decodedRequest1 := s.encryptionTable.Decode(firstRequest[0:1])
		nextReadByte = int(decodedRequest1[0])+2
		length +=nextReadByte
        	secondRequest := make([]byte, nextReadByte)
		readLength, err = Core.ReadAll(secondRequest,localTcpConn ,nextReadByte)
		if err != nil {
			return err
		}
		decodedRequest2 := s.encryptionTable.Decode(secondRequest[0:nextReadByte])
		realRequest := make([]byte, length)
		j:=0
		for i:=0;i<4;i++{
			realRequest[j] = decodedRequest[i]
			j+=1
		}
		realRequest[j]= decodedRequest1[0]
		j+=1
		for i:=0;i<nextReadByte;i++{
			realRequest[j]= decodedRequest2[i]
			j+=1
		}
		Logging.NormalLogger.Println(realRequest)
		tcpAddress := s.proxy.ConnectToRealServer(realRequest, length)
		serverTcpConns, err := net.DialTCP("tcp", nil, tcpAddress)
		if err != nil {
			return err
		}
		serverTcpConn = serverTcpConns

	}else if decodedRequest[3]==Core.IpV6{
			// v6
			
			length += 18
			firstRequest := make([]byte, 18)
			readLength, err = Core.ReadAll(firstRequest,localTcpConn ,18)
			if err != nil {
				return err
			}
			decodedRequest1 := s.encryptionTable.Decode(firstRequest[0:18])
			realRequest := make([]byte, length)
			j:=0
			for i:=0;i<4;i++{
				realRequest[j] = decodedRequest[i]
				j+=1
			}
			for i:=0;i<18;i++{
				realRequest[j]= decodedRequest1[i]
				j+=1
			}
			tcpAddress := s.proxy.ConnectToRealServer(realRequest, length)
			serverTcpConns, err := net.DialTCP("tcp", nil, tcpAddress)
			// add defer close
			
			if err != nil {
			   return err
			}
			serverTcpConn = serverTcpConns
			
	}


	response2 := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	encodeResponse = s.encryptionTable.Encode(response2)
	//localTcpConn.Core.WriteAll(encodeResponse)
	_,err = Core.WriteAll(encodeResponse, localTcpConn, 10)
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