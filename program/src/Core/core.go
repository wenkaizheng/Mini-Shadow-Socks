/**
  Author: JiaCheng Yang && Wenkai Zheng
  This file is used for declaring some constants
  All constants is used in other files
**/
package Core

import (
	"Encryption"
	"Logging"
	"net"
)
/**
  We assign different int to Server Local and different types
  Representation of different proxies and different working roles
**/
const (
	Server = iota
	Local  = iota
)

const (
	type0 = iota
	type1 = iota
)
/**
  For each connection we have heartbeat thread to send it every 5 seconds
  And read it also 5 seconds, if after 1 second sp does not receive heartbeat
  we think we can close this session
**/
const HeartBeatRate = 5
const HeartBeatTimeout = 1
/**
   FAIL AND SUCCESS are used for password and username verification
   BEAT is used for content from heartbeat message 
**/
var FAIL = []byte{0x3, 0x2, 0x1}
var SUCCESS = []byte{0x1, 0x2, 0x3}
var BEAT = []byte{0xff, 0xff, 0xff}
/**
  This function just compare two byte array's value
**/
func ByteArrEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
/**
  Simple convert String to Byte array
**/
func ConvertStringTOByte(str string) []byte {
	return []byte(str)

}
/**
  Simple convert Byte array to String
**/
func ConvertByteTOString(bt []byte) string {
	return string(bt)
}
/**
 This is correct usage for read in Go
 It guarantee can read n bytes (it need to be used when the data is huge such as more than 1KB)
 we used it when pass decode and encode table
 we used it when send username and password
**/
func ReadAll(buffer []byte, socket *net.TCPConn, size int) (int, error) {
	// 256 is one packet size
	readLength, err := socket.Read(buffer)
	if err != nil {
		return -1, err
	}
	if readLength == 0 {
		return 0, nil
	}
	for {
		if readLength == size {
			break
		}
		twice, err := socket.Read(buffer[readLength:size])
		if err != nil {
			return -1, err
		}
		if twice == 0 {
			return 0, nil
		}
		readLength += twice
	}
	return 1, nil
}
/**
 This is correct usage for write in Go
 It guarantee can write n bytes (it need to be used when the data is huge such as more than 1KB)
 we used it when pass decode and encode table
 we used it when send username and password
**/
func WriteAll(buffer []byte, socket *net.TCPConn, size int) (int, error) {
	// 256 is one packet size
	writeLength, err := socket.Write(buffer)
	if err != nil {
		return -1, err
	}
	for {
		if writeLength == size {
			break
		}
		twice, err := socket.Write(buffer[writeLength:size])
		if err != nil {
			return -1, err
		}
		writeLength += twice
	}
	return 1, nil

}
/**
 This function is used for transfer all data between different hosts and proxies
 It will Write all data in read buffer, and send it to correct destinations
 device can be local and server
 type can be 0 and 1    0 means works as a server, 1 means works as a client
**/
func Transfer(table *Encryption.Table, conn1, conn2 *net.TCPConn, device, types int) {
	for {
		request := make([]byte, 256)
		readLen, err := conn1.Read(request)
		// we need to use proxy to
		if err != nil {
			Logging.NormalLogger.Println("device and types", device, types, "got an error when reading request", "get length", readLen)
			Logging.ErrorLogger.Println(err)
			break
		}
		// connection close by user
		if readLen == 0 {
			Logging.NormalLogger.Println("device and types", device, types, "connection closed by user")
			break
		}

		// if it is local and works as a server
		// or if it is server and works as a client
		if (device == Local && types == type0) || (device == Server && types == type1) {
			request = table.Encode(request)
		}
		// if it is a local and works as a client
		// or it is a server and works as a server

		if (device == Local && types == type1) || (device == Server && types == type0) {
			request = table.Decode(request)
		}

		// we send this byte to sp
		writeLength, err := conn2.Write(request[0:readLen])
		if err != nil {
			Logging.NormalLogger.Println("device and types", device, types, "got an error when writing request")
			Logging.ErrorLogger.Println(err)
			break
		}
		for writeLength != readLen {
			if writeLength != readLen {
				twiceLength, err := conn2.Write(request[writeLength:readLen])
				if err != nil {
					Logging.NormalLogger.Println("device and types", device, types, "got an error when writing request")
					Logging.ErrorLogger.Println(err)
					break
				}
				writeLength += twiceLength
			}
		}
	}
}
