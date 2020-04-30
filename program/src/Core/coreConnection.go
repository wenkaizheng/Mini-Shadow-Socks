package Core

/**
  Author: JiaCheng Yang && Wenkai Zheng
  This file is used for representing Connection handle struct
  All methods and constructor are in this file
**/
import (
	"Encryption"
	"Logging"
	"errors"
	"net"
	"sync/atomic"
)

/**
   Each TcpConn is wokring as same way as socket,and they can read write directly.
   Each complete is used for joining thread
   Each isRunning is used for checking proxy's status
   Encryption table is used for decode and encode
**/
type ConnectionHandler struct {
	localTcpConn          *net.TCPConn
	serverTcpConn         *net.TCPConn
	localTcpComplete      chan int
	serverTcpComplete     chan int
	isLocalRunning        bool
	isServerRunning       bool
	device                int
	encryptionTable       *Encryption.Table
	isLocalTcpConnClosed  int32
	isServerTcpConnClosed int32
}

/**
   Simple constructor for connection handler
**/
func NewConnectionHandler(local, server *net.TCPConn, device int, table *Encryption.Table) *ConnectionHandler {
	return &ConnectionHandler{
		localTcpConn:          local,
		serverTcpConn:         server,
		localTcpComplete:      make(chan int),
		serverTcpComplete:     make(chan int),
		isLocalRunning:        false,
		isServerRunning:       false,
		device:                device,
		encryptionTable:       table,
		isLocalTcpConnClosed:  0,
		isServerTcpConnClosed: 0,
	}
}

/**
   We assgin proxy's corrected device and type to transfer function in core.go
   When there is any error occure we will close this connection and
   join the parent thread (read from left to right ) app to remote server
**/

func (h *ConnectionHandler) transferRequest() error {
	Logging.NormalLogger.Print("Going to transfer request ")
	if h.isServerRunning {
		return errors.New("server is already running")
	}
	h.isServerRunning = true
	h.serverTcpComplete <- 0
	Transfer(h.encryptionTable, h.localTcpConn, h.serverTcpConn, h.device, type0)
	var e = h.closeLocalConnection()
	Logging.NormalLogger.Print("deal as server terminates")
	h.serverTcpComplete <- 0
	return e
}

/**
   We assgin proxy's corrected device and type to transfer function in core.go
   When there is any error occure we will close this connection and
   join the parent thread (read from right to left ) remote server to app
**/
func (h *ConnectionHandler) transferRespond() error {
	Logging.NormalLogger.Print("Going to transfer respond ")
	if h.isLocalRunning {
		return errors.New("client is already running")
	}
	h.isLocalRunning = true
	h.localTcpComplete <- 0
	Transfer(h.encryptionTable, h.serverTcpConn, h.localTcpConn, h.device, type1)
	var e = h.closeServerConnection()
	Logging.NormalLogger.Print("deal as client terminates")
	h.localTcpComplete <- 0
	return e
}

/**
   Parent thread for response and request network data
   Simple call response and request thread and wait unit complete( call wait function )
   Makesure response and request thread are running before waiting
**/
func (h *ConnectionHandler) TransferData() {
	go func() {
		if err := h.transferRequest(); err != nil {
			Logging.ErrorLogger.Println(err)
		}
	}()
	go func() {
		if err := h.transferRespond(); err != nil {
			Logging.ErrorLogger.Println(err)
		}
	}()
	<-h.localTcpComplete
	<-h.serverTcpComplete
	if err := h.Wait(); err != nil {
		Logging.ErrorLogger.Println(err)
	}
}

/**
   This functions will be called after response and request thread is running
   And it will finished after  response and request thread are finished
   Makesure response and request thread is already running in here
**/
func (h *ConnectionHandler) Wait() error {
	Logging.NormalLogger.Print("Going to wait client and server ")
	if !h.isLocalRunning {
		return errors.New("client is not running")
	}
	if !h.isServerRunning {
		return errors.New("server is not running")
	}
	<-h.localTcpComplete
	<-h.serverTcpComplete
	h.isLocalRunning = false
	h.isServerRunning = false
	return nil
}

/**
   Simple close Tcp connection
**/
func (h *ConnectionHandler) Abort() {
	_ = h.closeLocalConnection()
	_ = h.closeServerConnection()
}
/**
   This function will close Tcp Conn safely 
**/
func (h *ConnectionHandler) closeLocalConnection() error {
	if swapped := atomic.CompareAndSwapInt32(&(h.isLocalTcpConnClosed), 0, 1); swapped {
		if err := h.localTcpConn.Close(); err != nil {
			Logging.NormalLogger.Print("cannot close local TCP conn")
			return err
		}
	}
	return nil
}
/**
   This function will close Tcp Conn safely 
**/
func (h *ConnectionHandler) closeServerConnection() error {
	if swapped := atomic.CompareAndSwapInt32(&(h.isServerTcpConnClosed), 0, 1); swapped {
		if err := h.serverTcpConn.Close(); err != nil {
			Logging.NormalLogger.Print("cannot close server TCP conn")
			return err
		}
	}
	return nil
}