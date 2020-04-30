/**
  Author: JiaCheng Yang && Wenkai Zheng
  This file is used for declaring struct for config file
  All method is used in other files
**/
package Local

import "strconv"

type ServerInfo struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	LocalPort  int    `json:"local_port"`
	Password   string `json:"password"`
	Timeout    int    `json:"timeout"`
	UserName   string `json:"username"`
}
/**
  Simple getter for server addr
**/
func (s ServerInfo) GetServerAddr() string {
	return s.Server + ":" + strconv.Itoa(s.ServerPort)
}
/**
  Simple getter for local addr
**/
func (s ServerInfo) GetLocalAddr() string {
	return "127.0.0.1:" + strconv.Itoa(s.LocalPort)
}
/**
  Simple getter for UserName
**/
func (s ServerInfo) GetUserName() string {
	return s.UserName
}
/**
  Simple getter for User Password
**/
func (s ServerInfo) GetPassword() string {
	return s.Password
}
