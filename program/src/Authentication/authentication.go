/**
  Author: JiaCheng Yang && Wenkai Zheng
  This file is used for authentication
  It has the userPasswordMap struct
  All constants is used in other files
**/
package Authentication

import (
	"Core"
	"FileParser"
	"Logging"
	"crypto/sha512"
	"fmt"
	"strings"
)
/**
  userPasswordMap struct will have 
  a map to store user name and password
  a bool to check load CSV or not
**/
type userPasswordMap struct {
	userPassword map[string]string
	loaded       bool
}
/**
  This function will load data from CSV 
  And then save them into map
  For future use
**/
func (s *userPasswordMap) Add(args ...interface{}) {
	str, ok := args[0].([]string)
	if !ok {
		Logging.ErrorLogger.Fatal("for unknown reason, fail to parse elements in csv")
	}
	if len(str) != 2 {
		Logging.ErrorLogger.Fatal("csv file contains more than 2 elements")
	}
	s.userPassword[strings.TrimSpace(str[0])] = strings.TrimSpace(str[1])
}
/**
  default construtor for map
**/
var record = userPasswordMap{make(map[string]string), false}
/**
   This function simply load CSV
**/
func LoadCSV(fileName string) {
	Logging.NormalLogger.Println("going to load CSV")
	if !record.loaded {
		FileParser.GetCSV(fileName, &record)
		record.loaded = true
	}
	Logging.NormalLogger.Println("finish loading CSV")
}
/**
   This function verify the user exists
   And we also need to check they can map to each other
   if user name and password is not matching,
   server won't establish any connection
**/
func Verify(username, password string) (bool, error) {
	Logging.NormalLogger.Println("going to verify given username and password")
	if !record.loaded {
		return false, nil //todo make a error
	}
	value, ok := record.userPassword[username]
	if ok && password == value {
		Logging.NormalLogger.Println("user login")
	} else {
		Logging.NormalLogger.Println("wrong username or password")
	}
	return ok && password == value, nil
}
/**
   Run specific algorithm 
   And takes couple strings
   Generate an encoded string
**/
func addSalt(s, salt1, salt2 string) string {
	return salt1 + s + salt2
}
/**
   Convert byte array to hex strng format
**/
func convert2Hex(arr []byte) string {
	return fmt.Sprintf("%X", arr)
}
/**
   Call helper function with running
   Specific encryption algorithm
   And our password will be encoded
   For future use
**/
func EncodePassword(password string) string {
	password = addSalt(password, "dlrC", "Ofsc")
	sha := sha512.New()
	sha.Write(Core.ConvertStringTOByte(password))
	return convert2Hex(sha.Sum(nil))
}
/**
   Call helper function with running
   Specific encryption algorithm
   And our username will be encoded
   For future use
**/
func EncodeUsername(username string) string {
	username = addSalt(username, "Bdho", "X643")
	sha := sha512.New()
	sha.Write(Core.ConvertStringTOByte(username))
	return convert2Hex(sha.Sum(nil))
}
