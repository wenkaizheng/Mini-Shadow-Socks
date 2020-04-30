/**
  Author: JiaCheng Yang && Wenkai Zheng
  This file is used for preparing differnt types of loger
  For future use in all file almost
**/
package Logging

import (
	"log"
	"os"
)
/**
  We have two logger one is for normal other is for error
**/
var NormalLogger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
var ErrorLogger = log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lshortfile)
