/**
  Author: JiaCheng Yang && Wenkai Zheng
  This file is used for config file parser
  It reads config json file byte array
  For future use
**/
package FileParser

import (
	"Logging"
	"encoding/json"
	"io/ioutil"
	"os"
)
/**
  This function simply read json into a byte array
**/
func readJson(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(f)
}
/**
   This function will save all info from json to interface
**/
func GetJasonConfig(configPATH string, c interface{}) error {
	content, err := readJson(configPATH)
	if err != nil {
		Logging.NormalLogger.Println("Cannot open " + configPATH + " : " + err.Error())
		return err
	}
	err = json.Unmarshal([]byte(content), c)
	if err != nil {
		Logging.NormalLogger.Println("ERROR: ", err.Error())
		return err
	}
	return nil

}
