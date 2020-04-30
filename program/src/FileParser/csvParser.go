/**
  Author: JiaCheng Yang && Wenkai Zheng
  This file is used for getting entry form CSV
  For future use
**/
package FileParser

import (
	"Logging"
	"encoding/csv"
	"io"
	"os"
)
/**
   Simple interface for adding method 
**/
type addable interface {
	Add(...interface{})
}
/**
  This function will read CSV line by line and add it to interface
**/
func GetCSV(fileName string, record addable) {
	f, err := os.Open(fileName)
	if err != nil {
		Logging.NormalLogger.Println("cannot open " + fileName)
		Logging.ErrorLogger.Fatal(err)
	}

	reader := csv.NewReader(f)
	for {
		result, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			Logging.NormalLogger.Println("encounter error while reading " + fileName)
			Logging.ErrorLogger.Fatal(err)
		}

		record.Add(result)
	}
}
