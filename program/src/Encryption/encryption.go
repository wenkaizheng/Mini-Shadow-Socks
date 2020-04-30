/**
  Author: JiaCheng Yang && Wenkai Zheng
  This file is used for generating encrypted table
  For future use
**/
package Encryption

import (
	"math/rand"
	"time"
)
/**
  Tables truct will hold encode and decode table
**/
type Table struct {
	// Encode is ascii
	// Decode is byte
	encode [256]byte
	decode [256]byte
}
/**
  This function will generate encode and decode table
  From random key set
  We save encode table as exactly from random key set
  And we use char's ASCI value as key to save as index value
  For example 'A' to 'a' so 65 to 97 for encode
  So we save 97 as 65 for decode 
**/
func NewEncryptionTable() *Table {
	rand.Seed(time.Now().Unix())
	var values [256]byte
	keys := generateKeys()
	for index, key := range keys {
		keys[index] = key
		values[key] = byte(index)
	}
	return &Table{keys, values}
}
/**
   This function will generate empty encode and decode table
**/
func NewEmptyEncryptionTable() *Table {
	var values [256]byte
	var keys [256]byte
	for i := 0; i < 256; i++ {
		values[i] = byte(0)
		keys[i] = byte(0)
	}
	return &Table{keys, values}

}
/**
   This function generate a random key set
   key 0 - 255
   value : random ascii number
   key = value is not allowed
**/
func generateKeys() [256]byte {
	randomArray := rand.Perm(256)
	var keys [256]byte
	for index, value := range randomArray {
		if index == value {
			return generateKeys()
		} else {
			keys[index] = byte(value)
		}
	}
	return keys
}
/**
   Simple return encode value from encode table
**/
func (t *Table) Encode(keys []byte) []byte {
	// Encode this byte array need jiacheng to change
	values := make([]byte, len(keys))
	for index, value := range keys {
		values[index] = t.encode[value]
	}
	return values
}
/**
   Simple return decode value from encode table
**/
func (t *Table) Decode(values []byte) []byte {
	//Decode this byte array need jiacheng to change
	keys := make([]byte, len(values))
	for index, value := range values {
		keys[index] = t.decode[value]
	}
	return keys
}
/**
   Simple getter for encode table
**/
func (t *Table) GetEncodeArr() []byte {
	return t.encode[:]
}
/**
   Simple getter for encode table
**/
func (t *Table) GetDecodeArr() []byte {
	return t.decode[:]
}
/**
   Simple setter for encode table
**/
func (t *Table) SetEncodeArr(copy []byte) {
	for i := 0; i < 256; i++ {
		t.encode[i] = copy[i]
	}
}
/**
   Simple setter for decode table
**/
func (t *Table) SetDecodeArr(copy []byte) {
	for i := 0; i < 256; i++ {
		t.decode[i] = copy[i]
	}
}
