package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

func generateKey(secret, salt []byte, iteration, keySize int) []byte {
	return pbkdf2.Key(secret, salt, iteration, keySize, sha256.New)
}

func paddingData(data []byte, blocksize int) []byte {
	padding := blocksize - len(data)%blocksize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func upPaddingData(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("data is empty")
	}

	padLength := int(data[length-1])
	if padLength > blockSize || padLength == 0 {
		return nil, errors.New("Invalid unPadding")
	}

	paddedPart := data[length - padLength:]
	for _, v := range paddedPart {
		if int(v) < padLength {
			return nil, errors.New("Invalid unPadding part")
		}
	}
	
	return data[:length- padLength], nil
}

func encrypt(data interface{}, key, iv []byte) (string, error) {
	
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	//create aes chiper
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// add padding to plain text
	paddedData := paddingData(jsonData, aes.BlockSize)

	//create a cbc mode
	mode := cipher.NewCBCEncrypter(block, iv)
	
	//encrypt data
	ciphertext := make([]byte, len(paddedData))
	mode.CryptBlocks(ciphertext, paddedData)

	encode := base64.StdEncoding.EncodeToString(ciphertext)

	return encode, nil
}

func decrypt(encryptedData string, key, iv []byte) (interface{}, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	//create aes chiper
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//create cbc
	mode := cipher.NewCBCDecrypter(block, iv)

	//decrypt data
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	//remove padding
	uppaddedData, err := upPaddingData(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	var data interface{}
	err = json.Unmarshal(uppaddedData, &data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func Aes256Encrypt(data interface{}, secret, salt []byte, iteration, keySize int) (string, error) {
	key := generateKey(secret, salt, iteration, keySize)
	iv := secret[:aes.BlockSize]

	encryptData, err := encrypt(data, key, iv)
	if err != nil {
		return "", err
	}

	return encryptData, nil
}

func Aes256Decrypt(data string, secret, salt []byte, iteration, keySize int) (interface{}, error) {
	key := generateKey(secret, salt, iteration, keySize)
	iv := secret[:aes.BlockSize]

	decryptData, err := decrypt(data, key, iv)
	if err != nil {
		return "", err
	}

	return decryptData, nil
}