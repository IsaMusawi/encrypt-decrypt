package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

func GenerateKey(secret, salt []byte, iteration, keySize int) string {
	key := pbkdf2.Key(secret, salt, iteration, keySize, sha1.New)
	return hex.EncodeToString(key)
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

	paddedPart := data[length-padLength:]
	for _, v := range paddedPart {
		if int(v) < padLength {
			return nil, errors.New("Invalid unPadding part")
		}
	}

	return data[:length-padLength], nil
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
	// body := bytes.TrimPrefix([]byte(encryptedData), []byte("\xef\xbb\xbf"))
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
	// uppaddedData, err := upPaddingData(plaintext, 8)
	// if err != nil {
	// 	return nil, err
	// }

	// fmt.Println(plaintext)
	// uppaddedData := pkcs5UnPadding(plaintext)
	// fmt.Println(uppaddedData)

	var data interface{}
	err = json.Unmarshal(plaintext, &data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func DesDecryption(key, iv, cipherText []byte) ([]byte, error) {

	block, err := des.NewCipher(key)

	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func generateRandIV(secret string) ([]byte, error) {
	iv := []byte(secret)[:aes.BlockSize]
	// _, err := rand.Read(iv)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to generate random IV: %w", err)
	// }
	return iv, nil
}
