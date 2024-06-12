package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	pad "github.com/zenazn/pkcs7pad"
)

func encryptFromJavaCode(data interface{}, secret, salt string, iteration, keysize int) (string, error) {
	// saltBytes, err := base64.StdEncoding.DecodeString(salt)
	// if err != nil {
	// 	return "", err
	// }

	// secretBytes, err := base64.StdEncoding.DecodeString(secret)
	// if err != nil {
	// 	return "", err
	// }

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	saltBytes := []byte(salt)
	secretBytes := []byte(secret)

	keys := GenerateKey(secretBytes, saltBytes, iteration, keysize)

	keyByte, err := hex.DecodeString(keys)
	if err != nil {
		return "", err
	}
	fmt.Println(keys)
	fmt.Println(keyByte)

	block, err := aes.NewCipher(keyByte)
	if err != nil {
		return "", err
	}

	// Initialize IV
	iv := secretBytes[:aes.BlockSize]
	// iv := make([]byte, aes.BlockSize)
	// if _, err := rand.Read(iv); err != nil {
	// 	return "", err
	// }

	// Pad plaintext
	// paddedText := PKCS5Padding(jsonData, 16)

	paddedText := pad.Pad(jsonData, aes.BlockSize)

	// Encrypt the message
	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)

	// Encode the encrypted text to base64
	// encodedIV := base64.StdEncoding.EncodeToString(iv)
	encryptedText := hex.EncodeToString(ciphertext)
	// encryptedText := fmt.Sprintf("%s%s", encodedIV, encryptedCipherText)

	return encryptedText, nil

}

func decryptFromJavaCode(encryptData, secret, salt string, iteration, keysize int) ([]byte, error) {
	// saltBytes, err := base64.StdEncoding.DecodeString(salt)
	// if err != nil {
	// 	return nil, err
	// }

	// secretBytes, err := base64.StdEncoding.DecodeString(secret)
	// if err != nil {
	// 	return nil, err
	// }

	saltBytes := []byte(salt)
	secretBytes := []byte(secret)

	key := GenerateKey(secretBytes, saltBytes, iteration, keysize)

	chipertext, err := base64.StdEncoding.DecodeString(encryptData)
	// chipertext, err := hex.DecodeString(encryptData)
	if err != nil {
		return nil, errors.New("invalid base64 encoded data")
	}

	keybyte, err := hex.DecodeString(key)
	if err != nil {
		return nil, errors.New("invalid key encoded data")
	}

	block, err := aes.NewCipher(keybyte)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	iv := []byte(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create iv: %w", err)
	}

	origData := make([]byte, len(chipertext))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(origData, chipertext)

	outData := PKCS5UnPadding(origData)

	return outData, nil
}

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func derivedKeyFromJavaCode(secret, salt []byte, iteration, keySize int) []byte {
	hashser := sha1.New()
	var key []byte
	for i := 0; i < iteration; i++ {
		hashser.Reset()
		hashser.Write(secret)
		hashser.Write(salt)
		key = append(key, hashser.Sum(nil)...)
	}
	return key[:keySize]
}
