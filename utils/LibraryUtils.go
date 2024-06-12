package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

/**
 * @author josepht
 * Encrypt AES256, comply with Oracle DBMS Crypto
 */
func EncryptAes256(dataPayload string, password string, mode int) (string, error) {
	block, err := aes.NewCipher([]byte(password))

	if err != nil {
		fmt.Println("key error1", err)
	}

	if dataPayload == "" {
		fmt.Println("plain content empty")
	}

	ecb := cipher.NewCBCEncrypter(block, make([]byte, 16))
	content := []byte(dataPayload)
	content = PKCS5PaddingUtils(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)

	if mode == 1 {
		return base64.StdEncoding.EncodeToString(crypted), nil
	} else if mode == 2 {
		return strings.ToUpper(hex.EncodeToString(crypted)), nil
	}

	return "", fmt.Errorf("Mode is not standard")
}

/**
 * @author josepht
 * Decrypt AES256, comply with Oracle DBMS Crypto
 * Return empty string when payload is empty
 */
func DecryptAes256(dataPayload string, password string, mode int) (string, error) {
	if dataPayload == "" {
		return "", nil
	}
	block, err := aes.NewCipher([]byte(password))

	if err != nil {
		return "", fmt.Errorf("key chipper is error : " + err.Error())
	}

	if dataPayload == "" {
		return "", fmt.Errorf("plain content empty")
	}

	var ciphertext []byte
	var errDecode error

	if mode == 1 {
		ciphertext, errDecode = base64.StdEncoding.DecodeString(dataPayload)
	} else if mode == 2 {
		ciphertext, errDecode = hex.DecodeString(dataPayload)
	} else {
		return "", fmt.Errorf("Mode is not standard")
	}

	if errDecode != nil {
		return "", fmt.Errorf("decode input text is error. error: " + errDecode.Error())
	}
	if len(ciphertext)%block.BlockSize() != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	ecb := cipher.NewCBCDecrypter(block, make([]byte, 16))
	ecb.CryptBlocks(ciphertext, ciphertext)

	cipherUnPad, errUnpad := PKCS5UnPaddingUtils(ciphertext)

	if errUnpad != nil {
		return "", fmt.Errorf(errUnpad.Error())
	}

	return string(cipherUnPad), nil
}

/**
 * @author josepht
 * PKCS5 Padding for Encryption
 */
func PKCS5PaddingUtils(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

/**
 * @author josepht
 * PKCS5 Unpadding for Decryption
 */
func PKCS5UnPaddingUtils(src []byte) ([]byte, error) {
	length := len(src)

	if length <= 0 {
		return nil, fmt.Errorf("invalid byte blob length: expecting > 0 having %d", length)
	}
	unpadding := int(src[length-1])
	delta := length - unpadding
	if delta < 0 {
		return nil, fmt.Errorf("invalid padding delta length: expecting >= 0 having %d", delta)
	}

	return src[:delta], nil
}
