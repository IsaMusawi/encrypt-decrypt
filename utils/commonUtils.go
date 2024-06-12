package utils

import (
	"encoding/json"
)

func Aes256Encrypt(data interface{}, secret, salt string, iteration, keySize int) (string, error) {
	// secretbytes := []byte(secret)
	// saltbytes := []byte(salt)
	// key := []byte("399cbf0de75d24bc2cb7396e5e9c4e72c34adb4f089bb228459363e1b6efc310") //GenerateKey(secretbytes, saltbytes, iteration, keySize)
	// iv := []byte(secret)

	// datae := fmt.Sprintf("%v", data)
	// fmt.Println(data)

	// key := GenerateKey([]byte(secret), []byte(salt), iteration, keySize)
	// keybytes, err := hex.DecodeString(key)
	// if err != nil {
	// 	return "", err
	// }
	// fmt.Println(key)
	// keybytes, err := hex.DecodeString(key)
	// if err != nil {
	// 	return "", err
	// }

	// jsonData, err := json.Marshal(data)
	// if err != nil {
	// 	return "", err
	// }

	// encryptData, err := EncryptAes256(string(jsonData), string(keybytes), 1)

	encryptData, err := encryptFromJavaCode(data, secret, salt, iteration, keySize)
	if err != nil {
		return "", err
	}

	return encryptData, nil
}

func Aes256Decrypt(data string, secret, salt string, iteration, keySize int) (interface{}, error) {
	// key := generateKey(secret, salt, iteration, keySize)
	// iv := secret[:aes.BlockSize]

	// decryptData, err := decrypt(data, key, iv)
	// if err != nil {
	// 	return "", err
	// }

	// return decryptData, nil

	// ciphertext, err := base64.StdEncoding.DecodeString(data)
	// if err != nil {
	// 	return nil, err
	// }

	// encrypt, err := DesDecryption(key, iv, ciphertext)
	// if err != nil {
	// 	return nil, err
	// }

	encrypt, err := decryptFromJavaCode(data, secret, salt, iteration, keySize)
	if err != nil {
		return nil, err
	}

	maps := make(map[string]interface{}, 0)

	err = json.Unmarshal(encrypt, &maps)
	if err != nil {
		return nil, err
	}
	return maps, nil
}
