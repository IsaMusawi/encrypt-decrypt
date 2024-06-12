package main

import (
	"encrypt-decrypt-utils/utils"
	"fmt"
)

type Lov struct {
	id           string
	value        string
	anotherValue string
}

var (
	// salt   = []byte("uxKqTsYSkDVeXxre")
	// secret = []byte("Faw8Qm8Ttwgf2Cc3")
	salt      = "uxKqTsYSkDVeXxre" //"46617738516d38547477676632436333" //
	secret    = "Faw8Qm8Ttwgf2Cc3" //"75784b71547359536b44566558787265" //
	iteration = 16
	keySize   = 32
	tesdata   = "S3cwZjlNa08vRFVJWlRWb29oSVJHYm1Uamw4elhBRklUSS9vT3ZmZHd5NzZrc2xNUDg1YStadHM5TEF3MEo4Kw=="
	tesinit   = "{\"id\":\"1\",\"value\":\"okkk\",\"anotherValue\":\"okkk\"}"
	// keyback    = "t9anjfa8mv42kss8t9anjfa8mv42kss8"
	keyangular = "399cbf0de75d24bc2cb7396e5e9c4e72c34adb4f089bb228459363e1b6efc310"
	tes        = map[string]interface{}{
		"id":             21594,
		"userId":         "DADANA",
		"nik":            900434,
		"name":           "DADAN AWALUDIN",
		"position_name":  "BUSINESS PROCESS ANALYST LEADER, SUPPORTING",
		"group_position": "JUNIOR MANAGER",
		"ouCode":         "HO",
		"department":     "BUSINESS PROCESS ANALYST DEPARTMENT",
	}

	tes2data = Lov{
		id:           "1",
		value:        "okkk",
		anotherValue: "okkk",
	}
)

func main() {
	// data := "TEST"

	key := utils.GenerateKey([]byte(secret), []byte(salt), iteration, keySize)
	// keystring := base64.StdEncoding.EncodeToString(key)
	fmt.Println(key)

	fmt.Println("\n===================================================================\n")

	// jsonData, err := json.Marshal(tes)
	// if err != nil {
	// 	fmt.Println("error encrypt")
	// }

	// encryptedData2, err := utils.EncryptAes256(string(jsonData), key, 2)
	// fmt.Println(encryptedData2)

	fmt.Println("\n===================================================================\n")

	encrypted, err := utils.Aes256Encrypt(tes2data, secret, salt, iteration, keySize)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Printf("Encrypted: %s\n", encrypted)

	fmt.Println("\n===================================================================\n")

	// decrypted, err := utils.Aes256Decrypt(encrypted, secret, salt, iteration, keySize)
	// if err != nil {
	// 	fmt.Println(err.Error())
	// }
	fmt.Println("Key Valid: ", keyangular == key)
	fmt.Println("Encrypted Valid: ", encrypted == tesdata)
	fmt.Println(tesdata)
	fmt.Println(encrypted)
}
