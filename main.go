package main

import (
	"encrypt-decrypt-utils/utils"
	"fmt"
)

var (
	salt      = []byte("uxKqTsYSkDVeXxre")
	secret    = []byte("Faw8Qm8Ttwgf2Cc3")
	iteration = 16
	keySize   = 32
	tesdata = "dTVtaUN5alRLMjRyS0VFZ2krNUgwNHdKUnlFczBHL1R0dzlQVS93NnRFamNpcUdDMnlaUjU0U0p0QWs0SHJzT2lxd2hBSXEySEFxTnlRZlJ1Q0ZhSy9MTlh0QkRySU9KbVdsS0ZCSStPVnpleUR4Zm10cXd4dFNwNEJHTWN0djZLaG1KNmpJOVl6K292UjA1VGExVzF6bVVkbWwwY1NZRWVIVmhIMjRIVDhPcEI5Sy9WdmNncGgwQWlOYnJUb0F0a1pUbExJOXppaFZNNURHeEl0cE5KYjhmeHNzVktoNUtGQTJzRndvK0x2TjRTbldsODlmYUtCYkRmV1VJai8rZDFvclUyRUhrSzY1eFVPdHEzTjYwbGlqN1Q4WkNJWlN2NDRpZ3pybEV1MTBvQjlFMkZpRVVsUDdPOVlmcE1RaGw="
)

func main() {
	data := "TEST"

	encrypted, err := utils.Aes256Encrypt(data, secret, salt, iteration, keySize)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Printf("Encrypted: %s\n", encrypted)

	decrypted, err := utils.Aes256Decrypt(tesdata, secret, salt, iteration, keySize)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Printf("Encrypted: %s\n", decrypted)
}