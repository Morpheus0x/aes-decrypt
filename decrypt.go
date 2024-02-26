package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/ini.v1"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: program input_file output_file key_file")
		return
	}

	inputFilePath := os.Args[1]
	outputFilePath := os.Args[2]
	keyFilePath := os.Args[3]

	// Read key from the INI file
	cfg, err := ini.Load(keyFilePath)
	if err != nil {
		fmt.Println("Error reading key file:", err)
		return
	}

	// Get the key value from the INI file
	key := []byte(cfg.Section("").Key("key").String())

	// Read ciphertext from the input file
	ciphertext, err := ioutil.ReadFile(inputFilePath)
	if err != nil {
		fmt.Println("Error reading input file:", err)
		return
	}

	// Extract nonce from the ciphertext
	nonceSize := 12
	if len(ciphertext) < nonceSize {
		fmt.Println("Ciphertext too short")
		return
	}
	// nonce := ciphertext[len(ciphertext)-nonceSize:]
	// ciphertext = ciphertext[:len(ciphertext)-nonceSize]
	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error creating AES cipher:", err)
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Error creating GCM cipher:", err)
		return
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println("Error decrypting ciphertext:", err)
		return
	}

	// Write the decrypted plaintext to the output file
	err = ioutil.WriteFile(outputFilePath, plaintext, 0644)
	if err != nil {
		fmt.Println("Error writing output file:", err)
		return
	}

	fmt.Println("Decryption successful. Output written to", outputFilePath)
}
