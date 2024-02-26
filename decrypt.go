package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: program input_file output_file")
		return
	}

	inputFilePath := os.Args[1]
	outputFilePath := os.Args[2]

	key := []byte("AES256Key-32Characters1234567890")
	nonce, _ := hex.DecodeString("bb8ef84243d2ee95a41c6c57")

	// Read ciphertext from the input file
	ciphertext, err := ioutil.ReadFile(inputFilePath)
	if err != nil {
		fmt.Println("Error reading input file:", err)
		return
	}

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

	// Nonce is not needed here as it's assumed to be part of the ciphertext
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
