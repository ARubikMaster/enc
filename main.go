package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		println("Please specify a valid filename and command")
		return
	}

	input := os.Args[2]
	var file string

	if filepath.IsAbs(input) {
		file = input
	} else {
		currentDir, err := os.Getwd()
		if err != nil {
			fmt.Println("Error getting current directory:", err)
			return
		}
		file = filepath.Join(currentDir, input)
	}

	_, err := os.Stat(file)
	if err != nil {
		fmt.Println("Error stating file:", err)
		return
	}

	if os.Args[1] == "encrypt" {
		encryptFile(getFileContent(file), file)
	} else if os.Args[1] == "decrypt" {
		decryptFile(getFileContent(file))
	}
}

func getFileContent(file string) string {
	fileContent, err := os.ReadFile(file)

	if err != nil {
		fmt.Println("Error reading file:", err)
		return ""
	}

	return string(fileContent)
}

func writeFileContent(file string, content string) {
	err := os.WriteFile(file, []byte(content), 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}
}

func Sha256Hash(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// Stolen from https://bruinsslot.jp/post/golang-crypto/
func Encrypt(key, data []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return ciphertext, nil
}

func Decrypt(key, ciphertext []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func encryptFile(content string, filename string) {
	fmt.Print("Set password for this file (no spaces): ")
	var password string
	fmt.Scanln(&password)
	password = strings.TrimSpace(password)

	relativeFilename := filepath.Base(filename)

	hashedKey := sha256.Sum256([]byte(password))

	encryptedContent, err := Encrypt(hashedKey[:], []byte(content))
	if err != nil {
		fmt.Println("Error encrypting file:", err)
		return
	}

	encoded := base64.StdEncoding.EncodeToString(encryptedContent)

	fileContent := fmt.Sprintf("%s\n%s", relativeFilename, encoded)
	writeFileContent(filename+".enc", fileContent)
}

func decryptFile(content string) {
	fmt.Print("What is this files password: ")
	var password string
	fmt.Scanln(&password)
	password = strings.TrimSpace(password)

	lines := strings.Split(content, "\n")

	if len(lines) < 2 {
		fmt.Println("Provided file is not valid")
		return
	}

	fileName := lines[0]

	encoded := strings.Join(lines[1:], "\n")
	decodedContent, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
		return
	}

	hashedKey := sha256.Sum256([]byte(password))
	decryptedContent, err := Decrypt(hashedKey[:], decodedContent)
	if err != nil {
		fmt.Println("The entered password is incorrect.")
		return
	}

	writeFileContent(fileName, string(decryptedContent))
}
