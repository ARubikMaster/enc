// This is a simple program that encryps/decrypts files
// This implementation is probably the worst one ever written, but it's a learning experience :P

// The encrypted file will be in this format:
// <filename>\n<encrypted content>\n

// To use this tool, you can do the following;
// enc encrypt <filename>
// enc decrypt <filename.enc>

// I did use ChatGPT to help me debug
// Anyways if you want to contribute feel free to do so

// This is literally just a wrapper for the built in crypto functions lmao

package main

// Imports
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

// Main function
func main() {
	// Checks if the user entered the good amount of arguments
	if len(os.Args) != 3 {
		println("Please specify a valid filename and command")
		return
	}

	// Gets the file
	input := os.Args[2]
	var file string

	// Checks if the file path is absolute
	if filepath.IsAbs(input) {
		file = input
	} else {
		// Gets the current directory
		currentDir, err := os.Getwd()
		if err != nil {
			fmt.Println("Error getting current directory:", err)
			return
		}
		// Joins the current directory with the input
		file = filepath.Join(currentDir, input)
	}

	// Checks if the file exists
	_, err := os.Stat(file)
	if err != nil {
		fmt.Println("Error stating file:", err)
		return
	}

	// Checks the command the user entered
	if os.Args[1] == "encrypt" {
		// Calls the encryptFile function
		encryptFile(getFileContent(file), file)
	} else if os.Args[1] == "decrypt" {
		// calls the decryptFile function
		decryptFile(getFileContent(file))
	}
}

// getFileContent returns the content of a file as a string
//
// Parameter: file: The path to the file
//
// Returns: The content of the file as a string
func getFileContent(file string) string {
	// Reads the file content as a list of bytes
	fileContent, err := os.ReadFile(file)

	if err != nil {
		fmt.Println("Error reading file:", err)
		return ""
	}

	// Converts the bytes to a string and returns it
	return string(fileContent)
}

// writeFileContent writes a string of content to a file
//
// Parameter: file: The path to the file
//
// Parameter: content: The content to write
//
// Returns: Nothing
func writeFileContent(file string, content string) {
	// Writes the content to the file
	err := os.WriteFile(file, []byte(content), 0644)

	// Checks if there was an error
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}
}

// Sha256Hash returns the SHA256 hash of a string
//
// Parameter: s: The string to hash
//
// Returns: The SHA256 hash of the string
func Sha256Hash(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// Encrypt encrypts a string using AES-256-GCM
//
// Taken from https://bruinsslot.jp/post/golang-crypto/
//
// Parameter: key: The encryption key
//
// Parameter: data: The data to encrypt
//
// Returns: The encrypted data as a byte array
//
// Returns: An error
func Encrypt(key, data []byte) ([]byte, error) {
	// Creates a new block cipher
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Creates a new GCM
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	// Creates a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypts the data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Returns the encrypted data
	return ciphertext, nil
}

// Decrypt decrypts a string using AES-256-GCM
//
// Parameter: key: The decryption key
//
// Parameter: data: The data to decrypt
//
// Returns: The decrypted data as a byte array
//
// Returns: An error
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	// Creates a new block cipher
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Creates a new GCM
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	// Checks if the ciphertext is valid
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Splits the ciphertext
	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]

	// Decrypts the ciphertext
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, err
	}

	// Returns the decrypted data
	return plaintext, nil
}

// encryptFile encrypts a file
//
// Parameter: content: The content of the file
//
// Parameter: filename: The name of the file
//
// Returns: Nothing
func encryptFile(content string, filename string) {
	// Asks the user for a password
	fmt.Print("Set password for this file (no spaces): ")

	// Reads the password
	var password string
	fmt.Scanln(&password)

	// Removes leading and trailing spaces
	password = strings.TrimSpace(password)

	// Gets the relative path filename
	relativeFilename := filepath.Base(filename)

	// Hashes the password to fit the accepted (16 bit, 32 bit, etc) key lengths
	hashedKey := sha256.Sum256([]byte(password))

	// Encrypts the file
	encryptedContent, err := Encrypt(hashedKey[:], []byte(content))
	if err != nil {
		fmt.Println("Error encrypting file:", err)
		return
	}

	// Encodes the encrypted content
	encoded := base64.StdEncoding.EncodeToString(encryptedContent)

	// Writes the file
	fileContent := fmt.Sprintf("%s\n%s", relativeFilename, encoded)
	writeFileContent(filename+".enc", fileContent)
}

// decryptFile decrypts a file
//
// Parameter: content: The content of the file
//
// Returns: Nothing
func decryptFile(content string) {
	// Prompts the user for the password
	fmt.Print("What is this files password: ")

	// Reads the password
	var password string
	fmt.Scanln(&password)
	password = strings.TrimSpace(password)

	// Splits the content
	lines := strings.Split(content, "\n")

	// Checks if the file is valid
	if len(lines) < 2 {
		fmt.Println("Provided file is not valid")
		return
	}

	// Gets the file name to use as the output file name
	fileName := lines[0]

	// Decodes the content
	encoded := strings.Join(lines[1:], "\n")
	decodedContent, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
		return
	}

	// Hashes the password
	hashedKey := sha256.Sum256([]byte(password))

	// Decrypts the file
	decryptedContent, err := Decrypt(hashedKey[:], decodedContent)
	if err != nil {
		fmt.Println("The entered password is incorrect.")
		return
	}

	// Writes the file to the output file name specified in the first line
	writeFileContent(fileName, string(decryptedContent))
}
