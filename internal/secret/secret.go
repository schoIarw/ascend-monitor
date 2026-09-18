package secret

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const prefix = "v1:"

// GenerateKey creates a fresh 256-bit AES key without replacing any existing file.
func GenerateKey(path string) error {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(key)); err != nil {
		return err
	}
	return f.Sync()
}

func LoadKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect key file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("key must be a regular file with permission 0600 or stricter (no group/other access)")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(content)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("key file must contain a base64-encoded 32-byte key")
	}
	return key, nil
}

func fieldAAD(field string) ([]byte, error) {
	switch field {
	case "user", "password":
		return []byte("ascend-monitor:v1:" + field), nil
	default:
		return nil, errors.New("field must be user or password")
	}
}

func Encrypt(key []byte, field, plaintext string) (string, error) {
	aad, err := fieldAAD(field)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	data := gcm.Seal(nonce, nonce, []byte(plaintext), aad)
	return prefix + base64.StdEncoding.EncodeToString(data), nil
}

func Decrypt(key []byte, field, ciphertext string) (string, error) {
	aad, err := fieldAAD(field)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(ciphertext, prefix) {
		return "", errors.New("invalid credential format: expected v1:")
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertext, prefix))
	if err != nil {
		return "", errors.New("invalid credential encoding")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize()+gcm.Overhead() {
		return "", errors.New("credential ciphertext is too short")
	}
	value, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], aad)
	if err != nil {
		return "", errors.New("credential decrypt failed: wrong key, field, or damaged ciphertext")
	}
	return string(value), nil
}

// ReadSecret prevents terminal echo using stty; piped stdin is accepted for automation.
// Do not pass plaintext as CLI args or export plaintext into persistent env files.
func ReadSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		off := exec.Command("stty", "-echo")
		off.Stdin = os.Stdin
		if err := off.Run(); err != nil {
			return "", fmt.Errorf("disable terminal echo: %w", err)
		}
		defer func() {
			on := exec.Command("stty", "echo")
			on.Stdin = os.Stdin
			_ = on.Run()
			fmt.Fprintln(os.Stderr)
		}()
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if err == io.EOF && line == "" {
		return "", errors.New("no input")
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}
