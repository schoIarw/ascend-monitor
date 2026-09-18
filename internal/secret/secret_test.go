package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyEncryptionAndProtection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.key")
	if err := GenerateKey(path); err != nil {
		t.Fatal(err)
	}
	if err := GenerateKey(path); err == nil {
		t.Fatal("key file unexpectedly overwritten")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("wrong permissions %o", info.Mode().Perm())
	}
	key, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	user, err := Encrypt(key, "user", "ascen_writer")
	if err != nil {
		t.Fatal(err)
	}
	password, err := Encrypt(key, "password", "secret:with/@!")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(password, "secret") {
		t.Fatal("plaintext leaked into ciphertext")
	}
	got, err := Decrypt(key, "password", password)
	if err != nil || got != "secret:with/@!" {
		t.Fatalf("decrypt got %q error %v", got, err)
	}
	if _, err := Decrypt(key, "user", password); err == nil {
		t.Fatal("field swap was accepted")
	}
	if _, err := Decrypt(key, "password", user); err == nil {
		t.Fatal("field swap user was accepted")
	}
	corrupted := password[:len(password)-2] + "ab"
	if _, err := Decrypt(key, "password", corrupted); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("insecure key file accepted")
	}
}
