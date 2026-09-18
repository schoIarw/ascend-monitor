package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionAndValidation(t *testing.T) {
	if version != "0.1.0" {
		t.Fatalf("unexpected version: %s", version)
	}
	for _, args := range [][]string{{"--mode", "invalid"}, {"--color", "invalid"}, {"--tail", "-1"}, {"--ip", "not-an-ip"}} {
		if err := run(args); err == nil {
			t.Errorf("accepted invalid flags: %v", args)
		}
	}
}

func TestPlainLogInput(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sample.log")
	content := "2026-09-18T04:07:30.000000002Z (APIServer pid=1) INFO 09-18 04:07:30 [loggers.py:310] Engine 000: Avg prompt throughput: 5983.1 tokens/s, Avg generation throughput: 13.7 tokens/s, Running: 4 reqs, Waiting: 1 reqs, GPU KV cache usage: 64.6%, Prefix cache hit rate: 24.0%\n"
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = original; reader.Close() }()
	if err := run([]string{"--input", file, "--follow=false", "--ip", "192.168.10.25"}); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	buf := make([]byte, 8192)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	out := string(buf[:n])
	if !strings.Contains(out, "10.25") || !strings.Contains(out, "W:1") || strings.Contains(out, "\x1b[") {
		t.Fatalf("invalid redirected output: %q", out)
	}
}
