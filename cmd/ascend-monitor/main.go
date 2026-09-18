package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/schoIarw/ascend-monitor/internal/monitor"
	"github.com/schoIarw/ascend-monitor/internal/secret"
	"github.com/schoIarw/ascend-monitor/internal/store"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "keygen":
			return keygen(args[1:])
		case "encrypt":
			return encrypt(args[1:])
		case "version", "-v", "--version":
			fmt.Println("ascend-monitor v" + version)
			return nil
		case "help", "-h", "--help":
			usage()
			return nil
		}
	}
	f := flag.NewFlagSet("ascend-monitor", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	mode := f.String("mode", "stdout", "stdout | mysql | both")
	match := f.String("match", "ascen", "substring to match docker container name or image")
	container := f.String("container", "", "explicit docker container ID or name")
	tail := f.Int("tail", 10, "number of existing Docker log lines to read")
	follow := f.Bool("follow", true, "follow new Docker log lines")
	input := f.String("input", "", "read lines from file, or - for stdin (instead of docker logs)")
	color := f.String("color", "auto", "auto | always | never")
	ip := f.String("ip", "", "optional host IPv4 override (useful with several NICs)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments; see --help")
	}
	if *mode != "stdout" && *mode != "mysql" && *mode != "both" {
		return errors.New("--mode must be stdout, mysql or both")
	}
	if *color != "auto" && *color != "always" && *color != "never" {
		return errors.New("--color must be auto, always or never")
	}
	if *tail < 0 {
		return errors.New("--tail cannot be negative")
	}
	if *ip == "" {
		*ip = monitor.LocalIPv4()
	}
	if *ip == "" {
		*ip = "-"
	}
	if *ip != "-" && monitor.IPTail(*ip) == "-" {
		return errors.New("--ip must be an IPv4 address")
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "-"
	}
	source := monitor.Source{Hostname: hostname, HostIP: *ip, IPTail: monitor.IPTail(*ip), ContainerID: "stdin", ContainerName: "stdin"}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var db *store.MySQL
	if *mode == "mysql" || *mode == "both" {
		db, err = store.Open(ctx)
		if err != nil {
			return err
		}
		defer db.Close()
	}
	if *input == "" {
		id, name, err := findContainer(ctx, *container, *match)
		if err != nil {
			return err
		}
		source.ContainerID, source.ContainerName = id, name
	}
	useColor := *color == "always" || (*color == "auto" && isTerminal(os.Stdout))
	if *mode != "mysql" {
		printHeader(useColor)
	}
	consume := func(line string) error {
		value, ok, err := monitor.Parse(line, source, time.Now())
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if *mode != "mysql" {
			printMetric(value, useColor)
		}
		if db != nil {
			return db.Write(ctx, value)
		}
		return nil
	}
	if *input != "" {
		var reader io.Reader
		if *input == "-" {
			reader = os.Stdin
		} else {
			file, err := os.Open(*input)
			if err != nil {
				return err
			}
			defer file.Close()
			reader = file
		}
		return scan(reader, consume)
	}
	return dockerLogs(ctx, source.ContainerID, *tail, *follow, consume)
}

func usage() {
	fmt.Fprintln(os.Stdout, `ascend-monitor - vLLM metrics from Docker logs
Usage:
  ascend-monitor [--mode stdout|mysql|both] [--match ascen] [--tail 10]
  ascend-monitor --version
  ascend-monitor --input sample.log --follow=false
  ascend-monitor keygen --key-file /etc/ascend-monitor/credentials.key
  ascend-monitor encrypt --key-file /etc/ascend-monitor/credentials.key --field user|password
Options: --container ID|NAME, --ip IPv4, --color auto|always|never,
         --input - (stdin), --follow=false, --tail N
MySQL env: MYSQL_ADDR, MYSQL_DATABASE, MYSQL_TLS=required|disabled, MYSQL_TLS_CA_FILE,
           MYSQL_CRED_KEY_FILE, MYSQL_USER_ENC, MYSQL_PASSWORD_ENC`)
}

func keygen(args []string) error {
	f := flag.NewFlagSet("keygen", flag.ContinueOnError)
	file := f.String("key-file", "", "new key file path")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *file == "" || f.NArg() != 0 {
		return errors.New("keygen requires --key-file PATH")
	}
	if err := secret.GenerateKey(*file); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Key created; keep it separate from encrypted environment variables and back it up securely.")
	return nil
}
func encrypt(args []string) error {
	f := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	file := f.String("key-file", "", "AES key file path")
	field := f.String("field", "", "user or password")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *file == "" || (*field != "user" && *field != "password") || f.NArg() != 0 {
		return errors.New("encrypt requires --key-file PATH --field user|password")
	}
	key, err := secret.LoadKey(*file)
	if err != nil {
		return err
	}
	value, err := secret.ReadSecret("Enter MySQL " + *field + " (input hidden on TTY): ")
	if err != nil {
		return err
	}
	if value == "" {
		return errors.New("credential cannot be empty")
	}
	ciphertext, err := secret.Encrypt(key, *field, value)
	if err != nil {
		return err
	}
	if *field == "user" {
		fmt.Println("MYSQL_USER_ENC=" + ciphertext)
	} else {
		fmt.Println("MYSQL_PASSWORD_ENC=" + ciphertext)
	}
	return nil
}

func findContainer(ctx context.Context, explicit, match string) (string, string, error) {
	if explicit != "" {
		return explicit, explicit, nil
	}
	cmd := exec.CommandContext(ctx, "docker", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return "", "", errors.New("docker ps failed: check Docker installation and permissions")
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) == 3 && strings.Contains(strings.ToLower(fields[1]+" "+fields[2]), strings.ToLower(match)) {
			return fields[0], fields[2], nil
		}
	}
	return "", "", fmt.Errorf("no running Docker container matches %q (try --container NAME)", match)
}

func dockerLogs(ctx context.Context, id string, tail int, follow bool, consume func(string) error) error {
	args := []string{"logs", "--timestamps", "--tail", strconv.Itoa(tail)}
	if follow {
		args = append(args, "--follow")
	}
	args = append(args, id)
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(childCtx, "docker", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return errors.New("cannot start docker logs: check Docker installation and permissions")
	}
	lines := make(chan string, 256)
	scanErrors := make(chan error, 2)
	var wg sync.WaitGroup
	for _, r := range []io.Reader{stdout, stderr} {
		wg.Add(1)
		go func(reader io.Reader) {
			defer wg.Done()
			scanner := bufio.NewScanner(reader)
			scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
			for scanner.Scan() {
				select {
				case lines <- scanner.Text():
				case <-childCtx.Done():
					return
				}
			}
			if err := scanner.Err(); err != nil && childCtx.Err() == nil {
				scanErrors <- err
			}
		}(r)
	}
	go func() { wg.Wait(); close(lines); close(scanErrors) }()
	var consumeErr error
	for line := range lines {
		if consumeErr == nil {
			if err := consume(line); err != nil {
				consumeErr = err
				cancel()
			}
		}
	}
	waitErr := cmd.Wait()
	if consumeErr != nil {
		return consumeErr
	}
	if ctx.Err() != nil {
		return nil
	}
	for err := range scanErrors {
		if err != nil {
			return fmt.Errorf("read docker logs: %w", err)
		}
	}
	if waitErr != nil {
		return errors.New("docker logs exited with an error; check container ID and Docker permissions")
	}
	return nil
}

func scan(r io.Reader, consume func(string) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if err := consume(sc.Text()); err != nil {
			return err
		}
	}
	return sc.Err()
}
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
func printHeader(color bool) {
	y, reset := "", ""
	if color {
		y, reset = "\x1b[1;33m", "\x1b[0m"
	}
	fmt.Printf("%-9s %-15s %-12s %-12s %-9s %s%-9s%s %-10s %-10s\n", "IP", "TIME", "PROMPT", "GENERATE", "RUNNING", y, "WAITING", reset, "KV_CACHE", "PREFIX")
	fmt.Println(strings.Repeat("-", 100))
}
func printMetric(m monitor.Metric, color bool) {
	start, reset := "", ""
	if color {
		reset = "\x1b[0m"
		if m.Waiting > 0 {
			start = "\x1b[1;31m"
		} else {
			start = "\x1b[1;32m"
		}
	}
	fmt.Printf("%-9s %-15s %-12s %-12s %-9s %s%-9s%s %-10s %-10s\n",
		m.IPTail, m.LogTime, fmt.Sprintf("P:%.1f", m.PromptTPS), fmt.Sprintf("G:%.1f", m.GenerationTPS),
		fmt.Sprintf("R:%d", m.Running), start, fmt.Sprintf("W:%d", m.Waiting), reset,
		fmt.Sprintf("KV:%.1f%%", m.KVCachePct), fmt.Sprintf("PC:%.1f%%", m.PrefixHitPct))
}
