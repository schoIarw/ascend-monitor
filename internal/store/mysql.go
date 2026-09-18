package store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	driver "github.com/go-sql-driver/mysql"
	"github.com/schoIarw/ascend-monitor/internal/monitor"
	"github.com/schoIarw/ascend-monitor/internal/secret"
)

var dbNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)

const createTable = `CREATE TABLE IF NOT EXISTS vllm_metrics (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 event_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 event_time_utc DATETIME(6) NOT NULL COMMENT 'Docker log timestamp, UTC',
 log_time VARCHAR(14) NOT NULL COMMENT 'Application MM-DD HH:MM:SS',
 host_name VARCHAR(255) NOT NULL,
 host_ip VARCHAR(45) NOT NULL,
 ip_tail VARCHAR(7) NOT NULL,
 container_id VARCHAR(64) NOT NULL,
 container_name VARCHAR(255) NOT NULL,
 prompt_tps DOUBLE NOT NULL,
 generation_tps DOUBLE NOT NULL,
 running_reqs INT UNSIGNED NOT NULL,
 waiting_reqs INT UNSIGNED NOT NULL,
 gpu_kv_cache_pct DOUBLE NOT NULL,
 prefix_cache_hit_pct DOUBLE NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE KEY uk_event_hash (event_hash),
 KEY idx_event_time (event_time_utc),
 KEY idx_host_time (host_name, event_time_utc),
 KEY idx_waiting_time (waiting_reqs, event_time_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`

const insertSQL = `INSERT INTO vllm_metrics
(event_hash, event_time_utc, log_time, host_name, host_ip, ip_tail, container_id, container_name,
 prompt_tps, generation_tps, running_reqs, waiting_reqs, gpu_kv_cache_pct, prefix_cache_hit_pct)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE event_hash = event_hash`

type MySQL struct{ db *sql.DB }

func Open(ctx context.Context) (*MySQL, error) {
	keyPath := strings.TrimSpace(os.Getenv("MYSQL_CRED_KEY_FILE"))
	uEnc := os.Getenv("MYSQL_USER_ENC")
	pEnc := os.Getenv("MYSQL_PASSWORD_ENC")
	if keyPath == "" || uEnc == "" || pEnc == "" {
		return nil, errors.New("MYSQL_CRED_KEY_FILE, MYSQL_USER_ENC and MYSQL_PASSWORD_ENC are required")
	}
	key, err := secret.LoadKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load MySQL credential key: %w", err)
	}
	user, err := secret.Decrypt(key, "user", uEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt MySQL user: %w", err)
	}
	password, err := secret.Decrypt(key, "password", pEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt MySQL password: %w", err)
	}
	if user == "" || password == "" {
		return nil, errors.New("MySQL user/password must not be empty")
	}
	address := strings.TrimSpace(os.Getenv("MYSQL_ADDR"))
	if address == "" {
		address = "127.0.0.1:3306"
	}
	serverHost, _, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		return nil, errors.New("MYSQL_ADDR must be host:port, e.g. db.example.com:3306")
	}
	dbName := strings.TrimSpace(os.Getenv("MYSQL_DATABASE"))
	if dbName == "" {
		dbName = "ascend_monitor"
	}
	if !dbNamePattern.MatchString(dbName) {
		return nil, errors.New("MYSQL_DATABASE must begin with a letter and contain only letters, digits and underscores (max 64 chars)")
	}
	tlsMode := strings.TrimSpace(os.Getenv("MYSQL_TLS"))
	if tlsMode == "" {
		tlsMode = "required"
	}
	if tlsMode != "required" && tlsMode != "disabled" {
		return nil, errors.New("MYSQL_TLS must be required or disabled")
	}
	cfg := driver.NewConfig()
	cfg.User, cfg.Passwd = user, password
	cfg.Net, cfg.Addr, cfg.DBName = "tcp", address, dbName
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 5 * time.Second
	cfg.WriteTimeout = 5 * time.Second
	if tlsMode == "required" {
		if caFile := strings.TrimSpace(os.Getenv("MYSQL_TLS_CA_FILE")); caFile != "" {
			certPEM, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("read MySQL CA certificate: %w", err)
			}
			roots, err := x509.SystemCertPool()
			if err != nil || roots == nil {
				roots = x509.NewCertPool()
			}
			if !roots.AppendCertsFromPEM(certPEM) {
				return nil, errors.New("MYSQL_TLS_CA_FILE has no valid PEM certificates")
			}
			if err := driver.RegisterTLSConfig("ascend-monitor-ca", &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: serverHost,
				RootCAs:    roots,
			}); err != nil {
				return nil, errors.New("cannot register MySQL TLS configuration")
			}
			cfg.TLSConfig = "ascend-monitor-ca"
		} else {
			cfg.TLSConfig = "true"
		}
	} else {
		fmt.Fprintln(os.Stderr, "WARNING: MYSQL_TLS=disabled; traffic including decrypted credentials is NOT encrypted in transit")
	}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, errors.New("cannot initialize MySQL driver")
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(3 * time.Minute)
	pingCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	err = db.PingContext(pingCtx)
	cancel()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("MySQL connection failed (check address, TLS certificate, database and permissions): %w", sanitize(err))
	}
	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, err = db.ExecContext(initCtx, createTable)
	cancel()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create metrics table failed: %w", sanitize(err))
	}
	return &MySQL{db: db}, nil
}

// Err messages from drivers can contain server diagnostics: never copy the DSN.
func sanitize(err error) error {
	// Driver diagnostics do not normally contain a password, but avoid returning
	// arbitrary server/driver text that could embed credentials in rare cases.
	if err == nil {
		return nil
	}
	return errors.New("database operation failed; inspect MySQL server logs and connectivity")
}

func (m *MySQL) Close() error { return m.db.Close() }
func (m *MySQL) Write(ctx context.Context, v monitor.Metric) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		opCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err = m.db.ExecContext(opCtx, insertSQL, v.EventHash, v.EventTime.UTC(), v.LogTime,
			v.Hostname, v.HostIP, v.IPTail, v.ContainerID, v.ContainerName,
			v.PromptTPS, v.GenerationTPS, v.Running, v.Waiting, v.KVCachePct, v.PrefixHitPct)
		cancel()
		if err == nil {
			return nil
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt+1) * time.Second):
			}
		}
	}
	return errors.New("MySQL insert failed after 3 attempts; monitoring stopped to avoid silently dropping metrics")
}
