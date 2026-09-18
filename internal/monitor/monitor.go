package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Metric is a single vLLM Engine status record. EventTime is a UTC instant.
type Metric struct {
	EventTime     time.Time
	LogTime       string
	Hostname      string
	HostIP        string
	IPTail        string
	ContainerID   string
	ContainerName string
	EventHash     string
	PromptTPS     float64
	GenerationTPS float64
	Running       int
	Waiting       int
	KVCachePct    float64
	PrefixHitPct  float64
}

var (
	statusRE  = regexp.MustCompile(`Avg prompt throughput:\s*([0-9]+(?:\.[0-9]+)?)\s*tokens/s.*?Avg generation throughput:\s*([0-9]+(?:\.[0-9]+)?)\s*tokens/s.*?Running:\s*([0-9]+)\s*reqs?,\s*Waiting:\s*([0-9]+)\s*reqs?.*?GPU KV cache usage:\s*([0-9]+(?:\.[0-9]+)?)%.*?Prefix cache hit rate:\s*([0-9]+(?:\.[0-9]+)?)%`)
	logTimeRE = regexp.MustCompile(`\b[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\b`)
)

type Source struct{ Hostname, HostIP, IPTail, ContainerID, ContainerName string }

// Parse returns (metric, true, nil) for matching status lines, false for unrelated lines.
// Docker --timestamps supplies the authoritative event instant; the app's MM-DD time
// is preserved for display, because its timezone may differ from the Docker daemon's.
func Parse(line string, source Source, now time.Time) (Metric, bool, error) {
	raw := strings.TrimRight(line, "\r\n")
	msg := raw
	instant := now.UTC()
	dockerTimestamp := ""
	if first, rest, ok := strings.Cut(raw, " "); ok {
		if ts, err := time.Parse(time.RFC3339Nano, first); err == nil {
			instant = ts.UTC()
			dockerTimestamp = first
			msg = rest
		}
	}
	values := statusRE.FindStringSubmatch(msg)
	if values == nil {
		return Metric{}, false, nil
	}
	var m Metric
	m.EventTime = instant
	m.Hostname, m.HostIP, m.IPTail = source.Hostname, source.HostIP, source.IPTail
	m.ContainerID, m.ContainerName = source.ContainerID, source.ContainerName
	m.LogTime = logTimeRE.FindString(msg)
	if m.LogTime == "" {
		m.LogTime = instant.Local().Format("01-02 15:04:05")
	}
	var err error
	for _, item := range []struct {
		dest  *float64
		index int
	}{
		{&m.PromptTPS, 1}, {&m.GenerationTPS, 2}, {&m.KVCachePct, 5}, {&m.PrefixHitPct, 6},
	} {
		*item.dest, err = strconv.ParseFloat(values[item.index], 64)
		if err != nil {
			return Metric{}, false, fmt.Errorf("parse metric: %w", err)
		}
	}
	m.Running, err = strconv.Atoi(values[3])
	if err != nil {
		return Metric{}, false, fmt.Errorf("parse running: %w", err)
	}
	m.Waiting, err = strconv.Atoi(values[4])
	if err != nil {
		return Metric{}, false, fmt.Errorf("parse waiting: %w", err)
	}
	// The docker timestamp uniquely distinguishes identical status lines on different runs.
	// Without it, the local ingestion timestamp avoids collapsing distinct occurrences.
	identityTime := dockerTimestamp
	if identityTime == "" {
		identityTime = instant.Format(time.RFC3339Nano)
	}
	sum := sha256.Sum256([]byte(source.ContainerID + "\x00" + identityTime + "\x00" + msg))
	m.EventHash = hex.EncodeToString(sum[:])
	return m, true, nil
}

func IPTail(ip string) string {
	addr := net.ParseIP(ip).To4()
	if addr == nil {
		return "-"
	}
	return fmt.Sprintf("%d.%d", addr[2], addr[3])
}

// LocalIPv4 prioritizes the interface named by the Linux default route.
// The fallback skips virtual/loopback interfaces where possible.
func LocalIPv4() string {
	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) >= 4 && f[1] == "00000000" && f[3] != "0000" {
				if iface, err := net.InterfaceByName(f[0]); err == nil {
					if ip := ipv4ForInterface(*iface); ip != "" {
						return ip
					}
				}
			}
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		if strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "cni") {
			continue
		}
		if ip := ipv4ForInterface(iface); ip != "" {
			return ip
		}
	}
	return ""
}

func ipv4ForInterface(iface net.Interface) string {
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.String()
		}
	}
	return ""
}
