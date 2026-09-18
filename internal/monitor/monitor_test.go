package monitor

import (
	"strings"
	"testing"
	"time"
)

const sample = `(APIServer pid=1) INFO 09-18 04:07:40 [loggers.py:310] Engine 000: Avg prompt throughput: 6304.3 tokens/s, Avg generation throughput: 10.6 tokens/s, Running: 4 reqs, Waiting: 1 reqs, GPU KV cache usage: 68.2%, Prefix cache hit rate: 23.7%`

func TestParseDockerTimestamp(t *testing.T) {
	src := Source{Hostname: "worker", HostIP: "192.168.10.25", IPTail: "10.25", ContainerID: "abc", ContainerName: "ascen"}
	input := "2026-09-18T04:07:40.123456789Z " + sample
	m, ok, err := Parse(input, src, time.Now())
	if err != nil || !ok {
		t.Fatalf("parse ok=%v err=%v", ok, err)
	}
	if m.PromptTPS != 6304.3 || m.GenerationTPS != 10.6 || m.Waiting != 1 || m.Running != 4 || m.KVCachePct != 68.2 || m.PrefixHitPct != 23.7 {
		t.Fatalf("bad parsed values: %+v", m)
	}
	if m.LogTime != "09-18 04:07:40" || m.IPTail != "10.25" {
		t.Fatalf("bad display: %+v", m)
	}
	if m.EventTime.Nanosecond() != 123456789 {
		t.Fatalf("lost Docker precision: %+v", m.EventTime)
	}
	other, _, _ := Parse(input, src, time.Now().Add(time.Hour))
	if m.EventHash != other.EventHash {
		t.Fatal("same Docker line has inconsistent dedupe ID")
	}
	other, _, _ = Parse(strings.Replace(input, "123456789", "123456788", 1), src, time.Now())
	if m.EventHash == other.EventHash {
		t.Fatal("distinct Docker lines have identical dedupe ID")
	}
}

func TestParsePlainAndUnrelated(t *testing.T) {
	now := time.Date(2026, 9, 18, 4, 7, 40, 0, time.UTC)
	m, ok, err := Parse(sample, Source{}, now)
	if err != nil || !ok || !m.EventTime.Equal(now) {
		t.Fatalf("plain parse: %+v %v %v", m, ok, err)
	}
	_, ok, err = Parse("random error line", Source{}, now)
	if ok || err != nil {
		t.Fatalf("unrelated line: %v %v", ok, err)
	}
}

func TestIPTail(t *testing.T) {
	for input, want := range map[string]string{"192.168.10.25": "10.25", "10.0.0.1": "0.1", "bad": "-", "2001:db8::1": "-"} {
		if got := IPTail(input); got != want {
			t.Errorf("%s: got %s want %s", input, got, want)
		}
	}
}
