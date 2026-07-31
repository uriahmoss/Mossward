package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddress  string
	DatabaseFile   string
	LegacyDataFile string
	AllowedCIDRs   []string
	AllowedPorts   map[int]bool
	MaxTargets     int
	MaxConcurrent  int
	QueueSize      int
	ConnectTimeout time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddress:  env("MOSSWARD_LISTEN", "127.0.0.1:8080"),
		DatabaseFile:   env("MOSSWARD_DATABASE_FILE", "data/mossward.db"),
		LegacyDataFile: env("MOSSWARD_DATA_FILE", "data/scans.json"),
		AllowedCIDRs: strings.Split(env("MOSSWARD_ALLOWED_CIDRS",
			"127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7"), ","),
		MaxTargets:     256,
		MaxConcurrent:  32,
		QueueSize:      16,
		ConnectTimeout: 800 * time.Millisecond,
	}
	var err error
	if cfg.MaxTargets, err = envPositiveInt("MOSSWARD_MAX_TARGETS", cfg.MaxTargets); err != nil {
		return Config{}, err
	}
	if cfg.MaxConcurrent, err = envPositiveInt("MOSSWARD_MAX_CONCURRENT", cfg.MaxConcurrent); err != nil {
		return Config{}, err
	}
	if cfg.QueueSize, err = envPositiveInt("MOSSWARD_QUEUE_SIZE", cfg.QueueSize); err != nil {
		return Config{}, err
	}
	timeoutMS, err := envPositiveInt("MOSSWARD_CONNECT_TIMEOUT_MS", int(cfg.ConnectTimeout/time.Millisecond))
	if err != nil {
		return Config{}, err
	}
	cfg.ConnectTimeout = time.Duration(timeoutMS) * time.Millisecond
	cfg.AllowedPorts = parsePorts(env("MOSSWARD_ALLOWED_PORTS", "22,80,443,445,3389,5432,6379,8080,8443"))
	if len(cfg.AllowedPorts) == 0 {
		return Config{}, fmt.Errorf("MOSSWARD_ALLOWED_PORTS must contain at least one valid port")
	}
	for _, raw := range cfg.AllowedCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(raw)); err != nil {
			return Config{}, fmt.Errorf("invalid CIDR %q in MOSSWARD_ALLOWED_CIDRS: %w", raw, err)
		}
	}
	return cfg, nil
}

func envPositiveInt(name string, fallback int) (int, error) {
	raw := env(name, strconv.Itoa(fallback))
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func parsePorts(raw string) map[int]bool {
	ports := make(map[int]bool)
	for _, item := range strings.Split(raw, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(item))
		if err == nil && port > 0 && port <= 65535 {
			ports[port] = true
		}
	}
	return ports
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
