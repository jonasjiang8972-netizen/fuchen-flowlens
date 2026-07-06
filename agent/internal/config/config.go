package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Agent      AgentConfig      `yaml:"agent"`
	Collector  CollectorConfig  `yaml:"collector"`
	Management ManagementConfig `yaml:"management"`
	Kafka      KafkaConfig      `yaml:"kafka"`
}

type AgentConfig struct {
	ID       string `yaml:"id"`
	Cluster  string `yaml:"cluster"`
	LogLevel string `yaml:"log_level"`
}

type CollectorConfig struct {
	Mode           string        `yaml:"mode"`
	Interface      string        `yaml:"interface"`
	FilterPorts    []string      `yaml:"filter_port"`
	CaptureHeaders bool          `yaml:"capture_headers"`
	CaptureBody    bool          `yaml:"capture_body"`
	MaxBodySizeKB  int           `yaml:"max_body_size_kb"`
	BufferSize     int           `yaml:"buffer_size"`
	Workers        int           `yaml:"workers"`

	EBPF  EBPFConfig  `yaml:"ebpf"`
	DPDK  DPDKConfig  `yaml:"dpdk"`
	GWLog GWLogConfig `yaml:"gateway_log"`
	VPC   VPCConfig   `yaml:"vpc"`
}

type EBPFConfig struct {
	EnableTLSProbe bool `yaml:"enable_tls_probe"`
}

type DPDKConfig struct {
	NICPCI    string `yaml:"nic_pci"`
	NumCores  int    `yaml:"num_cores"`
}

type GWLogConfig struct {
	Path   string `yaml:"path"`
	Format string `yaml:"format"`
}

type VPCConfig struct {
	Provider       string `yaml:"provider"`
	Region         string `yaml:"region"`
	Bucket         string `yaml:"bucket"`
	PollIntervalSec int   `yaml:"poll_interval_s"`
}

type ManagementConfig struct {
	PlatformEndpoint    string        `yaml:"platform_endpoint"`
	HeartbeatInterval   time.Duration `yaml:"heartbeat_interval_s"`
	HeartbeatTimeout    time.Duration `yaml:"heartbeat_timeout_s"`
	ReconnectBackoffMax time.Duration `yaml:"reconnect_backoff_max_s"`
	UseTLS              bool          `yaml:"use_tls"`
	TLSCertPath         string        `yaml:"tls_cert_path"`
	TLSCAPath           string        `yaml:"tls_ca_path"`
}

type KafkaConfig struct {
	Brokers          []string      `yaml:"brokers"`
	Topic            string        `yaml:"topic"`
	BatchSize        int           `yaml:"batch_size"`
	FlushIntervalMs  int           `yaml:"flush_interval_ms"`
	CompressionCodec string        `yaml:"compression_codec"`
	MaxMessageBytes  int           `yaml:"max_message_bytes"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Agent.ID == "" {
		hostname, _ := os.Hostname()
		cfg.Agent.ID = fmt.Sprintf("%s-%d", hostname, os.Getpid())
	}

	return cfg, nil
}

func DefaultConfig() *Config {
	return &Config{
		Agent: AgentConfig{
			LogLevel: "info",
			Cluster:  "default",
		},
		Collector: CollectorConfig{
			Mode:           "auto",
			FilterPorts:    []string{"80", "443", "8080", "8443"},
			CaptureHeaders: true,
			CaptureBody:    true,
			MaxBodySizeKB:  64,
			BufferSize:     65536,
			Workers:        4,
			EBPF: EBPFConfig{
				EnableTLSProbe: false,
			},
			GWLog: GWLogConfig{
				Format: "json",
			},
			VPC: VPCConfig{
				PollIntervalSec: 60,
			},
		},
		Management: ManagementConfig{
			HeartbeatInterval:   10 * time.Second,
			HeartbeatTimeout:    30 * time.Second,
			ReconnectBackoffMax: 300 * time.Second,
			UseTLS:              true,
		},
		Kafka: KafkaConfig{
			Brokers:          []string{"localhost:9092"},
			Topic:            "raw-api-events",
			BatchSize:        1000,
			FlushIntervalMs:  100,
			CompressionCodec: "snappy",
			MaxMessageBytes:  1048576,
		},
	}
}
