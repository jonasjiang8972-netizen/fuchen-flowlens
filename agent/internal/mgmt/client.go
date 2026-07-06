package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/config"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
)

type AgentRegistration struct {
	AgentID      string        `json:"agent_id"`
	Hostname     string        `json:"hostname"`
	CollectMode  string        `json:"collect_mode"`
	Cluster      string        `json:"cluster"`
	AgentVersion string        `json:"agent_version"`
	OS           string        `json:"os"`
	CPUPercent   float64       `json:"cpu_percent"`
	MemoryMB     uint64        `json:"memory_mb_used"`
}

type HeartbeatPayload struct {
	AgentID       string  `json:"agent_id"`
	Status        string  `json:"status"`
	QPS           float64 `json:"qps"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryMB      uint64  `json:"memory_mb"`
	DropRate      float64 `json:"drop_rate"`
	CollectMode   string  `json:"collect_mode"`
}

type Client struct {
	cfg        config.ManagementConfig
	httpClient *http.Client
	registered bool
	agentID    string
}

func NewClient(cfg config.ManagementConfig) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) Register(ctx context.Context, reg *AgentRegistration) error {
	url := fmt.Sprintf("http://%s/api/v1/agents/register", c.cfg.PlatformEndpoint)
	if c.cfg.UseTLS {
		url = fmt.Sprintf("https://%s/api/v1/agents/register", c.cfg.PlatformEndpoint)
	}
	if reg.AgentID != "" {
		c.agentID = reg.AgentID
	}

	body, _ := json.Marshal(reg)
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("register agent: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("register failed: %d", resp.StatusCode)
	}

	var result struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	c.agentID = result.AgentID
	c.registered = true
	logger.L().Infof("Agent registered with platform: %s", c.agentID)
	return nil
}

func (c *Client) SendHeartbeat(ctx context.Context, hb *HeartbeatPayload) error {
	if !c.registered {
		return nil
	}
	url := fmt.Sprintf("http://%s/api/v1/agents/%s/heartbeat", c.cfg.PlatformEndpoint, c.agentID)
	if c.cfg.UseTLS {
		url = fmt.Sprintf("https://%s/api/v1/agents/%s/heartbeat", c.cfg.PlatformEndpoint, c.agentID)
	}

	body, _ := json.Marshal(hb)
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		c.registered = false
		return fmt.Errorf("heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		c.registered = false
		return fmt.Errorf("agent not found on platform")
	}
	return nil
}

func (c *Client) StartHeartbeatLoop(ctx context.Context, cfg config.ManagementConfig, getMetrics func() HeartbeatPayload) {
	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hb := getMetrics()
			hb.AgentID = c.agentID
			if err := c.SendHeartbeat(ctx, &hb); err != nil {
				logger.L().Warnf("Heartbeat failed: %v", err)
				if !c.registered {
					logger.L().Warnf("Agent not registered, will retry registration")
				}
			}
		}
	}
}

func (c *Client) IsRegistered() bool {
	return c.registered
}
