package service

import (
	"fmt"
	"sync"
	"time"
)

type Asset struct {
	ID                      string    `json:"asset_id"`
	PathNormalized          string    `json:"path_normalized"`
	Method                  string    `json:"method"`
	ProtocolType            string    `json:"protocol_type"`
	Host                    string    `json:"host"`
	FirstSeen               time.Time `json:"first_seen"`
	LastSeen                time.Time `json:"last_seen"`
	DailyAvgCalls           int       `json:"daily_avg_calls"`
	SensitivityHint         string    `json:"sensitivity_hint"`
	ClaimStatus             string    `json:"claim_status"`
	Owner                   string    `json:"owner"`
	GroupPath               string    `json:"group_path"`
	NormalizationConfidence float64   `json:"normalization_confidence"`
}

type AssetService struct {
	mu     sync.RWMutex
	assets map[string]*Asset
}

func NewAssetService() *AssetService {
	s := &AssetService{
		assets: make(map[string]*Asset),
	}
	s.seedAssets()
	return s
}

func (s *AssetService) seedAssets() {
	now := time.Now()
	s.assets["ast-001"] = &Asset{
		ID: "ast-001", PathNormalized: "/api/v1/user/{id}", Method: "GET",
		ProtocolType: "REST", Host: "api.example.com",
		FirstSeen: now.Add(-30 * 24 * time.Hour), LastSeen: now.Add(-1 * time.Minute),
		DailyAvgCalls: 15230, SensitivityHint: "medium",
		ClaimStatus: "claimed", Owner: "zhang.wei@company.com",
		GroupPath: "零售事业部/交易系统/用户模块",
		NormalizationConfidence: 0.94,
	}
	s.assets["ast-002"] = &Asset{
		ID: "ast-002", PathNormalized: "/api/v1/order/{id}", Method: "GET",
		ProtocolType: "REST", Host: "api.example.com",
		FirstSeen: now.Add(-25 * 24 * time.Hour), LastSeen: now.Add(-30 * time.Second),
		DailyAvgCalls: 8720, SensitivityHint: "high",
		ClaimStatus: "claimed", Owner: "li.ming@company.com",
		GroupPath: "零售事业部/交易系统/订单模块",
		NormalizationConfidence: 0.91,
	}
	s.assets["ast-003"] = &Asset{
		ID: "ast-003", PathNormalized: "/api/v1/payment/checkout", Method: "POST",
		ProtocolType: "REST", Host: "api.example.com",
		FirstSeen: now.Add(-20 * 24 * time.Hour), LastSeen: now.Add(-2 * time.Minute),
		DailyAvgCalls: 3200, SensitivityHint: "high",
		ClaimStatus: "unclaimed", Owner: "",
		GroupPath: "零售事业部/交易系统/支付模块",
		NormalizationConfidence: 0.99,
	}
}

func (s *AssetService) List() []Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Asset, 0, len(s.assets))
	for _, a := range s.assets {
		result = append(result, *a)
	}
	return result
}

func (s *AssetService) Get(id string) (*Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[id]
	if !ok {
		return nil, fmt.Errorf("asset not found: %s", id)
	}
	return a, nil
}

func (s *AssetService) Claim(id, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assets[id]
	if !ok {
		return fmt.Errorf("asset not found: %s", id)
	}
	a.ClaimStatus = "claimed"
	a.Owner = owner
	return nil
}
