package event

import (
	"encoding/json"
	"time"
)

type APIEvent struct {
	EventID    string            `json:"event_id"`
	Timestamp  time.Time         `json:"timestamp"`
	Source     string            `json:"source"`
	AgentID    string            `json:"agent_id"`
	Network    NetworkLayer      `json:"network"`
	Application ApplicationLayer `json:"application"`
	Content    ContentLayer      `json:"content"`
	Metadata   Metadata          `json:"metadata"`
	RawPacket  []byte            `json:"-"`
}

type NetworkLayer struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Protocol  string `json:"protocol"`
}

type ApplicationLayer struct {
	Method        string  `json:"method"`
	PathRaw       string  `json:"path_raw"`
	PathNormalized string `json:"path_normalized"`
	Host          string  `json:"host"`
	StatusCode    uint16  `json:"status_code"`
	BytesIn       uint64  `json:"bytes_in"`
	BytesOut      uint64  `json:"bytes_out"`
	DurationMs    float64 `json:"duration_ms"`
	ProtocolType  string  `json:"protocol_type"`
	TLSVersion    string  `json:"tls_version"`
	TLSCipherSuite string `json:"tls_cipher_suite"`
}

type ContentLayer {
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	QueryParams     map[string]string `json:"query_params"`
	RequestBody     []byte            `json:"request_body"`
	ResponseBody    []byte            `json:"response_body"`
	RequestBodySize int32             `json:"request_body_size"`
	ResponseBodySize int32           `json:"response_body_size"`
	ContentType     string            `json:"content_type"`
}

type Metadata struct {
	Env          string            `json:"env"`
	Cluster      string            `json:"cluster"`
	Namespace    string            `json:"namespace"`
	ServiceName  string            `json:"service_name"`
	PodName      string            `json:"pod_name"`
	NodeName     string            `json:"node_name"`
	AZ           string            `json:"availability_zone"`
	Labels       map[string]string `json:"labels"`
}

func (e *APIEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

func (e *APIEvent) Size() int {
	networkSz := len(e.Network.SrcIP) + len(e.Network.DstIP) + len(e.Network.Protocol)
	appSz := len(e.Application.Method) + len(e.Application.PathRaw) + len(e.Application.PathNormalized) + len(e.Application.Host) + len(e.Application.ProtocolType)
	contentSz := len(e.Content.RequestBody) + len(e.Content.ResponseBody)
	for k, v := range e.Content.RequestHeaders {
		contentSz += len(k) + len(v)
	}
	for k, v := range e.Content.ResponseHeaders {
		contentSz += len(k) + len(v)
	}
	return networkSz + appSz + contentSz
}

func (e *APIEvent) Sanitize(maxBodySize int) {
	if len(e.Content.RequestBody) > maxBodySize {
		e.Content.RequestBody = e.Content.RequestBody[:maxBodySize]
	}
	if len(e.Content.ResponseBody) > maxBodySize {
		e.Content.ResponseBody = e.Content.ResponseBody[:maxBodySize]
	}
}
