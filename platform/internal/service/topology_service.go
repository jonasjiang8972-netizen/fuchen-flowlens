package service

import (
	"sort"
	"sync"
	"time"
)

// Node kinds of the traffic topology: who calls, which host they reach,
// and which backend the gateway forwards to.
const (
	NodeCaller  = "caller"  // caller type (external_user, partner, ...)
	NodeHost    = "host"    // requested host
	NodeService = "service" // backend: gateway route name or upstream address
)

type TopologyNode struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Requests int64  `json:"requests"`
}

type TopologyEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Requests int64  `json:"requests"`
	Errors   int64  `json:"errors"` // responses with status >= 400
}

type Topology struct {
	Since time.Time      `json:"since"`
	Nodes []TopologyNode `json:"nodes"`
	Edges []TopologyEdge `json:"edges"`
	// Truncated reports edges dropped once the edge table was full.
	Truncated bool `json:"truncated"`
}

type edgeKey struct{ from, to string }

// TopologyService aggregates caller -> host -> backend traffic since the
// platform started, in memory.
type TopologyService struct {
	mu        sync.Mutex
	nodes     map[string]*TopologyNode
	edges     map[edgeKey]*TopologyEdge
	since     time.Time
	truncated bool
}

// maxTopologyEdges bounds the edge table.
const maxTopologyEdges = 5000

func NewTopologyService() *TopologyService {
	return &TopologyService{nodes: map[string]*TopologyNode{}, edges: map[edgeKey]*TopologyEdge{}, since: time.Now()}
}

// Observe counts one request of a caller type to host, forwarded to
// backend (empty when unknown), with its status code.
func (s *TopologyService) Observe(callerType, host, backend string, status int) {
	if callerType == "" || host == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	caller := s.node(NodeCaller, callerType)
	h := s.node(NodeHost, host)
	caller.Requests++
	h.Requests++
	s.edge(caller.ID, h.ID, status)
	if backend != "" {
		b := s.node(NodeService, backend)
		b.Requests++
		s.edge(h.ID, b.ID, status)
	}
}

func (s *TopologyService) node(kind, name string) *TopologyNode {
	id := kind + ":" + name
	n, ok := s.nodes[id]
	if !ok {
		n = &TopologyNode{ID: id, Kind: kind}
		s.nodes[id] = n
	}
	return n
}

func (s *TopologyService) edge(from, to string, status int) {
	k := edgeKey{from, to}
	e, ok := s.edges[k]
	if !ok {
		if len(s.edges) >= maxTopologyEdges {
			s.truncated = true
			return
		}
		e = &TopologyEdge{From: from, To: to}
		s.edges[k] = e
	}
	e.Requests++
	if status >= 400 {
		e.Errors++
	}
}

// Snapshot returns the topology with nodes and edges busiest first.
func (s *TopologyService) Snapshot() Topology {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := Topology{Since: s.since, Truncated: s.truncated, Nodes: []TopologyNode{}, Edges: []TopologyEdge{}}
	for _, n := range s.nodes {
		t.Nodes = append(t.Nodes, *n)
	}
	for _, e := range s.edges {
		t.Edges = append(t.Edges, *e)
	}
	sort.Slice(t.Nodes, func(i, j int) bool {
		if t.Nodes[i].Requests != t.Nodes[j].Requests {
			return t.Nodes[i].Requests > t.Nodes[j].Requests
		}
		return t.Nodes[i].ID < t.Nodes[j].ID
	})
	sort.Slice(t.Edges, func(i, j int) bool {
		if t.Edges[i].Requests != t.Edges[j].Requests {
			return t.Edges[i].Requests > t.Edges[j].Requests
		}
		return t.Edges[i].From+t.Edges[i].To < t.Edges[j].From+t.Edges[j].To
	})
	return t
}
