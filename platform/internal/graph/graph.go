// Package graph builds the traffic-driven graphs behind the console: the
// data-flow map (client → service → endpoint → sensitive field) and the
// attack-path graph (source → account → endpoints touched → alerts raised).
//
// Everything is derived from observed events and held in memory, bounded by
// node, edge and actor caps so a hostile or very busy network cannot grow it
// without limit. State is rebuilt from traffic after a restart.
package graph

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Node kinds.
const (
	KindClient   = "client"
	KindService  = "service"
	KindEndpoint = "endpoint"
	KindField    = "field"
	KindActor    = "actor"
	KindAccount  = "account"
	KindAlert    = "alert"
)

// Edge kinds.
const (
	EdgeFlow     = "flow"     // traffic or data moving along the edge
	EdgeSequence = "sequence" // one attack stage following another
)

// Views of the data-flow map.
const (
	ViewBusiness = "business" // clients, services, endpoints and the fields they expose
	ViewService  = "service"  // services and their endpoints only
	ViewData     = "data"     // endpoints that expose sensitive fields
)

const (
	maxNodes           = 5000
	maxEdges           = 20000
	maxActors          = 5000
	maxTouchesPerActor = 200
	defaultRetention   = 7 * 24 * time.Hour
	defaultFlowLimit   = 150
	maxFlowLimit       = 500
	// A node needs this many calls before its error rate is judged.
	minCallsForRate = 20
)

// Observation is one processed event, reduced to what the graphs need.
type Observation struct {
	Time     time.Time
	SrcIP    string
	Account  string
	Role     string
	Service  string // host or service name
	Method   string
	Path     string
	Status   int
	BytesOut uint64
	Fields   []string // sensitive field names found in the exchange
}

// Node is a vertex of a served graph.
type Node struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	Label    string    `json:"label"`
	Layer    int       `json:"layer"`
	Calls    uint64    `json:"calls"`
	Errors   uint64    `json:"errors,omitempty"`
	Risk     string    `json:"risk,omitempty"` // critical | high | medium | low | ""
	Zone     string    `json:"zone,omitempty"` // clients: internal | external
	Detail   string    `json:"detail,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

// Edge is a directed link of a served graph.
type Edge struct {
	Source   string    `json:"source"`
	Target   string    `json:"target"`
	Kind     string    `json:"kind"`
	Label    string    `json:"label,omitempty"`
	Calls    uint64    `json:"calls"`
	Errors   uint64    `json:"errors,omitempty"`
	BytesOut uint64    `json:"bytes_out,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

// Stats describes how much of the graph a response covers.
type Stats struct {
	TotalNodes int    `json:"total_nodes"`
	TotalEdges int    `json:"total_edges"`
	Shown      int    `json:"shown_edges"`
	Truncated  bool   `json:"truncated"`
	Dropped    uint64 `json:"dropped"` // observations not recorded because a cap was full
}

// Graph is a served graph.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	Stats Stats  `json:"stats"`
}

type node struct {
	Node
}

type edge struct {
	Edge
}

// Store holds the flow graph and per-source activity.
type Store struct {
	mu        sync.RWMutex
	nodes     map[string]*node
	edges     map[string]*edge
	actors    map[string]*actor
	byIP      map[string][]*actor
	dropped   uint64
	retention time.Duration
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{
		nodes:     make(map[string]*node),
		edges:     make(map[string]*edge),
		actors:    make(map[string]*actor),
		byIP:      make(map[string][]*actor),
		retention: defaultRetention,
	}
}

// Zone classifies a source address as internal (private, loopback,
// link-local) or external.
func Zone(ip string) string {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return "external"
	}
	if p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() {
		return "internal"
	}
	return "external"
}

// Observe records one event.
func (s *Store) Observe(o Observation) {
	if o.Path == "" {
		return
	}
	if o.Time.IsZero() {
		o.Time = time.Now()
	}
	service := o.Service
	if service == "" {
		service = "unknown"
	}
	method := strings.ToUpper(o.Method)
	isErr := o.Status >= 400
	src := o.SrcIP
	if src == "" {
		src = "unknown"
	}

	clientID := "client:" + src
	serviceID := "service:" + service
	endpointID := "endpoint:" + service + "|" + method + "|" + o.Path

	s.mu.Lock()
	defer s.mu.Unlock()

	client := s.touchNode(clientID, KindClient, src, 0, o.Time, isErr)
	svc := s.touchNode(serviceID, KindService, service, 1, o.Time, isErr)
	ep := s.touchNode(endpointID, KindEndpoint, strings.TrimSpace(method+" "+o.Path), 2, o.Time, isErr)
	if client != nil {
		client.Zone = Zone(src)
	}
	if client != nil && svc != nil {
		s.touchEdge(clientID, serviceID, EdgeFlow, o.Time, isErr, o.BytesOut)
	}
	if svc != nil && ep != nil {
		s.touchEdge(serviceID, endpointID, EdgeFlow, o.Time, isErr, o.BytesOut)
	}
	if ep != nil {
		for _, f := range o.Fields {
			if f == "" {
				continue
			}
			fieldID := "field:" + f
			if s.touchNode(fieldID, KindField, f, 3, o.Time, false) != nil {
				s.touchEdge(endpointID, fieldID, EdgeFlow, o.Time, false, o.BytesOut)
			}
		}
	}
	s.touchActor(o, endpointID, service, method, isErr)
}

func (s *Store) touchNode(id, kind, label string, layer int, at time.Time, isErr bool) *node {
	n, ok := s.nodes[id]
	if !ok {
		if len(s.nodes) >= maxNodes {
			s.dropped++
			return nil
		}
		n = &node{Node{ID: id, Kind: kind, Label: label, Layer: layer}}
		s.nodes[id] = n
	}
	n.Calls++
	if isErr {
		n.Errors++
	}
	if at.After(n.LastSeen) {
		n.LastSeen = at
	}
	return n
}

func (s *Store) touchEdge(source, target, kind string, at time.Time, isErr bool, bytesOut uint64) {
	key := source + "\x00" + target
	e, ok := s.edges[key]
	if !ok {
		if len(s.edges) >= maxEdges {
			s.dropped++
			return
		}
		e = &edge{Edge{Source: source, Target: target, Kind: kind}}
		s.edges[key] = e
	}
	e.Calls++
	if isErr {
		e.Errors++
	}
	e.BytesOut += bytesOut
	if at.After(e.LastSeen) {
		e.LastSeen = at
	}
}

// Cleanup drops graph state not seen within the retention period until ctx
// ends.
func (s *Store) Cleanup(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.prune(time.Now().Add(-s.retention))
		}
	}
}

func (s *Store) prune(cutoff time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.edges {
		if e.LastSeen.Before(cutoff) {
			delete(s.edges, k)
		}
	}
	connected := make(map[string]bool, len(s.edges)*2)
	for _, e := range s.edges {
		connected[e.Source], connected[e.Target] = true, true
	}
	for id, n := range s.nodes {
		if n.LastSeen.Before(cutoff) && !connected[id] {
			delete(s.nodes, id)
		}
	}
	for k, a := range s.actors {
		if a.Last.Before(cutoff) {
			delete(s.actors, k)
			s.unindex(a)
		}
	}
}

// FlowQuery selects part of the flow graph.
type FlowQuery struct {
	View     string
	Keyword  string
	Limit    int    // maximum edges returned
	MinCalls uint64 // drop edges with fewer calls
}

// Flow returns the busiest edges of the requested view with the nodes they
// connect.
func (s *Store) Flow(q FlowQuery) Graph {
	if q.Limit <= 0 {
		q.Limit = defaultFlowLimit
	}
	if q.Limit > maxFlowLimit {
		q.Limit = maxFlowLimit
	}
	kw := strings.ToLower(strings.TrimSpace(q.Keyword))

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Endpoints that expose a sensitive field, for the data view and risk.
	sensitive := make(map[string]bool)
	fieldsOf := make(map[string][]string)
	for _, e := range s.edges {
		if strings.HasPrefix(e.Target, "field:") {
			sensitive[e.Source] = true
			fieldsOf[e.Source] = append(fieldsOf[e.Source], s.nodes[e.Target].Label)
		}
	}

	var cand []*edge
	for _, e := range s.edges {
		if e.Calls < q.MinCalls {
			continue
		}
		sn, tn := s.nodes[e.Source], s.nodes[e.Target]
		if sn == nil || tn == nil {
			continue
		}
		switch q.View {
		case ViewService:
			if sn.Kind != KindService || tn.Kind != KindEndpoint {
				continue
			}
		case ViewData:
			if tn.Kind == KindField {
				// keep
			} else if !(sn.Kind == KindService && tn.Kind == KindEndpoint && sensitive[e.Target]) {
				continue
			}
		}
		cand = append(cand, e)
	}

	if kw != "" {
		matched := make(map[string]bool)
		for _, e := range cand {
			for _, id := range []string{e.Source, e.Target} {
				if strings.Contains(strings.ToLower(s.nodes[id].Label), kw) {
					matched[id] = true
				}
			}
		}
		var keep []*edge
		for _, e := range cand {
			if matched[e.Source] || matched[e.Target] {
				keep = append(keep, e)
			}
		}
		cand = keep
	}

	sort.Slice(cand, func(i, j int) bool {
		if cand[i].Calls != cand[j].Calls {
			return cand[i].Calls > cand[j].Calls
		}
		return cand[i].Source+cand[i].Target < cand[j].Source+cand[j].Target
	})
	truncated := len(cand) > q.Limit
	if truncated {
		cand = cand[:q.Limit]
	}

	out := Graph{Stats: Stats{TotalNodes: len(s.nodes), TotalEdges: len(s.edges), Shown: len(cand), Truncated: truncated, Dropped: s.dropped}}
	seen := make(map[string]bool)
	for _, e := range cand {
		ed := e.Edge
		out.Edges = append(out.Edges, ed)
		for _, id := range []string{e.Source, e.Target} {
			if seen[id] {
				continue
			}
			seen[id] = true
			n := s.nodes[id].Node
			n.Risk = nodeRisk(n, sensitive[id])
			if len(fieldsOf[id]) > 0 {
				sort.Strings(fieldsOf[id])
				n.Detail = "敏感字段: " + strings.Join(fieldsOf[id], ", ")
			}
			out.Nodes = append(out.Nodes, n)
		}
	}
	sort.Slice(out.Nodes, func(i, j int) bool {
		if out.Nodes[i].Layer != out.Nodes[j].Layer {
			return out.Nodes[i].Layer < out.Nodes[j].Layer
		}
		return out.Nodes[i].ID < out.Nodes[j].ID
	})
	if out.Nodes == nil {
		out.Nodes, out.Edges = []Node{}, []Edge{}
	}
	return out
}

func nodeRisk(n Node, exposesSensitive bool) string {
	if n.Kind == KindField {
		return "high"
	}
	if n.Kind == KindEndpoint && exposesSensitive {
		return "high"
	}
	if n.Calls >= minCallsForRate && float64(n.Errors)/float64(n.Calls) >= 0.5 {
		return "medium"
	}
	return ""
}
