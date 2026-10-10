package service

import "testing"

func TestTopology(t *testing.T) {
	s := NewTopologyService()
	s.Observe("external_user", "shop.example", "user-svc", 200)
	s.Observe("external_user", "shop.example", "user-svc", 500)
	s.Observe("partner", "shop.example", "", 200) // backend unknown
	s.Observe("", "shop.example", "x", 200)       // ignored

	top := s.Snapshot()
	if len(top.Nodes) != 4 {
		t.Fatalf("nodes: %+v", top.Nodes)
	}
	if top.Nodes[0].ID != "host:shop.example" || top.Nodes[0].Requests != 3 {
		t.Fatalf("busiest node: %+v", top.Nodes[0])
	}
	var userEdge, backendEdge *TopologyEdge
	for i, e := range top.Edges {
		if e.From == "caller:external_user" {
			userEdge = &top.Edges[i]
		}
		if e.To == "service:user-svc" {
			backendEdge = &top.Edges[i]
		}
	}
	if userEdge == nil || userEdge.Requests != 2 || userEdge.Errors != 1 || backendEdge == nil || backendEdge.Requests != 2 {
		t.Fatalf("edges: %+v", top.Edges)
	}
	if len(top.Edges) != 3 {
		t.Fatalf("edge count %d, want 3", len(top.Edges))
	}
}
