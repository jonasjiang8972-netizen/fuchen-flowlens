package service

import "testing"

func TestCallerService(t *testing.T) {
	s := NewCallerService()
	for i := 0; i < 5; i++ {
		s.Observe("usr-1", "external_user", "user", "gateway_header", 0.92, "GET /a", "10.0.0.1", 200)
	}
	s.Observe("usr-1", "external_user", "user", "gateway_header", 0.92, "GET /b", "10.0.0.2", 403)
	s.Observe("ip:1.2.3.4", "network_principal", "external", "source_ip", 0.55, "GET /a", "1.2.3.4", 500)
	s.Observe("", "unknown", "", "", 0, "GET /a", "", 200) // ignored

	list := s.List("", 0)
	if len(list) != 2 || list[0].ID != "usr-1" || list[0].Requests != 6 || list[0].Errors != 1 ||
		list[0].Endpoints != 2 || len(list[0].SourceIPs) != 2 {
		t.Fatalf("list: %+v", list)
	}
	if got := s.List("network_principal", 0); len(got) != 1 || got[0].Errors != 1 {
		t.Fatalf("filtered: %+v", got)
	}
	st := s.Stats()
	if st.Callers != 2 || st.Requests != 7 || st.ByType["external_user"] != 1 || st.Traffic["external_user"] != 6 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestCallerTableIsBounded(t *testing.T) {
	s := NewCallerService()
	s.callers = make(map[string]*callerState, maxCallers)
	for i := 0; i < maxCallers; i++ {
		s.callers[string(rune(i))+"x"] = &callerState{endpoints: map[string]struct{}{}, ips: map[string]struct{}{}}
	}
	s.Observe("one-more", "partner", "partner", "api_key", 0.9, "GET /a", "", 200)
	if _, ok := s.callers["one-more"]; ok || s.Stats().Untracked != 1 {
		t.Fatalf("table grew past its bound")
	}
}
