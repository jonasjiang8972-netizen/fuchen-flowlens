package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestTicketEndpointPermissionsAndReviewSeparation(t *testing.T) {
	h := newHarness(t, "")
	tok := h.tokens()
	const create = `{"title":"撞库调查","severity":"high","owner":"安全运营"}`

	for _, call := range [][3]string{{"GET", "/api/v1/tickets", ""}, {"GET", "/api/v1/tickets/summary", ""}, {"POST", "/api/v1/tickets", create}} {
		if w := h.do(call[0], call[1], "", call[2]); w.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s %s: %d, want 401", call[0], call[1], w.Code)
		}
	}
	for _, role := range []string{"sys_admin", "audit_admin"} {
		if w := h.do("GET", "/api/v1/tickets", tok[role], ""); w.Code != http.StatusForbidden {
			t.Errorf("%s reading tickets: %d, want 403", role, w.Code)
		}
	}
	if w := h.do("GET", "/api/v1/tickets", tok["viewer"], ""); w.Code != http.StatusOK {
		t.Errorf("viewer read: %d", w.Code)
	}
	if w := h.do("POST", "/api/v1/tickets", tok["viewer"], create); w.Code != http.StatusForbidden {
		t.Errorf("viewer create: %d, want 403", w.Code)
	}

	w := h.do("POST", "/api/v1/tickets", tok["analyst"], create)
	if w.Code != http.StatusCreated {
		t.Fatalf("analyst create: %d %s", w.Code, w.Body.String())
	}
	var tk map[string]any
	json.Unmarshal(w.Body.Bytes(), &tk)
	id := tk["ticket_id"].(string)
	if tk["created_by"] != "ana" {
		t.Errorf("created_by = %v, want the signed-in user", tk["created_by"])
	}
	for _, tr := range []struct{ token, body string }{
		{"viewer", `{"to":"processing"}`}, // read-only users cannot act
	} {
		if w := h.do("POST", "/api/v1/tickets/"+id+"/transition", tok[tr.token], tr.body); w.Code != http.StatusForbidden {
			t.Errorf("%s transition: %d, want 403", tr.token, w.Code)
		}
	}

	// The analyst does the work; a different person must approve it.
	do := func(token, body string) int {
		return h.do("POST", "/api/v1/tickets/"+id+"/transition", tok[token], body).Code
	}
	if c := do("analyst", `{"to":"processing"}`); c != http.StatusOK {
		t.Fatalf("start: %d", c)
	}
	if c := do("analyst", `{"to":"review","note":"已修复并回归"}`); c != http.StatusOK {
		t.Fatalf("submit: %d", c)
	}
	if c := do("analyst", `{"to":"done"}`); c != http.StatusForbidden {
		t.Errorf("the submitter approving their own fix: %d, want 403", c)
	}
	if c := do("sec_admin", `{"to":"done"}`); c != http.StatusOK {
		t.Errorf("a different person approving: %d, want 200", c)
	}

	// Every step is in the tamper-evident audit trail with who did it.
	w = h.do("GET", "/api/v1/admin/audit-logs?event_type=ticket.", tok["audit_admin"], "")
	body := w.Body.String()
	for _, want := range []string{"ticket.create", "ticket.transition", `"username":"ana"`, `"username":"secadmin"`, "to=done"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit trail missing %s", want)
		}
	}
}
