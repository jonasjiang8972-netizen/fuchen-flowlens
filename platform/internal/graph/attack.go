package graph

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// actor is one source (address plus signed-in account) and what it touched.
type actor struct {
	IP      string
	Account string
	Role    string
	First   time.Time
	Last    time.Time
	Calls   uint64
	Errors  uint64
	touches map[string]*touch
}

// touch is an actor's activity against one endpoint.
type touch struct {
	EndpointID string
	Service    string
	Method     string
	Path       string
	Calls      uint64
	Errors     uint64
	Fields     map[string]bool
	First      time.Time
	Last       time.Time
}

func actorKey(ip, account string) string { return ip + "|" + account }

func (s *Store) touchActor(o Observation, endpointID, service, method string, isErr bool) {
	if o.SrcIP == "" {
		return
	}
	key := actorKey(o.SrcIP, o.Account)
	a, ok := s.actors[key]
	if !ok {
		if len(s.actors) >= maxActors {
			s.dropped++
			return
		}
		a = &actor{IP: o.SrcIP, Account: o.Account, First: o.Time, touches: make(map[string]*touch)}
		s.actors[key] = a
		s.byIP[o.SrcIP] = append(s.byIP[o.SrcIP], a)
	}
	if o.Role != "" {
		a.Role = o.Role
	}
	a.Calls++
	if isErr {
		a.Errors++
	}
	if o.Time.After(a.Last) {
		a.Last = o.Time
	}
	t, ok := a.touches[endpointID]
	if !ok {
		if len(a.touches) >= maxTouchesPerActor {
			return
		}
		t = &touch{EndpointID: endpointID, Service: service, Method: method, Path: o.Path, Fields: make(map[string]bool), First: o.Time}
		a.touches[endpointID] = t
	}
	t.Calls++
	if isErr {
		t.Errors++
	}
	for _, f := range o.Fields {
		if f != "" {
			t.Fields[f] = true
		}
	}
	if o.Time.After(t.Last) {
		t.Last = o.Time
	}
}

func (s *Store) unindex(a *actor) {
	list := s.byIP[a.IP]
	for i, x := range list {
		if x == a {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(s.byIP, a.IP)
	} else {
		s.byIP[a.IP] = list
	}
}

// AlertRef is the part of an alert the attack graph needs.
type AlertRef struct {
	ID          string
	Title       string
	Severity    string
	Requirement string
	SourceIP    string
	AccountID   string
	Time        time.Time
	RiskScore   int
	Status      string
}

// Stage is a step of the attack chain an alert is mapped to.
type Stage struct {
	Rank int
	Name string
}

// StageOf maps a detection requirement to its attack-chain stage.
func StageOf(requirement string) Stage {
	switch requirement {
	case "FR-RISK-002":
		return Stage{1, "侦察探测"}
	case "FR-DET-002", "FR-RISK-003":
		return Stage{2, "凭据攻击"}
	case "FR-DET-001":
		return Stage{3, "对象枚举"}
	case "FR-DET-005":
		return Stage{4, "权限提升"}
	case "FR-DLP-001", "FR-DLP-003":
		return Stage{5, "数据外泄"}
	default:
		return Stage{0, "异常访问"}
	}
}

// Step is one alert on an attacker's path.
type Step struct {
	Stage    string    `json:"stage"`
	Rank     int       `json:"rank"`
	AlertID  string    `json:"alert_id"`
	Title    string    `json:"title"`
	Severity string    `json:"severity"`
	Time     time.Time `json:"time"`
}

// Path is the ordered chain of alerts raised by one source address.
type Path struct {
	Actor    string   `json:"actor"`
	Accounts []string `json:"accounts,omitempty"`
	Zone     string   `json:"zone"`
	Steps    []Step   `json:"steps"`
	Severity string   `json:"severity"`
	// Escalating is true when later steps reach a higher stage than earlier
	// ones: recon that turned into credential abuse, then data exfiltration.
	Escalating bool `json:"escalating"`
}

// AttackGraph is the attack-path graph plus the per-source paths behind it.
type AttackGraph struct {
	Graph
	Paths []Path `json:"paths"`
}

// AttackQuery selects which alerts the attack graph covers.
type AttackQuery struct {
	// AlertID limits the graph to the source behind this alert (all of that
	// source's alerts are included, since the path spans them).
	AlertID string
	// Limit is the maximum number of sources (default 10).
	Limit int
	// EndpointsPerActor caps the endpoints drawn for each source (default 8).
	EndpointsPerActor int
}

var severityOrder = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

func maxSeverity(a, b string) string {
	if severityOrder[b] > severityOrder[a] {
		return b
	}
	return a
}

// Attack builds the attack-path graph for the given alerts.
func (s *Store) Attack(alerts []AlertRef, q AttackQuery) AttackGraph {
	if q.Limit <= 0 {
		q.Limit = 10
	}
	if q.EndpointsPerActor <= 0 {
		q.EndpointsPerActor = 8
	}

	// Group alerts by source address; alerts without one form their own group.
	groups := make(map[string][]AlertRef)
	var order []string
	for _, al := range alerts {
		k := al.SourceIP
		if k == "" {
			k = "account:" + al.AccountID
			if al.AccountID == "" {
				k = "alert:" + al.ID
			}
		}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], al)
	}
	if q.AlertID != "" {
		var only []string
		for _, k := range order {
			for _, al := range groups[k] {
				if al.ID == q.AlertID {
					only = append(only, k)
				}
			}
		}
		order = only
	}
	// Most severe source first.
	rank := func(k string) (int, int) {
		sev, score := 0, 0
		for _, al := range groups[k] {
			if v := severityOrder[al.Severity]; v > sev {
				sev = v
			}
			if al.RiskScore > score {
				score = al.RiskScore
			}
		}
		return sev, score
	}
	sort.SliceStable(order, func(i, j int) bool {
		si, pi := rank(order[i])
		sj, pj := rank(order[j])
		if si != sj {
			return si > sj
		}
		return pi > pj
	})
	truncated := len(order) > q.Limit
	if truncated {
		order = order[:q.Limit]
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	b := &builder{nodes: map[string]*Node{}, edges: map[string]*Edge{}}
	res := AttackGraph{Paths: []Path{}}

	for _, k := range order {
		list := groups[k]
		sort.SliceStable(list, func(i, j int) bool { return list[i].Time.Before(list[j].Time) })
		ip := list[0].SourceIP

		actorID := "actor:" + k
		label := ip
		if ip == "" {
			label = strings.TrimPrefix(strings.TrimPrefix(k, "account:"), "alert:")
		}
		an := b.node(actorID, KindActor, label, 0)
		if ip != "" {
			an.Zone = Zone(ip)
		}

		path := Path{Actor: label, Zone: an.Zone, Steps: []Step{}}
		accounts := map[string]bool{}
		var alertNodes []string
		lastRank := 0
		for _, al := range list {
			st := StageOf(al.Requirement)
			path.Steps = append(path.Steps, Step{Stage: st.Name, Rank: st.Rank, AlertID: al.ID, Title: al.Title, Severity: al.Severity, Time: al.Time})
			path.Severity = maxSeverity(path.Severity, al.Severity)
			if st.Rank > 0 && lastRank > 0 && st.Rank > lastRank {
				path.Escalating = true
			}
			if st.Rank > 0 {
				lastRank = st.Rank
			}
			alID := "alert:" + al.ID
			n := b.node(alID, KindAlert, al.Title, 4)
			n.Risk = al.Severity
			n.Detail = st.Name + " · 风险 " + strconv.Itoa(al.RiskScore)
			n.LastSeen = al.Time
			from := actorID
			if al.AccountID != "" {
				accounts[al.AccountID] = true
			}
			b.edge(from, alID, EdgeFlow, "触发·"+st.Name, 1, 0)
			alertNodes = append(alertNodes, alID)
		}
		an.Risk = path.Severity
		for i := 0; i+1 < len(alertNodes); i++ {
			b.edge(alertNodes[i], alertNodes[i+1], EdgeSequence, "后续", 1, 0)
		}

		// Activity recorded for this source: accounts used and endpoints hit.
		var actors []*actor
		if ip != "" {
			actors = s.byIP[ip]
		}
		for _, a := range actors {
			if a.Account != "" {
				accounts[a.Account] = true
			}
		}
		accList := make([]string, 0, len(accounts))
		for a := range accounts {
			accList = append(accList, a)
		}
		sort.Strings(accList)
		path.Accounts = accList

		for _, a := range actors {
			from := actorID
			if a.Account != "" {
				accID := "account:" + a.Account
				b.node(accID, KindAccount, a.Account, 1).Calls += a.Calls
				b.edge(actorID, accID, EdgeFlow, "登录使用", a.Calls, a.Errors)
				from = accID
			}
			for _, t := range topTouches(a, q.EndpointsPerActor) {
				en := b.node(t.EndpointID, KindEndpoint, strings.TrimSpace(t.Method+" "+t.Path), 2)
				en.Calls += t.Calls
				en.Errors += t.Errors
				en.Detail = t.Service
				b.edge(from, t.EndpointID, EdgeFlow, callLabel(t), t.Calls, t.Errors)
				for f := range t.Fields {
					fid := "field:" + f
					fn := b.node(fid, KindField, f, 3)
					fn.Risk = "high"
					en.Risk = "high"
					b.edge(t.EndpointID, fid, EdgeFlow, "", t.Calls, 0)
				}
			}
		}
		res.Paths = append(res.Paths, path)
	}

	for _, n := range b.nodes {
		res.Nodes = append(res.Nodes, *n)
	}
	for _, e := range b.edges {
		res.Edges = append(res.Edges, *e)
	}
	sort.Slice(res.Nodes, func(i, j int) bool {
		if res.Nodes[i].Layer != res.Nodes[j].Layer {
			return res.Nodes[i].Layer < res.Nodes[j].Layer
		}
		return res.Nodes[i].ID < res.Nodes[j].ID
	})
	sort.Slice(res.Edges, func(i, j int) bool {
		return res.Edges[i].Source+res.Edges[i].Target < res.Edges[j].Source+res.Edges[j].Target
	})
	if res.Nodes == nil {
		res.Nodes, res.Edges = []Node{}, []Edge{}
	}
	res.Stats = Stats{TotalNodes: len(res.Nodes), TotalEdges: len(res.Edges), Shown: len(res.Edges), Truncated: truncated, Dropped: s.dropped}
	return res
}

// topTouches returns the endpoints of an actor most worth drawing: those that
// exposed sensitive fields or drew errors first, then the busiest.
func topTouches(a *actor, n int) []*touch {
	all := make([]*touch, 0, len(a.touches))
	for _, t := range a.touches {
		all = append(all, t)
	}
	score := func(t *touch) int {
		v := 0
		if len(t.Fields) > 0 {
			v += 2
		}
		if t.Errors > 0 {
			v++
		}
		return v
	}
	sort.Slice(all, func(i, j int) bool {
		if si, sj := score(all[i]), score(all[j]); si != sj {
			return si > sj
		}
		if all[i].Calls != all[j].Calls {
			return all[i].Calls > all[j].Calls
		}
		return all[i].EndpointID < all[j].EndpointID
	})
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func callLabel(t *touch) string {
	l := strconv.FormatUint(t.Calls, 10) + " 次"
	if t.Errors > 0 {
		l += " · " + strconv.FormatUint(t.Errors, 10) + " 失败"
	}
	return l
}

// builder accumulates nodes and edges, merging repeats.
type builder struct {
	nodes map[string]*Node
	edges map[string]*Edge
}

func (b *builder) node(id, kind, label string, layer int) *Node {
	if n, ok := b.nodes[id]; ok {
		return n
	}
	n := &Node{ID: id, Kind: kind, Label: label, Layer: layer}
	b.nodes[id] = n
	return n
}

func (b *builder) edge(source, target, kind, label string, calls, errs uint64) {
	key := source + "\x00" + target
	if e, ok := b.edges[key]; ok {
		e.Calls += calls
		e.Errors += errs
		return
	}
	b.edges[key] = &Edge{Source: source, Target: target, Kind: kind, Label: label, Calls: calls, Errors: errs}
}
