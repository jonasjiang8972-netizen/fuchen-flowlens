package soar

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Nginx blocks addresses by maintaining an include file of `deny` lines and
// reloading nginx. Only validated IP literals are ever written to the file, so
// alert text can never inject configuration. If the reload fails the file is
// restored, leaving the running configuration and the file in agreement.
//
// In nginx.conf, inside the http or server block:
//
//	include /etc/nginx/flowlens-deny.conf;
type Nginx struct {
	file   string
	reload []string // command and arguments; empty means "do not reload"
	mu     sync.Mutex
}

// NewNginx returns a connector for the given include file. reloadCmd is split
// on whitespace and run directly (no shell), e.g. "nginx -s reload".
func NewNginx(file, reloadCmd string) *Nginx {
	return &Nginx{file: file, reload: strings.Fields(reloadCmd)}
}

func (n *Nginx) Name() string  { return "nginx" }
func (n *Nginx) Label() string { return "Nginx" }

func (n *Nginx) read() (map[string]bool, []byte, error) {
	raw, err := os.ReadFile(n.file)
	if os.IsNotExist(err) {
		return map[string]bool{}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	set := make(map[string]bool)
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(strings.TrimSuffix(strings.TrimSpace(sc.Text()), ";"))
		if len(f) == 2 && f[0] == "deny" && net.ParseIP(f[1]) != nil {
			set[f[1]] = true
		}
	}
	return set, raw, sc.Err()
}

func render(set map[string]bool) []byte {
	ips := make([]string, 0, len(set))
	for ip := range set {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	var b bytes.Buffer
	b.WriteString("# Managed by FlowLens. Do not edit: changes are overwritten.\n")
	for _, ip := range ips {
		fmt.Fprintf(&b, "deny %s;\n", ip)
	}
	return b.Bytes()
}

// write replaces the file atomically.
func (n *Nginx) write(content []byte) error {
	dir := filepath.Dir(n.file)
	tmp, err := os.CreateTemp(dir, ".flowlens-deny-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), n.file)
}

func (n *Nginx) apply(ctx context.Context, set map[string]bool, previous []byte) error {
	if err := n.write(render(set)); err != nil {
		return err
	}
	if len(n.reload) == 0 {
		return nil
	}
	out, err := exec.CommandContext(ctx, n.reload[0], n.reload[1:]...).CombinedOutput()
	if err != nil {
		// Put the old file back: nginx kept its previous config.
		if previous == nil {
			_ = os.Remove(n.file)
		} else {
			_ = n.write(previous)
		}
		msg := strings.TrimSpace(string(out))
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		return fmt.Errorf("重载 nginx 失败: %v: %s", err, msg)
	}
	return nil
}

func (n *Nginx) Block(ctx context.Context, req Request) (string, error) {
	if net.ParseIP(req.IP) == nil {
		return "", fmt.Errorf("invalid address %q", req.IP)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	set, prev, err := n.read()
	if err != nil {
		return "", err
	}
	if set[req.IP] {
		return "", nil
	}
	set[req.IP] = true
	return "", n.apply(ctx, set, prev)
}

func (n *Nginx) Unblock(ctx context.Context, ip, _ string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	set, prev, err := n.read()
	if err != nil {
		return err
	}
	if !set[ip] {
		return nil
	}
	delete(set, ip)
	return n.apply(ctx, set, prev)
}

// Check verifies the include file can be read and its directory written.
func (n *Nginx) Check(_ context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, _, err := n.read(); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(n.file), ".flowlens-check-*")
	if err != nil {
		return fmt.Errorf("目录不可写: %w", err)
	}
	tmp.Close()
	return os.Remove(tmp.Name())
}
