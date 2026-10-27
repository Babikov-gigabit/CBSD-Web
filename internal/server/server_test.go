package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cbsd-web/cbsd-web/internal/audit"
	"github.com/cbsd-web/cbsd-web/internal/auth"
	"github.com/cbsd-web/cbsd-web/internal/config"
	"github.com/cbsd-web/cbsd-web/internal/devfixture"
)

// testWorkdir is the fixture workdir of the latest setup().
var testWorkdir string

type client struct {
	t    *testing.T
	base string
	hc   *http.Client
	csrf string
}

func (c *client) do(method, path string, body any, hdr map[string]string) (*http.Response, map[string]any) {
	c.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" && method != "GET" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp, m
}

func (c *client) login(user, pw string) int {
	resp, m := c.do("POST", "/api/login", map[string]string{"user": user, "password": pw}, nil)
	if resp.StatusCode == 200 {
		c.csrf, _ = m["csrf"].(string)
	}
	return resp.StatusCode
}

func setup(t *testing.T) (*httptest.Server, func(string) *client) {
	t.Helper()
	auth.BcryptCost = 4 // bcrypt.MinCost: keeps tests fast
	dir := t.TempDir()
	wd := filepath.Join(dir, "jails")
	testWorkdir = wd
	if err := devfixture.Build(wd); err != nil {
		t.Fatal(err)
	}
	_, file, _, _ := runtime.Caller(0)
	fake := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "fake-cbsd")
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.TLSAuto = false
	cfg.Workdir = wd
	cfg.DistDir = filepath.Join(dir, "dist")
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.UsersFile = filepath.Join(dir, "users.json")
	cfg.AuditLog = filepath.Join(dir, "audit.log")
	cfg.CBSDCommand = []string{"/bin/sh", fake}
	cfg.InitenvCommand = []string{"/bin/sh", fake, "initenv"}
	users, err := auth.OpenStore(cfg.UsersFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []struct {
		n string
		r auth.Role
	}{{"admin", auth.RoleAdmin}, {"oper", auth.RoleOperator}, {"view", auth.RoleViewer}} {
		if err := users.Set(u.n, "password-"+u.n, u.r); err != nil {
			t.Fatal(err)
		}
	}
	al, _ := audit.Open(cfg.AuditLog)
	s, err := New(cfg, users, al, "test")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); s.Close(); al.Close() })
	return ts, func(user string) *client {
		jar, _ := cookiejar.New(nil)
		c := &client{t: t, base: ts.URL, hc: &http.Client{Jar: jar, Timeout: 20 * time.Second}}
		if user != "" {
			if code := c.login(user, "password-"+user); code != 200 {
				t.Fatalf("login %s: %d", user, code)
			}
		}
		return c
	}
}

func TestAuthAndHeaders(t *testing.T) {
	_, newClient := setup(t)
	anon := newClient("")
	resp, _ := anon.do("GET", "/api/envs", nil, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("anonymous access: %d", resp.StatusCode)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP missing: %q", csp)
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("security headers missing")
	}
	if code := anon.login("admin", "wrong-password"); code != 401 {
		t.Fatalf("bad password: %d", code)
	}
	if code := anon.login("nosuchuser", "whatever-pass"); code != 401 {
		t.Fatalf("unknown user: %d", code)
	}
	// Lockout after repeated failures from one IP.
	for i := 0; i < 5; i++ {
		anon.login("admin", "wrong-password")
	}
	if code := anon.login("admin", "password-admin"); code != 429 {
		t.Fatalf("expected lockout, got %d", code)
	}
}

func TestCookieFlags(t *testing.T) {
	ts, _ := setup(t)
	b, _ := json.Marshal(map[string]string{"user": "admin", "password": "password-admin"})
	resp, err := http.Post(ts.URL+"/api/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := resp.Header.Get("Set-Cookie")
	if !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "SameSite=Strict") {
		t.Errorf("cookie flags: %s", sc)
	}
}

func TestCSRFAndRoles(t *testing.T) {
	_, newClient := setup(t)
	view := newClient("view")
	resp, m := view.do("GET", "/api/envs?emulator=jail", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("viewer list: %d %v", resp.StatusCode, m)
	}
	if n := len(m["envs"].([]any)); n != 3 {
		t.Errorf("expected 3 jails, got %d", n)
	}
	resp, _ = view.do("POST", "/api/envs/build/action", map[string]string{"action": "start"}, nil)
	if resp.StatusCode != 403 {
		t.Errorf("viewer start: %d", resp.StatusCode)
	}

	op := newClient("oper")
	tok := op.csrf
	op.csrf = ""
	resp, _ = op.do("POST", "/api/envs/build/action", map[string]string{"action": "start"}, nil)
	if resp.StatusCode != 403 {
		t.Errorf("missing CSRF token accepted: %d", resp.StatusCode)
	}
	op.csrf = tok
	resp, _ = op.do("POST", "/api/envs/build/action", map[string]string{"action": "start"}, map[string]string{"Origin": "https://evil.example"})
	if resp.StatusCode != 403 {
		t.Errorf("cross-origin accepted: %d", resp.StatusCode)
	}
	resp, _ = op.do("POST", "/api/envs/build/action", map[string]string{"action": "remove"}, nil)
	if resp.StatusCode != 403 {
		t.Errorf("operator remove: %d", resp.StatusCode)
	}
	resp, _ = op.do("GET", "/api/users", nil, nil)
	if resp.StatusCode != 403 {
		t.Errorf("operator users: %d", resp.StatusCode)
	}

	admin := newClient("admin")
	resp, m = admin.do("POST", "/api/envs/db1/action", map[string]string{"action": "remove"}, nil)
	if resp.StatusCode != 409 {
		t.Errorf("protected env removal: %d %v", resp.StatusCode, m)
	}
}

func waitJob(t *testing.T, c *client, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, m := c.do("GET", "/api/jobs/"+id, nil, nil)
		job := m["job"].(map[string]any)
		if s := job["state"]; s == "done" || s == "failed" || s == "canceled" {
			return m
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return nil
}

func TestJobLifecycle(t *testing.T) {
	_, newClient := setup(t)
	op := newClient("oper")
	resp, m := op.do("POST", "/api/envs/build/action", map[string]string{"action": "start"}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("start: %d %v", resp.StatusCode, m)
	}
	id := m["job"].(map[string]any)["id"].(string)
	// A second operation on the same environment must be refused while the first runs.
	resp, _ = op.do("POST", "/api/envs/build/action", map[string]string{"action": "stop"}, nil)
	if resp.StatusCode != 409 {
		t.Errorf("concurrent op on same env: %d", resp.StatusCode)
	}
	res := waitJob(t, op, id)
	out := res["output"].(string)
	if res["job"].(map[string]any)["state"] != "done" {
		t.Fatalf("job failed: %v", res)
	}
	if !strings.Contains(out, "jstart jname=build") {
		t.Errorf("unexpected output: %q", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("ANSI codes not stripped: %q", out)
	}
}

func TestCreateValidation(t *testing.T) {
	_, newClient := setup(t)
	op := newClient("oper")
	resp, m := op.do("POST", "/api/jails", map[string]any{"jname": "x;reboot"}, nil)
	if resp.StatusCode != 422 || m["field"] != "jname" {
		t.Errorf("hostile name: %d %v", resp.StatusCode, m)
	}
	resp, m = op.do("POST", "/api/jails", map[string]any{"jname": "web1"}, nil)
	if resp.StatusCode != 422 {
		t.Errorf("duplicate name: %d %v", resp.StatusCode, m)
	}
	resp, _ = op.do("POST", "/api/jails", map[string]any{"jname": "ok1", "unknown_field": "x"}, nil)
	if resp.StatusCode != 400 {
		t.Errorf("unknown field accepted: %d", resp.StatusCode)
	}
	resp, m = op.do("POST", "/api/vms/bhyve", map[string]any{"jname": "vm9", "vm_os_type": "linux", "vm_os_profile": "nope", "vm_cpus": 1, "vm_ram": "1g", "imgsize": "10g"}, nil)
	if resp.StatusCode != 422 || m["field"] != "vm_os_profile" {
		t.Errorf("unknown profile: %d %v", resp.StatusCode, m)
	}
	resp, m = op.do("POST", "/api/vms/bhyve", map[string]any{"jname": "vm9", "vm_os_type": "linux", "vm_os_profile": "cloud-Debian-12-x86_64", "vm_cpus": 1, "vm_ram": "1g", "imgsize": "10g",
		"ci_user_pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host"}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("vm create: %d %v", resp.StatusCode, m)
	}
	res := waitJob(t, op, m["job"].(map[string]any)["id"].(string))
	if out := res["output"].(string); !strings.Contains(out, "ci_user_pubkey=/") {
		t.Errorf("pubkey should be passed as a file path: %q", out)
	}
}

func TestProfilesAndReadOnlyPages(t *testing.T) {
	_, newClient := setup(t)
	v := newClient("view")
	_, m := v.do("GET", "/api/profiles?emulator=xen", nil, nil)
	for _, p := range m["profiles"].([]any) {
		if p.(map[string]any)["cloud"] == true {
			t.Errorf("xen-inactive cloud profile listed: %v", p)
		}
	}
	for _, p := range []string{"/api/overview", "/api/images", "/api/bases", "/api/nodes", "/api/jobs", "/api/setup", "/api/envs/vm_freebsd"} {
		resp, m := v.do("GET", p, nil, nil)
		if resp.StatusCode != 200 {
			t.Errorf("%s: %d %v", p, resp.StatusCode, m)
		}
	}
	_, m = v.do("GET", "/api/nodes", nil, nil)
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "/secret/key") {
		t.Error("node key path leaked")
	}
}

func TestStaticAndSPA(t *testing.T) {
	ts, _ := setup(t)
	req, _ := http.NewRequest("GET", ts.URL+"/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" || resp.Header.Get("ETag") == "" {
		t.Errorf("static asset not compressed/etagged: %v", resp.Header)
	}
	req.Header.Set("If-None-Match", resp.Header.Get("ETag"))
	resp, _ = http.DefaultTransport.RoundTrip(req)
	resp.Body.Close()
	if resp.StatusCode != 304 {
		t.Errorf("ETag revalidation: %d", resp.StatusCode)
	}
}

func TestUsersAdmin(t *testing.T) {
	_, newClient := setup(t)
	a := newClient("admin")
	resp, _ := a.do("PUT", "/api/users/newbie", map[string]string{"role": "viewer", "password": "short"}, nil)
	if resp.StatusCode != 422 {
		t.Errorf("short password accepted: %d", resp.StatusCode)
	}
	resp, _ = a.do("PUT", "/api/users/newbie", map[string]string{"role": "viewer", "password": "long-enough-pw"}, nil)
	if resp.StatusCode != 200 {
		t.Errorf("create user: %d", resp.StatusCode)
	}
	resp, _ = a.do("DELETE", "/api/users/admin", nil, nil)
	if resp.StatusCode != 409 {
		t.Errorf("self delete: %d", resp.StatusCode)
	}
	// Demoting a user takes effect on their existing session immediately.
	op := newClient("oper")
	a.do("PUT", "/api/users/oper", map[string]string{"role": "viewer"}, nil)
	resp, _ = op.do("POST", "/api/envs/build/action", map[string]string{"action": "start"}, nil)
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		t.Errorf("demoted operator still allowed: %d", resp.StatusCode)
	}
	_, m := a.do("GET", "/api/audit", nil, nil)
	if len(m["entries"].([]any)) == 0 {
		t.Error("audit log empty")
	}
	_ = os.Remove
}
