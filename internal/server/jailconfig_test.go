package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestJailConfigAndLimits(t *testing.T) {
	_, newClient := setup(t)
	view, oper, admin := newClient("view"), newClient("oper"), newClient("admin")

	resp, m := view.do("GET", "/api/envs/web1/config", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("config: %d %v", resp.StatusCode, m)
	}
	vals := m["values"].(map[string]any)
	if vals["devfs_ruleset"] != "4" || vals["sysvshm"] != "new" || vals["host_hostname"] != "web1.example.org" {
		t.Errorf("values: %v", vals)
	}
	if m["running"] != true || len(m["params"].([]any)) < 60 {
		t.Errorf("spec: running=%v params=%d", m["running"], len(m["params"].([]any)))
	}

	if resp, _ := view.do("PATCH", "/api/envs/build/config", map[string]any{"values": map[string]string{"allow_raw_sockets": "1"}}, nil); resp.StatusCode != 403 {
		t.Errorf("viewer patch: %d", resp.StatusCode)
	}
	if resp, m := oper.do("PATCH", "/api/envs/build/config", map[string]any{"values": map[string]string{"exec_master_poststart": "/root/up.sh"}}, nil); resp.StatusCode != 422 || m["field"] != "exec_master_poststart" {
		t.Errorf("operator hook: %d %v", resp.StatusCode, m)
	}
	if resp, m := oper.do("PATCH", "/api/envs/web1/config", map[string]any{"values": map[string]string{"vnet": "1"}}, nil); resp.StatusCode != 422 || m["field"] != "restart" {
		t.Errorf("running non-live: %d %v", resp.StatusCode, m)
	}
	resp, m = oper.do("PATCH", "/api/envs/build/config", map[string]any{"values": map[string]string{"allow_raw_sockets": "1", "sysvshm": "new"}}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("patch: %d %v", resp.StatusCode, m)
	}
	jobOutput(t, oper, m)
	if resp, m := admin.do("PATCH", "/api/envs/db1/config", map[string]any{"values": map[string]string{"exec_master_poststart": "/root/up.sh"}, "restart": true}, nil); resp.StatusCode != 202 {
		t.Errorf("admin hook: %d %v", resp.StatusCode, m)
	} else {
		jobOutput(t, admin, m)
	}

	resp, m = view.do("GET", "/api/envs/web1/limits", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("limits: %d %v", resp.StatusCode, m)
	}
	if lv := m["values"].(map[string]any); lv["memoryuse"] != "2g" || lv["pcpu"] != "50" {
		t.Errorf("limit values: %v", lv)
	}
	if u, _ := m["usage"].(map[string]any); u["memoryuse"] != "412M" {
		t.Errorf("usage: %v", m["usage"])
	}
	if resp, m := view.do("GET", "/api/envs/build/limits", nil, nil); resp.StatusCode != 200 || len(m["values"].(map[string]any)) != 0 {
		t.Errorf("no limits file: %d %v", resp.StatusCode, m)
	}
	if resp, m := oper.do("PUT", "/api/envs/build/limits", map[string]any{"values": map[string]string{"memoryuse": "1g;reboot"}}, nil); resp.StatusCode != 422 || m["field"] != "memoryuse" {
		t.Errorf("bad limit: %d %v", resp.StatusCode, m)
	}
	resp, m = oper.do("PUT", "/api/envs/build/limits", map[string]any{"values": map[string]string{"memoryuse": "1g", "pcpu": "100"}}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("limits put: %d %v", resp.StatusCode, m)
	}
	if out := jobOutput(t, oper, m); !strings.Contains(out, "jrctl mode=set jname=build memoryuse=1g pcpu=100") {
		t.Errorf("limits job output: %q", out)
	}
}

// jobOutput waits for the job in a 202 response and returns its output.
func jobOutput(t *testing.T, c *client, m map[string]any) string {
	t.Helper()
	res := waitJob(t, c, m["job"].(map[string]any)["id"].(string))
	if st := res["job"].(map[string]any)["state"]; st != "done" {
		t.Errorf("job state %v: %v", st, res["output"])
	}
	out, _ := res["output"].(string)
	return out
}

func dialTerminal(t *testing.T, c *client, path string, origin string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	return websocket.Dial(ctx, "ws"+strings.TrimPrefix(c.base, "http")+path, &websocket.DialOptions{HTTPClient: c.hc, HTTPHeader: h})
}

func TestTerminal(t *testing.T) {
	ts, newClient := setup(t)
	admin, oper := newClient("admin"), newClient("oper")

	// Operators are refused by default, and a missing CSRF token or foreign Origin is refused.
	if _, resp, err := dialTerminal(t, oper, "/api/envs/web1/terminal?csrf="+oper.csrf, ts.URL); err == nil || resp.StatusCode != 403 {
		t.Errorf("operator terminal: %v", err)
	}
	if _, resp, err := dialTerminal(t, admin, "/api/envs/web1/terminal", ts.URL); err == nil || resp.StatusCode != 403 {
		t.Errorf("no csrf: %v", err)
	}
	if _, resp, err := dialTerminal(t, admin, "/api/envs/web1/terminal?csrf="+admin.csrf, "https://evil.example"); err == nil || resp.StatusCode != 403 {
		t.Errorf("foreign origin: %v", err)
	}
	if _, resp, err := dialTerminal(t, admin, "/api/envs/build/terminal?csrf="+admin.csrf, ts.URL); err == nil || resp.StatusCode != 409 {
		t.Errorf("stopped jail: %v", err)
	}

	conn, _, err := dialTerminal(t, admin, "/api/envs/web1/terminal?cols=100&rows=30&csrf="+admin.csrf, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"resize","cols":90,"rows":25}`)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("echo marker-$((40+2))\n")); err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	for !strings.Contains(got.String(), "marker-42") {
		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v (got %q)", err, got.String())
		}
		got.Write(data)
	}
	if !strings.Contains(got.String(), "fake jlogin: jname=web1") {
		t.Errorf("banner missing: %q", got.String())
	}
	conn.Write(ctx, websocket.MessageBinary, []byte("exit\n"))
	for {
		if _, _, err := conn.Read(ctx); err != nil {
			break
		}
	}
}

func TestVMTerminal(t *testing.T) {
	ts, newClient := setup(t)
	admin := newClient("admin")
	if _, resp, err := dialTerminal(t, admin, "/api/envs/vm_debian/terminal?csrf="+admin.csrf, ts.URL); err == nil || resp.StatusCode != 409 {
		t.Errorf("stopped VM: %v", err)
	}
	conn, _, err := dialTerminal(t, admin, "/api/envs/vm_freebsd/terminal?csrf="+admin.csrf, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var got strings.Builder
	for !strings.Contains(got.String(), "fake blogin: jname=vm_freebsd remote=1") {
		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v (got %q)", err, got.String())
		}
		got.Write(data)
	}
}

func TestVMConfig(t *testing.T) {
	_, newClient := setup(t)
	view, oper, admin := newClient("view"), newClient("oper"), newClient("admin")

	resp, m := view.do("GET", "/api/envs/vm_freebsd/config", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("config: %d %v", resp.StatusCode, m)
	}
	vals := m["values"].(map[string]any)
	if vals["vm_ram"] != "2g" || vals["vm_cpus"] != "2" || vals["vm_efi"] != "uefi" || vals["cd_vnc_wait"] != "1" || m["command"] != "bset" {
		t.Errorf("values: %v", vals)
	}
	if vals["vnc_password"] != "" || m["secret_set"].(map[string]any)["vnc_password"] != true {
		t.Errorf("VNC password leaked or not flagged: %v %v", vals["vnc_password"], m["secret_set"])
	}
	if resp, _ := view.do("PATCH", "/api/envs/vm_freebsd/config", map[string]any{"values": map[string]string{"vm_cpus": "4"}}, nil); resp.StatusCode != 403 {
		t.Errorf("viewer patch: %d", resp.StatusCode)
	}
	if resp, m := oper.do("PATCH", "/api/envs/vm_freebsd/config", map[string]any{"values": map[string]string{"vnc_password": "newpass123"}}, nil); resp.StatusCode != 422 || m["field"] != "vnc_password" {
		t.Errorf("operator password: %d %v", resp.StatusCode, m)
	}
	for k, v := range map[string]string{"vm_ram": "4g;reboot", "bhyve_vnc_resolution": "big", "vm_efi": "bios", "nosuch": "1", "vm_cpus": "0"} {
		if resp, m := oper.do("PATCH", "/api/envs/vm_freebsd/config", map[string]any{"values": map[string]string{k: v}}, nil); resp.StatusCode != 422 || m["field"] != k {
			t.Errorf("bad %s=%s: %d %v", k, v, resp.StatusCode, m)
		}
	}
	resp, m = oper.do("PATCH", "/api/envs/vm_freebsd/config", map[string]any{"values": map[string]string{"vm_cpus": "4", "vm_ram": "4G", "cd_vnc_wait": "0"}, "restart": true}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("patch: %d %v", resp.StatusCode, m)
	}
	out := jobOutput(t, oper, m)
	if !strings.Contains(out, "bset jname=vm_freebsd vm_cpus=4 vm_ram=4g cd_vnc_wait=0") || !strings.Contains(out, "bstop jname=vm_freebsd") || !strings.Contains(out, "bstart jname=vm_freebsd") {
		t.Errorf("output: %s", out)
	}
	resp, m = admin.do("PATCH", "/api/envs/xen1/config", map[string]any{"values": map[string]string{"vnc_password": "newpass123", "xen_vnc_resolution": "1280x1024"}}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("xen patch: %d %v", resp.StatusCode, m)
	}
	if out := jobOutput(t, admin, m); !strings.Contains(out, "$ cbsd xset jname=xen1 xen_vnc_resolution=1280x1024 vnc_password=***\n") {
		t.Errorf("xen output: %s", out)
	}
}

func TestVMInstallFlow(t *testing.T) {
	_, newClient := setup(t)
	view, oper := newClient("view"), newClient("oper")

	resp, m := view.do("GET", "/api/envs/vm_freebsd/media", nil, nil)
	if resp.StatusCode != 200 || m["cd_vnc_wait"] != true || len(m["attached"].([]any)) != 1 {
		t.Fatalf("media: %d %v", resp.StatusCode, m)
	}
	if resp, _ := view.do("POST", "/api/envs/vm_freebsd/media", map[string]string{"action": "eject"}, nil); resp.StatusCode != 403 {
		t.Errorf("viewer action: %d", resp.StatusCode)
	}
	if resp, _ := view.do("GET", "/api/envs/build/media", nil, nil); resp.StatusCode != 400 {
		t.Errorf("jail media: %d", resp.StatusCode)
	}
	if resp, m := oper.do("POST", "/api/envs/vm_debian/media", map[string]string{"action": "install"}, nil); resp.StatusCode != 422 || m["field"] != "iso" {
		t.Errorf("install without ISO: %d %v", resp.StatusCode, m)
	}
	for _, bad := range []string{"nosuch", "x;reboot"} {
		if resp, m := oper.do("POST", "/api/envs/vm_freebsd/media", map[string]string{"action": "attach", "iso": bad}, nil); resp.StatusCode != 422 {
			t.Errorf("attach %q: %d %v", bad, resp.StatusCode, m)
		}
	}

	for _, c := range []struct {
		body map[string]string
		want []string
	}{
		{map[string]string{"action": "attach", "iso": "web-alpine-3.20"}, []string{
			"media mode=eject jname=vm_freebsd", "media mode=attach name=web-alpine-3.20", "bset jname=vm_freebsd vm_iso_path=web-alpine-3.20"}},
		{map[string]string{"action": "install"}, []string{
			"bstop jname=vm_freebsd", "bset jname=vm_freebsd vm_boot=cd", "bstart jname=vm_freebsd"}},
		{map[string]string{"action": "finish"}, []string{
			"bset jname=vm_freebsd vm_boot=hdd vm_iso_path=0", "media mode=eject jname=vm_freebsd", "bstart jname=vm_freebsd"}},
		{map[string]string{"action": "eject"}, []string{"bset jname=vm_freebsd vm_iso_path=0"}},
	} {
		resp, m := oper.do("POST", "/api/envs/vm_freebsd/media", c.body, nil)
		if resp.StatusCode != 202 {
			t.Fatalf("%v: %d %v", c.body, resp.StatusCode, m)
		}
		out := jobOutput(t, oper, m)
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%v: missing %q in %s", c.body, w, out)
			}
		}
	}
}
