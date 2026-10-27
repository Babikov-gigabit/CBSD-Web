package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/cbsd-web/cbsd-web/internal/hoststat"
)

func useFakeTools(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	hoststat.UseToolsDir(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "fake-tools"))
	t.Cleanup(func() { hoststat.UseToolsDir("/nonexistent") })
}

func TestSnapshotsAndStats(t *testing.T) {
	_, newClient := setup(t)
	useFakeTools(t)
	view := newClient("view")

	resp, m := view.do("GET", "/api/envs/web1/snapshots", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("snapshots: %d %v", resp.StatusCode, m)
	}
	list := m["snapshots"].([]any)
	if len(list) != 2 {
		t.Fatalf("snapshots: %v", m)
	}
	s0 := list[0].(map[string]any)
	if s0["name"] != "web20251001093000" || s0["dataset"] != "zroot/jails/web1" || s0["created"] != "2025-10-01 09:30" ||
		s0["path"] != "/usr/jails/jails-data/web1-data/.zfs/snapshot/web20251001093000" || s0["used"] != float64(52428800) {
		t.Errorf("snapshot item: %v", s0)
	}

	resp, m = view.do("GET", "/api/envs/web1/stats", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("stats: %d %v", resp.StatusCode, m)
	}
	nics, _ := m["nics"].([]any)
	if len(nics) != 1 || nics[0].(map[string]any)["name"] != "epair3a" || nics[0].(map[string]any)["bridge"] != "bridge1" {
		t.Errorf("nics: %v", m)
	}
	if p, _ := m["procs"].(map[string]any); p["count"] != float64(3) {
		t.Errorf("procs: %v", m["procs"])
	}
	if d, _ := m["disk"].(map[string]any); d["name"] != "zroot/jails/web1" {
		t.Errorf("disk: %v", m["disk"])
	}

	oper := newClient("oper")
	if resp, m := oper.do("POST", "/api/envs/web1/snapshots", map[string]string{"mode": "destroyall"}, nil); resp.StatusCode != 403 {
		t.Errorf("operator destroyall: %d %v", resp.StatusCode, m)
	}
	admin := newClient("admin")
	resp, m = admin.do("POST", "/api/envs/web1/snapshots", map[string]string{"mode": "destroyall"}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("destroyall: %d %v", resp.StatusCode, m)
	}
	if out := jobOutput(t, admin, m); !strings.Contains(out, "jsnapshot mode=destroyall jname=web1") {
		t.Errorf("destroyall output: %q", out)
	}
}

func TestVNC(t *testing.T) {
	ts, newClient := setup(t)
	// A fake VNC server that greets and echoes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); c.Write([]byte("RFB 003.008\n")); io.Copy(c, c) }()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	db, err := sql.Open("sqlite", filepath.Join(testWorkdir, "var", "db", "local.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE bhyve SET vm_vnc_port=?, bhyve_vnc_tcp_bind='0.0.0.0'`, port); err != nil {
		t.Fatal(err)
	}
	db.Exec(`ALTER TABLE bhyve ADD COLUMN vnc_password TEXT DEFAULT ''`)
	db.Exec(`UPDATE bhyve SET vnc_password='s3cret' WHERE jname='vm_freebsd'`)
	db.Close()

	oper, admin := newClient("oper"), newClient("admin")
	_, m := oper.do("GET", "/api/envs/vm_freebsd/vnc", nil, nil)
	if _, has := m["password"]; has || m["has_password"] != true || m["port"] != float64(port) {
		t.Errorf("operator vnc info: %v", m)
	}
	if _, m := admin.do("GET", "/api/envs/vm_freebsd/vnc", nil, nil); m["password"] != "s3cret" {
		t.Errorf("admin vnc info: %v", m)
	}
	_, m = oper.do("GET", "/api/envs/vm_freebsd", nil, nil)
	if strings.Contains(strconv.Quote(toJSON(m)), "s3cret") {
		t.Error("env leaks the VNC password")
	}
	if _, resp, err := dialTerminal(t, oper, "/api/envs/vm_freebsd/vnc/ws?csrf="+oper.csrf, ts.URL); err == nil || resp.StatusCode != 403 {
		t.Errorf("operator vnc ws: %v", err)
	}
	if _, resp, err := dialTerminal(t, admin, "/api/envs/vm_freebsd/vnc/ws", ts.URL); err == nil || resp.StatusCode != 403 {
		t.Errorf("vnc without csrf: %v", err)
	}
	conn, _, err := dialTerminal(t, admin, "/api/envs/vm_freebsd/vnc/ws?csrf="+admin.csrf, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var got []byte
	for len(got) < 12 {
		_, d, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, d...)
	}
	if string(got) != "RFB 003.008\n" {
		t.Fatalf("greeting %q", got)
	}
	conn.Write(ctx, websocket.MessageBinary, []byte("ping"))
	_, d, err := conn.Read(ctx)
	if err != nil || string(d) != "ping" {
		t.Fatalf("echo %q %v", d, err)
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
