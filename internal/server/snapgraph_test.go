package server

import (
	"strings"
	"testing"
)

func TestSnapshotGraphAndRollbackBranch(t *testing.T) {
	_, newClient := setup(t)
	useFakeTools(t)
	view, admin := newClient("view"), newClient("admin")

	resp, g := view.do("GET", "/api/envs/web1/snapshots/graph", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("graph: %d %v", resp.StatusCode, g)
	}
	snaps := g["snapshots"].([]any)
	if len(snaps) != 3 || snaps[0].(map[string]any)["cbsd"] != false || snaps[1].(map[string]any)["cbsd"] != true {
		t.Fatalf("snapshots: %v", snaps)
	}
	br := g["branches"].([]any)
	envs := map[string]string{}
	for _, b := range br {
		m := b.(map[string]any)
		envs[m["env"].(string)] = m["snap"].(string)
	}
	if envs["build"] != "web20251001093000" || envs["db1"] != "base-install" {
		t.Errorf("branches: %v", br)
	}
	if _, g := view.do("GET", "/api/envs/build/snapshots/graph", nil, nil); g["parent"].(map[string]any)["env"] != "web1" {
		t.Errorf("parent: %v", g["parent"])
	}

	if resp, m := admin.do("POST", "/api/envs/web1/snapshots", map[string]string{"mode": "rollback", "snapname": "web20251001093000", "save_as": "db1"}, nil); resp.StatusCode != 422 || m["field"] != "save_as" {
		t.Errorf("taken branch name: %d %v", resp.StatusCode, m)
	}
	if resp, m := admin.do("POST", "/api/envs/web1/snapshots", map[string]string{"mode": "rollback", "snapname": "web20251001093000", "save_as": "x;id"}, nil); resp.StatusCode != 422 {
		t.Errorf("bad branch name: %d %v", resp.StatusCode, m)
	}
	resp, m := admin.do("POST", "/api/envs/web1/snapshots", map[string]string{"mode": "rollback", "snapname": "web20251001093000", "save_as": "web1_saved"}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("rollback: %d %v", resp.StatusCode, m)
	}
	out := jobOutput(t, admin, m)
	// web1 is running: stop, copy, roll back, start again.
	last := -1
	for _, want := range []string{"$ cbsd jstop jname=web1", "jclone old=web1 new=web1_saved host_hostname=web1-saved ip4_addr=DHCP clone_method=rsync",
		"jsnapshot mode=rollback jname=web1 snapname=web20251001093000", "$ cbsd jstart jname=web1"} {
		i := strings.Index(out, want)
		if i <= last {
			t.Fatalf("step %q missing or out of order: %q", want, out)
		}
		last = i
	}
	_, g = view.do("GET", "/api/envs/web1/snapshots/graph", nil, nil)
	hist := g["history"].([]any)
	if len(hist) != 1 {
		t.Fatalf("history: %v", g["history"])
	}
	ev := hist[0].(map[string]any)
	lost := ev["lost"].([]any)
	if ev["to"] != "web20251001093000" || ev["branch"] != "web1_saved" || ev["user"] != "admin" || len(lost) != 1 || lost[0].(map[string]any)["name"] != "before-upgrade" {
		t.Errorf("event: %v", ev)
	}
}

func TestCloneRunningJail(t *testing.T) {
	_, newClient := setup(t)
	oper := newClient("oper")
	resp, m := oper.do("POST", "/api/envs/web1/clone", map[string]string{"new": "web1copy"}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("clone: %d %v", resp.StatusCode, m)
	}
	out := jobOutput(t, oper, m)
	a, b, c := strings.Index(out, "$ cbsd jstop jname=web1"), strings.Index(out, "$ cbsd jclone old=web1"), strings.Index(out, "$ cbsd jstart jname=web1")
	if a < 0 || b < a || c < b {
		t.Fatalf("clone steps: %q", out)
	}
	// A failing step still starts the jail again.
	resp, m = oper.do("POST", "/api/envs/web1/clone", map[string]string{"new": "fail"}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("clone fail: %d %v", resp.StatusCode, m)
	}
	res := waitJob(t, oper, m["job"].(map[string]any)["id"].(string))
	if out := res["output"].(string); res["job"].(map[string]any)["state"] != "failed" || !strings.Contains(out, "$ cbsd jstart jname=web1") {
		t.Fatalf("failed clone must restart: %v %q", res["job"], out)
	}
}

func TestOpenSnapshotAsJail(t *testing.T) {
	_, newClient := setup(t)
	useFakeTools(t)
	view, admin := newClient("view"), newClient("admin")

	req := map[string]any{"mode": "try", "snapname": "web20251001093000", "new": "web1_try", "keep": "before_try", "start": true}
	if resp, m := view.do("POST", "/api/envs/web1/snapshots", req, nil); resp.StatusCode != 403 {
		t.Errorf("viewer: %d %v", resp.StatusCode, m)
	}
	for field, bad := range map[string]map[string]any{
		"new":      {"mode": "try", "snapname": "web20251001093000", "new": "db1"},
		"keep":     {"mode": "try", "snapname": "web20251001093000", "new": "web1_t2", "keep": "a b"},
		"snapname": {"mode": "try", "snapname": "x;id", "new": "web1_t3"},
	} {
		if resp, m := admin.do("POST", "/api/envs/web1/snapshots", bad, nil); resp.StatusCode != 422 || m["field"] != field {
			t.Errorf("%s: %d %v", field, resp.StatusCode, m)
		}
	}
	resp, m := admin.do("POST", "/api/envs/web1/snapshots", req, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("try: %d %v", resp.StatusCode, m)
	}
	out := jobOutput(t, admin, m)
	// The source jail is neither stopped nor rolled back.
	if strings.Contains(out, "jstop") || strings.Contains(out, "rollback") {
		t.Errorf("source touched: %q", out)
	}
	last := -1
	for _, want := range []string{"jsnapshot mode=create jname=web1 snapname=before_try",
		"jcreate jname=web1_try zfs_snapsrc=zroot/jails/web1@web20251001093000 ver=", "runasap=1"} {
		i := strings.Index(out, want)
		if i <= last {
			t.Fatalf("step %q missing or out of order: %q", want, out)
		}
		last = i
	}
	_, g := view.do("GET", "/api/envs/web1/snapshots/graph", nil, nil)
	hist := g["history"].([]any)
	if len(hist) != 1 {
		t.Fatalf("history: %v", hist)
	}
	if ev := hist[0].(map[string]any); ev["type"] != "try" || ev["branch"] != "web1_try" || ev["kept"] != "before_try" {
		t.Errorf("event: %v", ev)
	}
}
