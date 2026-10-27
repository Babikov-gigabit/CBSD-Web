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
	i, j := strings.Index(out, "jclone old=web1 new=web1_saved host_hostname=web1-saved ip4_addr=DHCP clone_method=rsync"), strings.Index(out, "jsnapshot mode=rollback jname=web1 snapname=web20251001093000")
	if i < 0 || j < i {
		t.Fatalf("steps out of order: %q", out)
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
