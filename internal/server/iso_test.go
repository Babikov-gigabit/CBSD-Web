package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cbsd-web/cbsd-web/internal/config"
	"github.com/cbsd-web/cbsd-web/internal/devfixture"
)

// testISO is bigger than the generic 64 KiB API body limit on purpose.
func testISO() []byte { return append(devfixture.FakeISO(), make([]byte, 300<<10)...) }

func (c *client) upload(name string, body []byte, hdr map[string]string) (*http.Response, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest("POST", c.base+"/api/isos/upload?name="+name, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.csrf != "" {
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

func isoByMedia(m map[string]any, media string) map[string]any {
	for _, v := range m["isos"].([]any) {
		if it := v.(map[string]any); it["media"] == media {
			return it
		}
	}
	return nil
}

func uploadDir() string { return filepath.Join(testWorkdir, "src", "iso", "upload") }

func TestISOList(t *testing.T) {
	_, newClient := setup(t)
	resp, m := newClient("view").do("GET", "/api/isos", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list: %d %v", resp.StatusCode, m)
	}
	if m["writable"] != true {
		t.Errorf("upload dir not writable: %v", m["dir_error"])
	}
	a := isoByMedia(m, "web-alpine-3.20")
	if a == nil || a["uploaded"] != true || a["registered"] != true || a["usable"] != true || a["file"] != "alpine-3.20.iso" {
		t.Errorf("uploaded ISO: %v", a)
	}
	f := isoByMedia(m, "iso-FreeBSD-14.3")
	if f == nil || f["uploaded"] != false || f["usable"] != true || len(f["attached_to"].([]any)) != 1 {
		t.Errorf("CBSD ISO: %v", f)
	}
	if isoByMedia(m, "hdd-vm_freebsd") != nil {
		t.Error("disk images must not be listed as ISO")
	}
}

func TestISOUpload(t *testing.T) {
	_, newClient := setup(t)
	if resp, _ := newClient("oper").upload("x.iso", testISO(), nil); resp.StatusCode != 403 {
		t.Errorf("operator upload: %d", resp.StatusCode)
	}
	admin := newClient("admin")
	tok := admin.csrf
	admin.csrf = ""
	if resp, _ := admin.upload("x.iso", testISO(), nil); resp.StatusCode != 403 {
		t.Errorf("upload without CSRF token: %d", resp.StatusCode)
	}
	admin.csrf = tok
	for _, bad := range []string{"..%2Fetc%2Fpasswd.iso", "a%3Breboot.iso", "a.img", ".hidden.iso"} {
		if resp, _ := admin.upload(bad, testISO(), nil); resp.StatusCode != 422 {
			t.Errorf("bad name %q: %d", bad, resp.StatusCode)
		}
	}
	resp, m := admin.upload("debian-12.iso", testISO(), nil)
	if resp.StatusCode != 200 || m["media"] != "web-debian-12" || len(m["sha256"].(string)) != 64 {
		t.Fatalf("upload: %d %v", resp.StatusCode, m)
	}
	if b, err := os.ReadFile(filepath.Join(uploadDir(), "debian-12.iso")); err != nil || len(b) != len(testISO()) {
		t.Fatalf("stored file: %v %d", err, len(b))
	}
	if resp, m := admin.upload("debian-12.iso", testISO(), nil); resp.StatusCode != 422 || !strings.Contains(m["error"].(string), "уже есть") {
		t.Errorf("overwrite: %d %v", resp.StatusCode, m)
	}
	if resp, _ := admin.upload("notiso.iso", bytes.Repeat([]byte("x"), 100<<10), nil); resp.StatusCode != 422 {
		t.Errorf("non-ISO content: %d", resp.StatusCode)
	}
	if resp, _ := admin.upload("sum.iso", testISO(), map[string]string{"X-Content-SHA256": strings.Repeat("0", 64)}); resp.StatusCode != 422 {
		t.Errorf("checksum mismatch: %d", resp.StatusCode)
	}
	if resp, _ := admin.upload("fail-reg.iso", testISO(), nil); resp.StatusCode != 422 {
		t.Errorf("failed registration: %d", resp.StatusCode)
	}
	ents, _ := os.ReadDir(uploadDir())
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if got := strings.Join(names, " "); got != "alpine-3.20.iso debian-12.iso" {
		t.Errorf("rejected uploads left files behind: %s", got)
	}
}

func TestISODelete(t *testing.T) {
	_, newClient := setup(t)
	if resp, _ := newClient("oper").do("DELETE", "/api/isos/alpine-3.20.iso", nil, nil); resp.StatusCode != 403 {
		t.Errorf("operator delete: %d", resp.StatusCode)
	}
	admin := newClient("admin")
	if resp, _ := admin.do("DELETE", "/api/isos/FreeBSD-14.3.iso", nil, nil); resp.StatusCode != 404 {
		t.Errorf("deleting outside the upload dir: %d", resp.StatusCode)
	}
	if resp, m := admin.do("DELETE", "/api/isos/alpine-3.20.iso", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("delete: %d %v", resp.StatusCode, m)
	}
	if _, err := os.Stat(filepath.Join(uploadDir(), "alpine-3.20.iso")); !os.IsNotExist(err) {
		t.Error("file still there")
	}
}

func TestISOFetch(t *testing.T) {
	iso := testISO()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(iso)
	}))
	defer src.Close()

	// Loopback is refused unless explicitly allowed.
	_, newClient := setup(t)
	admin := newClient("admin")
	resp, m := admin.do("POST", "/api/isos/fetch", map[string]string{"url": src.URL + "/dl/netinst.iso"}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("fetch: %d %v", resp.StatusCode, m)
	}
	res := waitJob(t, admin, m["job"].(map[string]any)["id"].(string))
	if job := res["job"].(map[string]any); job["state"] != "failed" || !strings.Contains(job["error"].(string), "внутренней сети") {
		t.Errorf("private address not refused: %v", job)
	}
	for _, bad := range []map[string]string{{"url": "file:///etc/passwd"}, {"url": "ftp://x/a.iso"}, {"url": "https://u:p@x/a.iso"}, {"url": "https://x/a.exe"}} {
		if resp, _ := admin.do("POST", "/api/isos/fetch", bad, nil); resp.StatusCode != 422 {
			t.Errorf("bad request %v: %d", bad, resp.StatusCode)
		}
	}

	_, newClient = setup(t, func(c *config.Config) { c.ISOFetchAllowPrivate = true })
	admin = newClient("admin")
	resp, m = admin.do("POST", "/api/isos/fetch", map[string]string{"url": src.URL + "/dl/netinst.iso"}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("fetch: %d %v", resp.StatusCode, m)
	}
	res = waitJob(t, admin, m["job"].(map[string]any)["id"].(string))
	if job := res["job"].(map[string]any); job["state"] != "done" {
		t.Fatalf("fetch job: %v %s", job, res["output"])
	}
	if out := res["output"].(string); !strings.Contains(out, "mode=register name=web-netinst") {
		t.Errorf("not registered: %s", out)
	}
	if fi, err := os.Stat(filepath.Join(uploadDir(), "netinst.iso")); err != nil || fi.Size() != int64(len(iso)) {
		t.Errorf("downloaded file: %v", err)
	}
}

func TestVMCreateWithISO(t *testing.T) {
	_, newClient := setup(t)
	op := newClient("oper")
	vm := map[string]any{"jname": "vm9", "vm_os_type": "linux", "vm_os_profile": "Debian-12-x86_64", "vm_cpus": 1, "vm_ram": "1g", "imgsize": "10g", "iso": "web-alpine-3.20"}
	resp, m := op.do("POST", "/api/vms/bhyve", vm, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("create: %d %v", resp.StatusCode, m)
	}
	out := waitJob(t, op, m["job"].(map[string]any)["id"].(string))["output"].(string)
	if !strings.Contains(out, "register_iso_as=web-alpine-3.20 register_iso_name=upload/alpine-3.20.iso vm_iso_path=web-alpine-3.20") {
		t.Errorf("ISO args missing: %s", out)
	}
	vm["jname"], vm["iso"] = "vm10", "nope"
	if resp, m := op.do("POST", "/api/vms/bhyve", vm, nil); resp.StatusCode != 422 || m["field"] != "iso" {
		t.Errorf("unknown ISO: %d %v", resp.StatusCode, m)
	}
	vm["iso"], vm["vm_os_profile"] = "web-alpine-3.20", "cloud-Debian-12-x86_64"
	if resp, m := op.do("POST", "/api/vms/bhyve", vm, nil); resp.StatusCode != 422 || m["field"] != "iso" {
		t.Errorf("ISO with cloud profile: %d %v", resp.StatusCode, m)
	}
}

func TestEnvLogs(t *testing.T) {
	_, newClient := setup(t)
	if resp, _ := newClient("view").do("GET", "/api/envs/vm_freebsd/logs", nil, nil); resp.StatusCode != 403 {
		t.Errorf("viewer logs: %d", resp.StatusCode)
	}
	op := newClient("oper")
	resp, m := op.do("GET", "/api/envs/vm_freebsd/logs", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("logs: %d %v", resp.StatusCode, m)
	}
	first := m["logs"].([]any)[0].(map[string]any)
	text := first["text"].(string)
	if !strings.HasPrefix(first["title"].(string), "bstart.log") || !strings.Contains(text, "bhyve exited with code 4") {
		t.Errorf("bstart.log: %v", first)
	}
	if strings.Contains(text, "secret123") || !strings.Contains(text, "password=***") {
		t.Errorf("VNC password not redacted: %s", text)
	}
	if resp, _ := op.do("GET", "/api/envs/..%2Fetc/logs", nil, nil); resp.StatusCode != 400 && resp.StatusCode != 404 {
		t.Errorf("hostile name: %d", resp.StatusCode)
	}
}
