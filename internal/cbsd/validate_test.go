package cbsd

import (
	"strings"
	"testing"
)

var hostile = []string{
	"a;reboot", "a$(id)", "a`id`", "a b", "a\nb", "a'b", `a"b`, "a|b", "a&b", "a>b", "-rf", "../etc", "a\x00b", "a\\b", "a{b}", "a*",
}

func TestNamesRejectShellMetacharacters(t *testing.T) {
	for _, s := range hostile {
		if ValidNewName(s) || ValidExistingName(s) {
			t.Errorf("name %q accepted", s)
		}
	}
	for _, s := range []string{"web1", "db_2", "A1"} {
		if !ValidNewName(s) {
			t.Errorf("name %q rejected", s)
		}
	}
	if ValidNewName("1abc") || ValidNewName("") {
		t.Error("names must start with a letter")
	}
}

func TestJailCreateArgs(t *testing.T) {
	j := JailCreate{Name: "web1", IP4: "10.0.0.5/24,192.168.1.2", PkgList: "nginx git-lite", RunASAP: true}
	args, err := j.Args()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\x00")
	for _, want := range []string{"jcreate", "jname=web1", "host_hostname=web1", "ip4_addr=10.0.0.5/24,192.168.1.2", "ver=native", "runasap=1", "pkglist=nginx git-lite"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}
	for _, bad := range []JailCreate{
		{Name: "web1", IP4: "10.0.0.1;reboot"},
		{Name: "web1", Hostname: "$(id)"},
		{Name: "web1", Ver: "14.2;id"},
		{Name: "web1", PkgList: "nginx;id"},
		{Name: "web1", PkgList: "nginx $(id)"},
		{Name: "web1", Interface: "em0;id"},
		{Name: "web 1"},
	} {
		if _, err := bad.Args(); err == nil {
			t.Errorf("accepted hostile jail form %+v", bad)
		}
	}
}

func TestVMCreateArgs(t *testing.T) {
	v := VMCreate{Name: "vm1", OSType: "linux", Profile: "cloud-Debian-12-x86_64", CPUs: 2, RAM: "2G", ImgSize: "20g", CIIP4: "10.0.0.9/24", CIGW4: "10.0.0.1"}
	args, err := v.Args("bhyve", "/var/db/cbsd-web/pubkeys/x.pub")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"bcreate", "vm_ram=2g", "vm_cpus=2", "bhyve_vnc_tcp_bind=127.0.0.1", "ci_user_pubkey=/var/db/cbsd-web/pubkeys/x.pub"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}
	bad := []VMCreate{
		{Name: "vm1", OSType: "linux", Profile: "x;id", CPUs: 1, RAM: "1g", ImgSize: "10g"},
		{Name: "vm1", OSType: "linux", Profile: "p", CPUs: 0, RAM: "1g", ImgSize: "10g"},
		{Name: "vm1", OSType: "linux", Profile: "p", CPUs: 1, RAM: "1g;id", ImgSize: "10g"},
		{Name: "vm1", OSType: "linux", Profile: "p", CPUs: 1, RAM: "1g", ImgSize: "10g", VNCPass: "a b'c"},
		{Name: "vm1", OSType: "linux", Profile: "p", CPUs: 1, RAM: "1g", ImgSize: "10g", VNCBind: "0.0.0.0;id"},
		{Name: "vm1", OSType: "linux", Profile: "p", CPUs: 1, RAM: "1g", ImgSize: "10g", CIUser: "root$(id)"},
	}
	for _, b := range bad {
		if _, err := b.Args("bhyve", ""); err == nil {
			t.Errorf("accepted hostile vm form %+v", b)
		}
	}
	if args, _ := v.Args("xen", ""); args[0] != "xcreate" {
		t.Errorf("xen should use xcreate, got %v", args[0])
	}
}

func TestPubKey(t *testing.T) {
	ok := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host"
	if !ValidPubKey(ok) {
		t.Error("valid key rejected")
	}
	for _, k := range []string{ok + "\nssh-rsa AAAA", "ssh-ed25519 $(reboot)", "ssh-ed25519 AAAA; id", "command=\"id\" " + ok} {
		if ValidPubKey(k) {
			t.Errorf("hostile key accepted: %q", k)
		}
	}
}

func TestActionArgs(t *testing.T) {
	cases := map[string][]string{
		"jail":  {"jstart", "jname=web1"},
		"bhyve": {"bstart", "jname=web1"},
		"xen":   {"xstart", "jname=web1"},
	}
	for emu, want := range cases {
		got, err := ActionArgs(emu, ActStart, "web1")
		if err != nil || strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: got %v %v", emu, got, err)
		}
	}
	if _, err := ActionArgs("jail", "reboot", "web1"); err == nil {
		t.Error("unknown action accepted")
	}
	if _, err := ActionArgs("jail", ActStart, "a;b"); err == nil {
		t.Error("bad name accepted")
	}
	if _, err := ActionArgs("xen", ActRestart, "x"); err == nil {
		t.Error("xen restart should be rejected")
	}
}

func TestInitEnvConf(t *testing.T) {
	e := InitEnv{Workdir: "/usr/jails", IPPool: "10.0.0.0/24 10.1.0.0/16", NatEnable: "pf", ZFS: true}
	c, err := e.Conf()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`workdir="/usr/jails"`, `nodeippool="10.0.0.0/24 10.1.0.0/16"`, `zfsfeat="1"`, `nat_enable="pf"`} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, bad := range []InitEnv{
		{Workdir: "/usr/jails\";reboot;\""},
		{Workdir: "/usr/../etc"},
		{NodeName: "a$(id)"},
		{Nameservers: "8.8.8.8;id"},
		{IPPool: "10.0.0.0/24;id"},
		{NatEnable: "pf\nfoo=1"},
	} {
		if _, err := bad.Conf(); err == nil {
			t.Errorf("accepted hostile initenv %+v", bad)
		}
	}
}

func TestStripANSI(t *testing.T) {
	if got := StripANSI("\x1b[0;32mok\x1b[0m done"); got != "ok done" {
		t.Errorf("got %q", got)
	}
}
