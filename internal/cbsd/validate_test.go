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

func TestJailConfigUpdate(t *testing.T) {
	ok := JailConfigUpdate{Values: map[string]string{"allow_raw_sockets": "1", "devfs_ruleset": "4", "sysvshm": "new", "cpuset": "0-3", "jnameserver": "8.8.8.8,1.1.1.1"}}
	args, err := ok.Args("web1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	want := "jset jname=web1 jnameserver=8.8.8.8,1.1.1.1 allow_raw_sockets=1 devfs_ruleset=4 sysvshm=new cpuset=0-3"
	if got := strings.Join(args, " "); got != want {
		t.Fatalf("args:\n got %s\nwant %s", got, want)
	}
	bad := []map[string]string{
		{"host_hostname": "a;reboot"},
		{"jnameserver": "8.8.8.8 $(id)"},
		{"allow_mount": "yes"},
		{"devfs_ruleset": "04"},
		{"devfs_ruleset": "70000"},
		{"sysvsem": "new;"},
		{"cpuset": "0-3'"},
		{"tags": "a b"},
		{"nosuch": "1"},
		{"path": "/"},
	}
	for _, v := range bad {
		u := JailConfigUpdate{Values: v}
		if _, err := u.Args("web1", true, false); err == nil {
			t.Errorf("accepted %v", v)
		}
	}
	hookU := JailConfigUpdate{Values: map[string]string{"exec_master_poststart": "/root/bin/up.sh"}}
	if _, err := hookU.Args("web1", false, false); err == nil {
		t.Error("non-admin changed a host hook")
	}
	if _, err := hookU.Args("web1", true, false); err != nil {
		t.Errorf("admin hook: %v", err)
	}
	for _, h := range []string{"/bin/sh /etc/rc", "/x;id", "`id`", "$(id)", "/a|b", "/a\nb", "/a'b"} {
		u := JailConfigUpdate{Values: map[string]string{"exec_start": h}}
		if _, err := u.Args("web1", true, false); err == nil {
			t.Errorf("accepted hook %q", h)
		}
	}
	// Non-live params on a running jail need an explicit restart.
	vnet := JailConfigUpdate{Values: map[string]string{"vnet": "1"}}
	if _, err := vnet.Args("web1", true, true); err == nil {
		t.Error("vnet on running jail without restart")
	}
	vnet.Restart = true
	if args, err := vnet.Args("web1", true, true); err != nil || args[len(args)-1] != "autorestart=1" {
		t.Errorf("restart: %v %v", args, err)
	}
}

func TestRctlArgs(t *testing.T) {
	args, err := RctlArgs("web1", map[string]string{"memoryuse": "2g", "pcpu": "50", "nice": "-5", "fsquota": "0"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(args, " "); got != "jrctl mode=set jname=web1 memoryuse=2g pcpu=50 nice=-5 fsquota=0" {
		t.Fatalf("got %s", got)
	}
	for _, v := range []map[string]string{{"memoryuse": "2gb"}, {"pcpu": "5g"}, {"nice": "30"}, {"maxproc": "1;id"}, {"cputime": "1"}, {"memoryuse": ""}} {
		if _, err := RctlArgs("web1", v); err == nil {
			t.Errorf("accepted %v", v)
		}
	}
}
