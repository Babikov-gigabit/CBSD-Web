// Package hoststat reads per-environment host data (NIC counters, process
// usage, ZFS space) with FreeBSD base tools. Everything here runs as the
// unprivileged daemon user: these tools only read public kernel state.
package hoststat

import (
	"bufio"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Tool paths; variables so tests and other systems can override them.
var (
	IfconfigCmd = "/sbin/ifconfig"
	NetstatCmd  = "/usr/bin/netstat"
	PsCmd       = "/bin/ps"
	ZfsCmd      = "/sbin/zfs"
)

// UseToolsDir points all tools at stand-ins in dir (development and tests).
func UseToolsDir(dir string) {
	IfconfigCmd, NetstatCmd, PsCmd, ZfsCmd = dir+"/ifconfig", dir+"/netstat", dir+"/ps", dir+"/zfs"
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/sbin:/bin:/usr/sbin:/usr/bin", "LANG=C"}
	out, err := cmd.Output()
	return string(out), err
}

// NIC is a host-side interface of an environment with its counters as the
// host sees them. For epair/tap the host's output is the guest's input.
type NIC struct {
	Name    string `json:"name"`
	Desc    string `json:"desc,omitempty"`
	MAC     string `json:"mac,omitempty"`
	Up      bool   `json:"up"`
	Bridge  string `json:"bridge,omitempty"`
	RxBytes uint64 `json:"rx_bytes"` // received by the guest
	TxBytes uint64 `json:"tx_bytes"` // sent by the guest
	RxPkts  uint64 `json:"rx_pkts"`
	TxPkts  uint64 `json:"tx_pkts"`
	Errs    uint64 `json:"errs"`
}

type ifInfo struct {
	desc, mac string
	up        bool
	members   []string
}

// parseIfconfig maps interface names to description, MAC, state and bridge members.
func parseIfconfig(out string) map[string]*ifInfo {
	res := map[string]*ifInfo{}
	var cur *ifInfo
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			name, rest, ok := strings.Cut(line, ": ")
			if !ok {
				cur = nil
				continue
			}
			cur = &ifInfo{up: strings.Contains(rest, "<UP")}
			res[name] = cur
			continue
		}
		if cur == nil {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "description:":
			cur.desc = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "description:"))
		case "ether":
			cur.mac = f[1]
		case "member:":
			cur.members = append(cur.members, f[1])
		}
	}
	return res
}

type ifCounters struct{ ipkts, ierrs, ibytes, opkts, oerrs, obytes uint64 }

// parseNetstat reads 'netstat -ibn' link-level rows. Columns are taken from
// the right, because the Address column is empty for some interfaces.
func parseNetstat(out string) map[string]ifCounters {
	res := map[string]ifCounters{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 11 || !strings.HasPrefix(f[2], "<Link") {
			continue
		}
		n := len(f)
		u := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		res[strings.TrimSuffix(f[0], "*")] = ifCounters{ipkts: u(n - 8), ierrs: u(n - 7), ibytes: u(n - 5), opkts: u(n - 4), oerrs: u(n - 3), obytes: u(n - 2)}
	}
	return res
}

// matchNICs picks the interfaces CBSD tagged for jname: "<jname>-nicN" for
// bhyve taps and "<jname>-epairN" for VNET jails.
func matchNICs(jname string, ifs map[string]*ifInfo, cnt map[string]ifCounters) []NIC {
	bridgeOf := map[string]string{}
	for name, in := range ifs {
		for _, m := range in.members {
			bridgeOf[m] = name
		}
	}
	var out []NIC
	for name, in := range ifs {
		if !strings.HasPrefix(in.desc, jname+"-") {
			continue
		}
		c := cnt[name]
		out = append(out, NIC{Name: name, Desc: in.desc, MAC: in.mac, Up: in.up, Bridge: bridgeOf[name],
			RxBytes: c.obytes, TxBytes: c.ibytes, RxPkts: c.opkts, TxPkts: c.ipkts, Errs: c.ierrs + c.oerrs})
	}
	sortNICs(out)
	return out
}

func sortNICs(n []NIC) {
	for i := 1; i < len(n); i++ {
		for j := i; j > 0 && n[j].Name < n[j-1].Name; j-- {
			n[j], n[j-1] = n[j-1], n[j]
		}
	}
}

// NICs returns the host interfaces of an environment.
func NICs(ctx context.Context, jname string) ([]NIC, error) {
	ic, err := run(ctx, IfconfigCmd, "-a")
	if err != nil {
		return nil, err
	}
	ns, err := run(ctx, NetstatCmd, "-ibn")
	if err != nil {
		return nil, err
	}
	return matchNICs(jname, parseIfconfig(ic), parseNetstat(ns)), nil
}

// Procs is the summed usage of an environment's processes.
type Procs struct {
	Count int     `json:"count"`
	CPU   float64 `json:"cpu_pct"`
	RSS   uint64  `json:"rss"` // bytes
	VSZ   uint64  `json:"vsz"` // bytes
}

func parsePs(out string) Procs {
	var p Procs
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		cpu, err1 := strconv.ParseFloat(strings.Replace(f[0], ",", ".", 1), 64)
		rss, err2 := strconv.ParseUint(f[1], 10, 64)
		vsz, err3 := strconv.ParseUint(f[2], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		p.Count++
		p.CPU += cpu
		p.RSS += rss * 1024
		p.VSZ += vsz * 1024
	}
	return p
}

// JailProcs sums the processes of a running jail (ps -J).
func JailProcs(ctx context.Context, jid int64) (Procs, error) {
	out, err := run(ctx, PsCmd, "-J", strconv.FormatInt(jid, 10), "-o", "pcpu=,rss=,vsz=")
	return parsePs(out), err
}

// PidProcs reports one process, e.g. a bhyve VM.
func PidProcs(ctx context.Context, pid int64) (Procs, error) {
	out, err := run(ctx, PsCmd, "-p", strconv.FormatInt(pid, 10), "-o", "pcpu=,rss=,vsz=")
	return parsePs(out), err
}

// Dataset is the ZFS dataset holding a path.
type Dataset struct {
	Name       string `json:"name"`
	Used       uint64 `json:"used"`
	Avail      uint64 `json:"avail"`
	Refer      uint64 `json:"refer"`
	Mountpoint string `json:"mountpoint"`
}

func parseDataset(out string) (*Dataset, bool) {
	f := strings.Split(strings.TrimSpace(out), "\t")
	if len(f) != 5 {
		return nil, false
	}
	u := func(s string) uint64 { v, _ := strconv.ParseUint(s, 10, 64); return v }
	return &Dataset{Name: f[0], Used: u(f[1]), Avail: u(f[2]), Refer: u(f[3]), Mountpoint: f[4]}, true
}

// DatasetOf returns the dataset mounted at path or by name.
func DatasetOf(ctx context.Context, pathOrName string) (*Dataset, error) {
	out, err := run(ctx, ZfsCmd, "list", "-Hp", "-o", "name,used,avail,refer,mountpoint", pathOrName)
	if err != nil {
		return nil, err
	}
	d, _ := parseDataset(out)
	return d, nil
}

// SnapshotUsed maps "dataset@snap" to the space each snapshot holds.
func SnapshotUsed(ctx context.Context, dataset string) map[string]uint64 {
	out, err := run(ctx, ZfsCmd, "list", "-Hp", "-t", "snapshot", "-d", "1", "-o", "name,used", dataset)
	if err != nil {
		return nil
	}
	res := map[string]uint64{}
	for _, line := range strings.Split(out, "\n") {
		if name, used, ok := strings.Cut(line, "\t"); ok {
			v, _ := strconv.ParseUint(strings.TrimSpace(used), 10, 64)
			res[name] = v
		}
	}
	return res
}

// ZSnap is a ZFS snapshot of one dataset. Written is the data changed
// between the previous snapshot and this one.
type ZSnap struct {
	Name    string `json:"name"` // part after @
	Created int64  `json:"created"`
	Used    uint64 `json:"used"`
	Written uint64 `json:"written"`
	Refer   uint64 `json:"refer"`
}

func parseZSnaps(out string) []ZSnap {
	var res []ZSnap
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) != 5 {
			continue
		}
		_, snap, ok := strings.Cut(f[0], "@")
		if !ok {
			continue
		}
		u := func(s string) uint64 { v, _ := strconv.ParseUint(s, 10, 64); return v }
		c, _ := strconv.ParseInt(f[1], 10, 64)
		res = append(res, ZSnap{Name: snap, Created: c, Used: u(f[2]), Written: u(f[3]), Refer: u(f[4])})
	}
	return res
}

// ZFSSnapshots lists a dataset's snapshots in creation order.
func ZFSSnapshots(ctx context.Context, dataset string) ([]ZSnap, error) {
	out, err := run(ctx, ZfsCmd, "list", "-Hp", "-t", "snapshot", "-d", "1", "-s", "createtxg", "-o", "name,creation,used,written,refer", dataset)
	if err != nil {
		return nil, err
	}
	return parseZSnaps(out), nil
}

// Props are the dataset properties the snapshot graph needs.
type Props struct {
	Origin  string `json:"origin,omitempty"` // "pool/ds@snap" when the dataset is a clone
	Written uint64 `json:"written"`          // changed since the latest snapshot
	Used    uint64 `json:"used"`
	Refer   uint64 `json:"refer"`
}

func parseProps(out string) Props {
	var p Props
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(v, 10, 64)
		switch k {
		case "origin":
			if v != "-" {
				p.Origin = v
			}
		case "written":
			p.Written = n
		case "used":
			p.Used = n
		case "referenced":
			p.Refer = n
		}
	}
	return p
}

// DatasetProps reads origin and space properties of a dataset.
func DatasetProps(ctx context.Context, dataset string) (Props, error) {
	out, err := run(ctx, ZfsCmd, "get", "-Hp", "-o", "property,value", "origin,written,used,referenced", dataset)
	return parseProps(out), err
}

// Clone is a dataset created from a snapshot.
type Clone struct {
	Name       string `json:"name"`
	Origin     string `json:"origin"`
	Mountpoint string `json:"mountpoint,omitempty"`
}

func parseClones(out string) []Clone {
	var res []Clone
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) != 3 || f[1] == "-" || f[1] == "" {
			continue
		}
		c := Clone{Name: f[0], Origin: f[1]}
		if f[2] != "-" && f[2] != "none" && f[2] != "legacy" {
			c.Mountpoint = f[2]
		}
		res = append(res, c)
	}
	return res
}

// Clones lists every clone in a pool.
func Clones(ctx context.Context, pool string) ([]Clone, error) {
	out, err := run(ctx, ZfsCmd, "list", "-Hp", "-r", "-t", "filesystem,volume", "-o", "name,origin,mountpoint", pool)
	if err != nil {
		return nil, err
	}
	return parseClones(out), nil
}
