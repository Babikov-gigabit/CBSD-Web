// Package sysinfo collects cheap host metrics for the dashboard.
package sysinfo

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Info struct {
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	Release   string    `json:"release,omitempty"`
	Arch      string    `json:"arch"`
	CPUs      int       `json:"cpus"`
	PhysMem   uint64    `json:"physmem,omitempty"`
	FreeMem   uint64    `json:"freemem,omitempty"`
	Load      []float64 `json:"load,omitempty"`
	Uptime    int64     `json:"uptime,omitempty"`
	DiskTotal uint64    `json:"disk_total,omitempty"`
	DiskFree  uint64    `json:"disk_free,omitempty"`
	VMMLoaded bool      `json:"vmm_loaded"`
	// VMGuest is kern.vm_guest: "none" on hardware, else the hypervisor
	// this host itself runs under (vbox, vmware, kvm, ...).
	VMGuest string    `json:"vm_guest,omitempty"`
	At      time.Time `json:"at"`
}

// Collector caches host info for a few seconds so dashboards stay cheap.
type Collector struct {
	workdir string
	mu      sync.Mutex
	last    Info
}

func NewCollector(workdir string) *Collector { return &Collector{workdir: workdir} }

func (c *Collector) Get(ctx context.Context) Info {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.last.At) < 5*time.Second {
		return c.last
	}
	in := Info{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(), At: time.Now()}
	in.Hostname, _ = os.Hostname()
	var st syscall.Statfs_t
	if err := syscall.Statfs(c.workdir, &st); err == nil {
		in.DiskTotal = uint64(st.Blocks) * uint64(st.Bsize)
		in.DiskFree = uint64(st.Bavail) * uint64(st.Bsize)
	}
	if runtime.GOOS == "freebsd" {
		vals := sysctl(ctx, "kern.osrelease", "hw.physmem", "vm.loadavg", "hw.pagesize", "vm.stats.vm.v_free_count", "kern.boottime")
		if len(vals) == 6 {
			in.Release = vals[0]
			in.PhysMem, _ = strconv.ParseUint(vals[1], 10, 64)
			in.Load = parseLoad(vals[2])
			ps, _ := strconv.ParseUint(vals[3], 10, 64)
			free, _ := strconv.ParseUint(vals[4], 10, 64)
			in.FreeMem = ps * free
			in.Uptime = parseBoottime(vals[5])
		}
		in.VMMLoaded = exec.CommandContext(ctx, "/sbin/kldstat", "-q", "-m", "vmm").Run() == nil
		if v := sysctl(ctx, "kern.vm_guest"); len(v) == 1 {
			in.VMGuest = v[0]
		}
	} else if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		in.Load = parseLoad(string(b))
	}
	c.last = in
	return in
}

func sysctl(ctx context.Context, names ...string) []string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/sbin/sysctl", append([]string{"-n"}, names...)...).Output()
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

func parseLoad(s string) []float64 {
	s = strings.Trim(strings.TrimSpace(s), "{}")
	var out []float64
	for _, f := range strings.Fields(s) {
		if v, err := strconv.ParseFloat(f, 64); err == nil {
			out = append(out, v)
		}
		if len(out) == 3 {
			break
		}
	}
	return out
}

// parseBoottime parses "{ sec = 1700000000, usec = 0 } ..." into uptime seconds.
func parseBoottime(s string) int64 {
	i := strings.Index(s, "sec = ")
	if i < 0 {
		return 0
	}
	s = s[i+6:]
	if j := strings.IndexByte(s, ','); j > 0 {
		s = s[:j]
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return time.Now().Unix() - sec
}
