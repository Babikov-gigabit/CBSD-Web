package cbsd

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Profile is a VM OS profile (etc/defaults/vm-<type>-<profile>.conf).
type Profile struct {
	OSType      string `json:"vm_os_type"`
	Name        string `json:"vm_profile"`
	Description string `json:"long_description"`
	Cloud       bool   `json:"cloud"`
	Arch        string `json:"arch,omitempty"`
	bhyve, xen  bool
}

// Profiles scans profile directories (user overrides first) and caches the result.
type Profiles struct {
	dirs []string
	mu   sync.Mutex
	at   time.Time
	list []Profile
}

func NewProfiles(workdir, distdir string) *Profiles {
	return &Profiles{dirs: []string{
		filepath.Join(workdir, "etc"),
		filepath.Join(workdir, "etc", "defaults"),
		filepath.Join(distdir, "etc", "defaults"),
	}}
}

// For returns profiles active for an emulator ("bhyve" or "xen").
func (p *Profiles) For(emulator string) []Profile {
	p.mu.Lock()
	if time.Since(p.at) > time.Minute || p.list == nil {
		p.list = p.scan()
		p.at = time.Now()
	}
	all := p.list
	p.mu.Unlock()
	out := make([]Profile, 0, len(all))
	for _, pr := range all {
		if (emulator == "bhyve" && pr.bhyve) || (emulator == "xen" && pr.xen) {
			out = append(out, pr)
		}
	}
	return out
}

func (p *Profiles) scan() []Profile {
	seen := map[string]bool{}
	var out []Profile
	for _, dir := range p.dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "vm-*.conf"))
		for _, f := range files {
			base := filepath.Base(f)
			if seen[base] {
				continue // override in workdir/etc wins
			}
			seen[base] = true
			if pr, ok := parseProfile(f); ok {
				out = append(out, pr)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OSType != out[j].OSType {
			return out[i].OSType < out[j].OSType
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func parseProfile(path string) (Profile, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Profile{}, false
	}
	defer f.Close()
	pr := Profile{bhyve: true, xen: true}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "vm_profile":
			pr.Name = v
		case "vm_os_type":
			pr.OSType = v
		case "long_description":
			pr.Description = v
		case "bhyve_active":
			pr.bhyve = v == "1"
		case "xen_active":
			pr.xen = v == "1"
		case "is_cloud":
			pr.Cloud = v == "1"
		case "vm_arch", "arch":
			pr.Arch = v
		}
	}
	if pr.Name == "" || pr.OSType == "" || !reProfile.MatchString(pr.Name) || !reOSType.MatchString(pr.OSType) {
		return Profile{}, false
	}
	if strings.HasPrefix(pr.Name, "cloud-") {
		pr.Cloud = true
	}
	return pr, true
}

// Has reports whether a profile name exists for the OS type and emulator.
func (p *Profiles) Has(emulator, ostype, name string) bool {
	for _, pr := range p.For(emulator) {
		if pr.OSType == ostype && pr.Name == name {
			return true
		}
	}
	return false
}
