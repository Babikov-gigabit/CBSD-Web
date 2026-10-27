// Package config loads cbsd-web settings from a JSON file and fills defaults.
package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Config is the on-disk configuration (see deploy/cbsd-web.conf.sample).
type Config struct {
	// Listen address. Default keeps the UI reachable only from the host itself.
	Listen string `json:"listen"`

	// TLS. When TLSCert/TLSKey are empty and TLSAuto is true, a self-signed
	// certificate is generated in DataDir on first start.
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	TLSAuto bool   `json:"tls_auto"`

	// Set when cbsd-web runs behind a TLS-terminating reverse proxy on the same host.
	// Cookies are still marked Secure. Never combine with a non-loopback Listen.
	BehindProxy bool `json:"behind_proxy"`

	DataDir   string `json:"data_dir"`
	UsersFile string `json:"users_file"`
	AuditLog  string `json:"audit_log"`

	// Command used to invoke CBSD. The daemon itself runs unprivileged; privileges
	// are obtained through sudo restricted to the cbsd binary (deploy/sudoers).
	CBSDCommand []string `json:"cbsd_command"`
	// Path to the initenv helper used by the setup wizard.
	InitenvCommand []string `json:"initenv_command"`
	// CBSD working directory. Empty = autodetect from /etc/rc.conf (cbsd_workdir).
	Workdir string `json:"workdir"`
	// CBSD distribution directory (profiles in etc/defaults).
	DistDir string `json:"dist_dir"`

	SessionIdleMinutes    int      `json:"session_idle_minutes"`
	SessionMaxHours       int      `json:"session_max_hours"`
	MaxConcurrentJobs     int      `json:"max_concurrent_jobs"`
	CommandTimeoutMinutes int      `json:"command_timeout_minutes"`
	AllowedNetworks       []string `json:"allowed_networks"`
	// Minimum role for the in-browser jail terminal: admin, operator or disabled.
	// A jail shell is root inside the jail, so the default is admin.
	TerminalRole string `json:"terminal_role"`
	// Close terminals without input or output for this long.
	TerminalIdleMinutes int `json:"terminal_idle_minutes"`

	allowed []*net.IPNet
}

// Default returns a configuration with secure defaults.
func Default() *Config {
	return &Config{
		Listen:                "127.0.0.1:8443",
		TLSAuto:               true,
		DataDir:               "/var/db/cbsd-web",
		UsersFile:             "/var/db/cbsd-web/users.json",
		AuditLog:              "/var/log/cbsd-web/audit.log",
		CBSDCommand:           []string{"/usr/local/bin/sudo", "-n", "/usr/local/bin/cbsd"},
		InitenvCommand:        []string{"/usr/local/bin/sudo", "-n", "/usr/local/cbsd/sudoexec/initenv"},
		DistDir:               "/usr/local/cbsd",
		SessionIdleMinutes:    30,
		SessionMaxHours:       12,
		MaxConcurrentJobs:     4,
		CommandTimeoutMinutes: 120,
		TerminalRole:          "admin",
		TerminalIdleMinutes:   30,
		AllowedNetworks:       []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"},
	}
}

// Load reads path (if it exists) over the defaults and validates the result.
func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
			dec := json.NewDecoder(strings.NewReader(string(b)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(c); err != nil {
				return nil, fmt.Errorf("config %s: %w", path, err)
			}
		case errors.Is(err, os.ErrNotExist):
		default:
			return nil, err
		}
	}
	return c, c.finish()
}

func (c *Config) finish() error {
	if len(c.CBSDCommand) == 0 {
		return errors.New("cbsd_command must not be empty")
	}
	if c.Workdir == "" {
		c.Workdir = DetectWorkdir("/etc/rc.conf")
	}
	if !filepath.IsAbs(c.Workdir) {
		return fmt.Errorf("workdir must be absolute: %q", c.Workdir)
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls_cert and tls_key must be set together")
	}
	if c.SessionIdleMinutes <= 0 {
		c.SessionIdleMinutes = 30
	}
	if c.SessionMaxHours <= 0 {
		c.SessionMaxHours = 12
	}
	if c.MaxConcurrentJobs <= 0 {
		c.MaxConcurrentJobs = 4
	}
	if c.CommandTimeoutMinutes <= 0 {
		c.CommandTimeoutMinutes = 120
	}
	switch c.TerminalRole {
	case "":
		c.TerminalRole = "admin"
	case "admin", "operator", "disabled":
	default:
		return fmt.Errorf("terminal_role must be admin, operator or disabled: %q", c.TerminalRole)
	}
	if c.TerminalIdleMinutes <= 0 {
		c.TerminalIdleMinutes = 30
	}
	c.allowed = nil
	for _, s := range c.AllowedNetworks {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("allowed_networks: %w", err)
		}
		c.allowed = append(c.allowed, n)
	}
	if c.BehindProxy && !c.TLSEnabled() {
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return errors.New("behind_proxy without TLS requires a loopback listen address")
		}
	}
	if !c.TLSEnabled() && !c.BehindProxy {
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return errors.New("plain HTTP is only allowed on a loopback address; enable tls_auto or set tls_cert/tls_key")
		}
	}
	return nil
}

// TLSEnabled reports whether the daemon terminates TLS itself.
func (c *Config) TLSEnabled() bool { return c.TLSAuto || c.TLSCert != "" }

// SecureCookies reports whether session cookies must carry the Secure flag.
func (c *Config) SecureCookies() bool { return c.TLSEnabled() || c.BehindProxy }

// ClientAllowed checks the remote address against allowed_networks.
// An empty list allows everyone.
func (c *Config) ClientAllowed(ip net.IP) bool {
	if len(c.allowed) == 0 {
		return true
	}
	for _, n := range c.allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// DetectWorkdir reads cbsd_workdir from rc.conf; falls back to /usr/jails.
func DetectWorkdir(rcconf string) string {
	f, err := os.Open(rcconf)
	if err != nil {
		return "/usr/jails"
	}
	defer f.Close()
	wd := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "cbsd_workdir="); ok {
			if i := strings.Index(v, "#"); i >= 0 && !strings.HasPrefix(v, "\"") {
				v = v[:i]
			}
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			if filepath.IsAbs(v) {
				wd = filepath.Clean(v)
			}
		}
	}
	if wd == "" {
		return "/usr/jails"
	}
	return wd
}
