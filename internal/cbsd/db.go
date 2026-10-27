package cbsd

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure Go driver: static binary, no cgo
)

// DB gives read-only access to CBSD's own SQLite databases. All writes go
// through the cbsd CLI so CBSD's invariants and hooks stay intact. Queries
// adapt to the columns present, so older and newer CBSD versions both work.
type DB struct {
	workdir string
	mu      sync.Mutex
	conns   map[string]*sql.DB
	cols    map[string]colCache
}

type colCache struct {
	mtime time.Time
	cols  map[string]bool
}

func NewDB(workdir string) *DB {
	return &DB{workdir: workdir, conns: map[string]*sql.DB{}, cols: map[string]colCache{}}
}

func (d *DB) path(name string) string { return filepath.Join(d.workdir, "var", "db", name+".sqlite") }

// Exists reports whether a CBSD database file exists (workdir initialized).
// A file that is present but unreadable (e.g. permission denied) counts as
// existing, so callers report the real error instead of "not initialized".
func (d *DB) Exists(name string) bool {
	_, err := os.Stat(d.path(name))
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}

// Readable checks that a CBSD database can actually be opened and queried.
func (d *DB) Readable(ctx context.Context, name string) error {
	c, err := d.conn(name)
	if err != nil {
		return err
	}
	var n int
	return c.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&n)
}

// IsPermission reports whether err comes from missing filesystem permissions.
func IsPermission(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrPermission) {
		return true
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "permission denied") || strings.Contains(m, "unable to open database") || strings.Contains(m, "readonly database")
}

func (d *DB) conn(name string) (*sql.DB, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.conns[name]; ok {
		return c, nil
	}
	c, err := openRO(d.path(name))
	if err != nil {
		return nil, err
	}
	d.conns[name] = c
	return c, nil
}

// openRO opens an existing SQLite file read-only.
func openRO(p string) (*sql.DB, error) {
	if _, err := os.Stat(p); err != nil {
		return nil, err
	}
	dsn := "file:" + (&url.URL{Path: p}).EscapedPath() +
		"?mode=ro&_pragma=busy_timeout(3000)&_pragma=query_only(1)"
	c, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	c.SetMaxOpenConns(4)
	c.SetConnMaxIdleTime(5 * time.Minute)
	return c, nil
}

func (d *DB) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, c := range d.conns {
		c.Close()
		delete(d.conns, k)
	}
}

// columns returns the column set of table, cached until the db file changes.
func (d *DB) columns(ctx context.Context, dbname, table string) (map[string]bool, error) {
	st, err := os.Stat(d.path(dbname))
	if err != nil {
		return nil, err
	}
	key := dbname + "/" + table
	d.mu.Lock()
	cc, ok := d.cols[key]
	d.mu.Unlock()
	if ok && cc.mtime.Equal(st.ModTime()) {
		return cc.cols, nil
	}
	c, err := d.conn(dbname)
	if err != nil {
		return nil, err
	}
	// table is always a constant from this package, never user input.
	rows, err := c.QueryContext(ctx, "SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		cols[n] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.cols[key] = colCache{mtime: st.ModTime(), cols: cols}
	d.mu.Unlock()
	return cols, nil
}

type Row map[string]any

// selectAvailable selects the wanted columns that exist in table.
// where must only contain constant SQL; values go through args.
func (d *DB) selectAvailable(ctx context.Context, dbname, table string, want []string, where string, args ...any) ([]Row, error) {
	have, err := d.columns(ctx, dbname, table)
	if err != nil {
		return nil, err
	}
	if len(have) == 0 {
		return nil, nil // table missing in this CBSD version
	}
	var sel []string
	for _, w := range want {
		if have[w] {
			sel = append(sel, `"`+w+`"`)
		}
	}
	if len(sel) == 0 {
		return nil, nil
	}
	q := fmt.Sprintf("SELECT %s FROM %q", strings.Join(sel, ","), table)
	if where != "" {
		q += " WHERE " + where
	}
	c, err := d.conn(dbname)
	if err != nil {
		return nil, err
	}
	rows, err := c.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names, _ := rows.Columns()
	var out []Row
	for rows.Next() {
		vals := make([]any, len(names))
		ptrs := make([]any, len(names))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := Row{}
		for i, n := range names {
			switch v := vals[i].(type) {
			case []byte:
				r[n] = string(v)
			default:
				r[n] = v
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Env is a jail or VM as shown in the UI.
type Env struct {
	Name      string `json:"jname"`
	Emulator  string `json:"emulator"`
	Status    int    `json:"status"` // 0 off, 1 running, 2 slave, 3 maintenance
	JID       int64  `json:"jid"`
	IP4       string `json:"ip4_addr"`
	Hostname  string `json:"host_hostname,omitempty"`
	Path      string `json:"path,omitempty"`
	AutoStart bool   `json:"astart"`
	Ver       string `json:"ver,omitempty"`
	Arch      string `json:"arch,omitempty"`
	BaseRW    bool   `json:"baserw,omitempty"`
	VNet      bool   `json:"vnet,omitempty"`
	Protected bool   `json:"protected"`
	Hidden    bool   `json:"hidden,omitempty"`
	Node      string `json:"node,omitempty"`
	Interface string `json:"interface,omitempty"`
	CPUs      int64  `json:"vm_cpus,omitempty"`
	RAM       int64  `json:"vm_ram,omitempty"`
	OSType    string `json:"vm_os_type,omitempty"`
	Profile   string `json:"vm_os_profile,omitempty"`
	VNCPort   int64  `json:"vnc_port,omitempty"`
	VNCAuto   bool   `json:"vnc_auto,omitempty"` // vm_vnc_port=0: CBSD picks a port at start
	VNCOff    bool   `json:"vnc_off,omitempty"`  // vm_vnc_port=1
	VNCBind   string `json:"vnc_bind,omitempty"`
	VNCRes    string `json:"vnc_resolution,omitempty"`
	// The password itself is only served by the console endpoint.
	VNCPassword string `json:"-"`
	HasVNCPass  bool   `json:"vnc_has_password,omitempty"`
	Maint       string `json:"maintenance,omitempty"`
}

// Str returns column k as text.
func (r Row) Str(k string) string { return str(r[k]) }

// Num returns column k as a number.
func (r Row) Num(k string) int64 { return num(r[k]) }

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case int64:
		return fmt.Sprint(t)
	case float64:
		return fmt.Sprint(t)
	}
	return fmt.Sprint(v)
}

func num(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case float64:
		return int64(t)
	case string:
		var n int64
		fmt.Sscan(t, &n)
		return n
	}
	return 0
}

// clean maps CBSD's "0" placeholders for unset text fields to "".
func clean(v any) string {
	s := str(v)
	if s == "0" {
		return ""
	}
	return s
}

var jailCols = []string{"jname", "jid", "path", "host_hostname", "ip4_addr", "astart", "ver", "arch",
	"baserw", "vnet", "status", "protected", "hidden", "emulator", "interface", "maintenance", "slavenode"}

func firstClean(vs ...any) string {
	for _, v := range vs {
		if s := clean(v); s != "" {
			return s
		}
	}
	return ""
}

// Envs lists environments. emulator filters ("" = all).
func (d *DB) Envs(ctx context.Context, emulator string) ([]Env, error) {
	rows, err := d.selectAvailable(ctx, "local", "jails", jailCols, "")
	if err != nil {
		return nil, err
	}
	var out []Env
	idx := map[string]int{}
	for _, r := range rows {
		emu := str(r["emulator"])
		if emu == "" || emu == "0" {
			emu = "jail"
		}
		if emulator != "" && emu != emulator {
			continue
		}
		e := Env{
			Name:      str(r["jname"]),
			Emulator:  emu,
			Status:    int(num(r["status"])),
			JID:       num(r["jid"]),
			IP4:       clean(r["ip4_addr"]),
			Hostname:  clean(r["host_hostname"]),
			Path:      clean(r["path"]),
			AutoStart: num(r["astart"]) == 1,
			Ver:       clean(r["ver"]),
			Arch:      clean(r["arch"]),
			BaseRW:    num(r["baserw"]) == 1,
			VNet:      num(r["vnet"]) == 1,
			Protected: num(r["protected"]) == 1,
			Hidden:    num(r["hidden"]) == 1,
			Interface: clean(r["interface"]),
			Maint:     clean(r["maintenance"]),
		}
		idx[e.Name] = len(out)
		out = append(out, e)
	}
	// Merge emulator-specific settings.
	for _, emu := range []string{"bhyve", "xen"} {
		if emulator != "" && emulator != emu {
			continue
		}
		vrows, err := d.selectAvailable(ctx, "local", emu,
			[]string{"jname", "vm_cpus", "vm_ram", "vm_os_type", "vm_os_profile", "vm_vnc_port", "bhyve_vnc_tcp_bind", "bhyve_vnc_bind", "xen_vnc_tcp_bind",
				"bhyve_vnc_resolution", "xen_vnc_resolution", "vnc_password"}, "")
		if err != nil {
			continue // table may not exist on hosts without that hypervisor
		}
		for _, r := range vrows {
			i, ok := idx[str(r["jname"])]
			if !ok {
				continue
			}
			e := &out[i]
			e.CPUs = num(r["vm_cpus"])
			e.RAM = num(r["vm_ram"])
			e.OSType = clean(r["vm_os_type"])
			e.Profile = clean(r["vm_os_profile"])
			e.VNCPort = num(r["vm_vnc_port"])
			switch e.VNCPort {
			case 0:
				e.VNCAuto, e.VNCPort = true, d.autoVNCPort(e.Name)
			case 1:
				e.VNCOff, e.VNCPort = true, 0
			}
			e.VNCBind = firstClean(r["bhyve_vnc_tcp_bind"], r["bhyve_vnc_bind"], r["xen_vnc_tcp_bind"])
			e.VNCRes = firstClean(r["bhyve_vnc_resolution"], r["xen_vnc_resolution"])
			e.VNCPassword = clean(r["vnc_password"])
			e.HasVNCPass = e.VNCPassword != ""
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// autoVNCPort returns the port CBSD chose at the last start of a VM with
// vm_vnc_port=0; bstart writes it to jails-system/NAME/vnc_port. 0 if unknown.
func (d *DB) autoVNCPort(name string) int64 {
	if !ValidExistingName(name) {
		return 0
	}
	b, err := os.ReadFile(filepath.Join(d.workdir, "jails-system", name, "vnc_port"))
	if err != nil || len(b) > 32 {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	p, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil || p < 2 || p > 65535 {
		return 0
	}
	return p
}

// Env returns one environment by name.
func (d *DB) Env(ctx context.Context, name string) (*Env, error) {
	all, err := d.Envs(ctx, "")
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Name == name {
			return &all[i], nil
		}
	}
	return nil, nil
}

// Images lists registered images (local::images).
func (d *DB) Images(ctx context.Context) ([]Row, error) {
	return d.selectAvailable(ctx, "local", "images", []string{"name", "path", "emulator", "size", "created", "sources", "md5"}, "")
}

// Media lists registered ISO/disk media. Current CBSD keeps them in
// storage_media::media; older releases used local::media.
func (d *DB) Media(ctx context.Context) ([]Row, error) {
	db := "local"
	if d.Exists("storage_media") {
		db = "storage_media"
	}
	return d.selectAvailable(ctx, db, "media", []string{"name", "path", "type", "jname", "size"}, "")
}

// Bases lists installed FreeBSD bases (local::bsdbase).
func (d *DB) Bases(ctx context.Context) ([]Row, error) {
	return d.selectAvailable(ctx, "local", "bsdbase", []string{"platform", "name", "arch", "targetarch", "ver", "stable", "elf", "date", "source", "status"}, "")
}

// Nodes lists remote nodes (nodes::nodelist).
func (d *DB) Nodes(ctx context.Context) ([]Row, error) {
	if !d.Exists("nodes") {
		return nil, nil
	}
	return d.selectAvailable(ctx, "nodes", "nodelist", []string{"nodename", "ip", "port", "status", "idle"}, "")
}

// Local returns the local node info row (local::local).
func (d *DB) Local(ctx context.Context) (Row, error) {
	rows, err := d.selectAvailable(ctx, "local", "local",
		[]string{"nodename", "nodeip", "nodeip6", "nodeippool", "natip", "nat_enable", "zfsfeat", "jnameserver", "fs", "ncpu", "physmem", "osrelease", "hostarch", "vnet", "cbsdver", "is_virtual", "disks"}, "")
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	r := rows[0]
	return r, nil
}
