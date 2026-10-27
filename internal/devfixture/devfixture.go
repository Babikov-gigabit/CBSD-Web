// Package devfixture builds a fake CBSD workdir (SQLite databases and VM
// profiles) so the UI can be developed and tested without FreeBSD.
package devfixture

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/cbsd-web/cbsd-web/internal/cbsd"
)

var schema = []string{
	`CREATE TABLE jails (jname TEXT PRIMARY KEY, jid INTEGER DEFAULT 0, path TEXT DEFAULT '0', host_hostname TEXT DEFAULT '0',
		ip4_addr TEXT DEFAULT '0', astart INTEGER DEFAULT 0, ver TEXT DEFAULT '0', arch TEXT DEFAULT '0', baserw INTEGER DEFAULT 0,
		vnet INTEGER DEFAULT 0, status INTEGER DEFAULT 0, protected INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0,
		emulator TEXT DEFAULT 'jail', interface TEXT DEFAULT '0', maintenance TEXT DEFAULT '0')`,
	`CREATE TABLE bhyve (jname TEXT UNIQUE, vm_cpus INTEGER, vm_ram INTEGER, vm_os_type TEXT, vm_os_profile TEXT,
		vm_vnc_port INTEGER DEFAULT 0, bhyve_vnc_tcp_bind TEXT DEFAULT '127.0.0.1')`,
	`CREATE TABLE xen (jname TEXT UNIQUE, vm_cpus INTEGER, vm_ram INTEGER, vm_os_type TEXT, vm_os_profile TEXT, vm_vnc_port INTEGER DEFAULT 0)`,
	`CREATE TABLE local (nodename TEXT, nodeip TEXT, nodeippool TEXT, natip TEXT, nat_enable TEXT, zfsfeat INTEGER, jnameserver TEXT)`,
	`CREATE TABLE bsdbase (idx INTEGER PRIMARY KEY, platform TEXT, name TEXT, arch TEXT, targetarch TEXT, ver TEXT, stable INTEGER, elf TEXT, date TEXT, source TEXT, status INTEGER)`,
	`CREATE TABLE images (id INTEGER PRIMARY KEY, name TEXT, path TEXT, emulator TEXT, size INTEGER, created TEXT)`,
}

var data = []string{
	`INSERT INTO jails (jname,jid,path,host_hostname,ip4_addr,astart,ver,baserw,status,protected,emulator,interface) VALUES
		('web1',3,'/usr/jails/jails/web1','web1.example.org','10.0.0.2/24',1,'14.3',0,1,0,'jail','auto'),
		('db1',4,'/usr/jails/jails/db1','db1.example.org','10.0.0.3/24',1,'14.3',1,1,1,'jail','auto'),
		('build',0,'/usr/jails/jails/build','build','10.0.0.4/24',0,'native',0,0,0,'jail','auto'),
		('vm_freebsd',0,'/usr/jails/jails/vm_freebsd','0','10.0.0.20',1,'0',0,1,0,'bhyve','auto'),
		('vm_debian',0,'/usr/jails/jails/vm_debian','0','DHCP',0,'0',0,0,0,'bhyve','auto'),
		('xen1',0,'/usr/jails/jails/xen1','0','10.0.0.30',0,'0',0,0,0,'xen','auto')`,
	`INSERT INTO bhyve (jname,vm_cpus,vm_ram,vm_os_type,vm_os_profile,vm_vnc_port,bhyve_vnc_tcp_bind) VALUES ('vm_freebsd',2,2147483648,'freebsd','FreeBSD-14.3-x86_64',5900,'127.0.0.1'),
		('vm_debian',1,1073741824,'linux','cloud-Debian-12-x86_64',0,'127.0.0.1')`,
	`INSERT INTO xen (jname,vm_cpus,vm_ram,vm_os_type,vm_os_profile,vm_vnc_port) VALUES ('xen1',1,536870912,'freebsd','FreeBSD-14.3-x86_64',0)`,
	`INSERT INTO local VALUES ('node1.example.org','192.168.1.10','10.0.0.0/24','192.168.1.10','pf',1,'8.8.8.8,8.8.4.4')`,
	`INSERT INTO bsdbase (platform,name,arch,targetarch,ver,stable,elf,date,source,status) VALUES ('FreeBSD','base','amd64','amd64','14.3',0,'1403000','2025-06-10','repo',1)`,
	`INSERT INTO images (name,path,emulator,size,created) VALUES ('nginx-template','/usr/jails/import/nginx.img','jail',157286400,'2025-09-01 10:00:00')`,
}

var profiles = map[string]string{
	"vm-freebsd-FreeBSD-14.3-x86_64.conf":           "vm_profile=\"FreeBSD-14.3-x86_64\"\nvm_os_type=\"freebsd\"\nlong_description=\"FreeBSD: 14.3-RELEASE\"\nbhyve_active=1\nxen_active=1\n",
	"vm-freebsd-cloud-FreeBSD-14.3-ufs-x86_64.conf": "vm_profile=\"cloud-FreeBSD-14.3-ufs-x86_64\"\nvm_os_type=\"freebsd\"\nlong_description=\"FreeBSD: 14.3-RELEASE cloud (UFS)\"\nis_cloud=1\nbhyve_active=1\nxen_active=0\n",
	"vm-linux-Debian-12-x86_64.conf":                "vm_profile=\"Debian-12-x86_64\"\nvm_os_type=\"linux\"\nlong_description=\"Linux Debian 12\"\nbhyve_active=1\nxen_active=1\n",
	"vm-linux-cloud-Debian-12-x86_64.conf":          "vm_profile=\"cloud-Debian-12-x86_64\"\nvm_os_type=\"linux\"\nlong_description=\"Linux Debian 12 cloud\"\nis_cloud=1\nbhyve_active=1\nxen_active=0\n",
	"vm-windows-10_86x_64x.conf":                    "vm_profile=\"10_86x_64x\"\nvm_os_type=\"windows\"\nlong_description=\"Windows 10\"\nbhyve_active=1\nxen_active=0\n",
}

func run(db *sql.DB, qs []string) error {
	for _, q := range qs {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("%w: %s", err, q)
		}
	}
	return nil
}

// Build (re)creates the fixture in dir.
func Build(dir string) error {
	dbdir := filepath.Join(dir, "var", "db")
	pdir := filepath.Join(dir, "etc", "defaults")
	for _, d := range []string{dbdir, pdir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	os.Remove(filepath.Join(dbdir, "local.sqlite"))
	os.Remove(filepath.Join(dbdir, "nodes.sqlite"))
	db, err := sql.Open("sqlite", filepath.Join(dbdir, "local.sqlite"))
	if err != nil {
		return err
	}
	defer db.Close()
	if err := run(db, schema); err != nil {
		return err
	}
	// Give the jails table every column the settings page edits, as real CBSD has.
	have := map[string]bool{"host_hostname": true, "ip4_addr": true, "astart": true, "ver": true, "baserw": true,
		"vnet": true, "protected": true, "hidden": true, "interface": true}
	defaults := map[string]string{"stop_timeout": "10", "mount_fdescfs": "1", "allow_procfs": "1", "allow_zfs": "1",
		"allow_dying": "1", "allow_reserved_ports": "1", "persist": "1", "enforce_statfs": "1", "allow_unprivileged_proc_debug": "1",
		"allow_suser": "1", "allow_extattr": "1", "sysvsem": "new", "sysvshm": "new", "sysvmsg": "new", "devfs_ruleset": "4",
		"mount_devfs": "1", "exec_start": "/bin/sh /etc/rc", "exec_stop": "/bin/sh /etc/rc.shutdown"}
	for _, p := range cbsd.JailParams {
		if have[p.Name] {
			continue
		}
		def := defaults[p.Name]
		if def == "" {
			def = "0"
		}
		if _, err := db.Exec(fmt.Sprintf("ALTER TABLE jails ADD COLUMN %q TEXT DEFAULT '%s'", p.Name, def)); err != nil {
			return err
		}
	}
	// VM tables get every column the VM settings page edits, as real CBSD has.
	vmDefaults := map[string]string{"vm_boot": "hdd", "vm_efi": "uefi", "cd_boot_firmware": "bhyve", "hdd_boot_firmware": "bhyve",
		"cd_vnc_wait": "1", "bhyve_vnc_resolution": "1024x768", "xen_vnc_resolution": "1024x768", "bhyve_vnc_vgaconf": "io",
		"fbuf": "1", "xhci": "1", "tablet": "1", "soundhw": "none", "vm_hostbridge": "hostbridge", "on_poweroff": "destroy",
		"on_reboot": "restart", "on_crash": "destroy", "double_acpi": "1", "bhyve_generate_acpi": "1", "bhyve_mptable_gen": "1",
		"xen_hap": "1", "vnc_password": "cbsd123456", "ip4_addr": "DHCP"}
	for table, params := range map[string][]cbsd.Param{"bhyve": cbsd.BhyveParams, "xen": cbsd.XenParams} {
		var cols []string
		rows, err := db.Query(fmt.Sprintf("SELECT name FROM pragma_table_info('%s')", table))
		if err != nil {
			return err
		}
		have := map[string]bool{}
		for rows.Next() {
			var c string
			rows.Scan(&c)
			have[c] = true
		}
		rows.Close()
		for _, p := range params {
			if !have[p.Name] {
				cols = append(cols, p.Name)
			}
		}
		for _, c := range cols {
			def := vmDefaults[c]
			if def == "" {
				def = "0"
			}
			if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %q TEXT DEFAULT '%s'", table, c, def)); err != nil {
				return err
			}
		}
	}
	if err := run(db, data); err != nil {
		return err
	}
	// Limits of web1, as 'cbsd jrctl mode=set' stores them.
	hdir := filepath.Join(dir, "jails-system", "web1", "helpers")
	if err := os.MkdirAll(hdir, 0o755); err != nil {
		return err
	}
	os.Remove(filepath.Join(hdir, "jrctl.sqlite"))
	rd, err := sql.Open("sqlite", filepath.Join(hdir, "jrctl.sqlite"))
	if err != nil {
		return err
	}
	defer rd.Close()
	if err := run(rd, []string{
		`CREATE TABLE forms (idx INTEGER PRIMARY KEY, param TEXT, cur TEXT, new TEXT)`,
		`INSERT INTO forms (param,cur,new) VALUES ('memoryuse','2g',''),('pcpu','50',''),('maxproc','0',''),('fsquota','20g','')`,
	}); err != nil {
		return err
	}
	nd, err := sql.Open("sqlite", filepath.Join(dbdir, "nodes.sqlite"))
	if err != nil {
		return err
	}
	defer nd.Close()
	if err := run(nd, []string{
		`CREATE TABLE nodelist (nodename TEXT, ip TEXT, port INTEGER, status INTEGER, idle TEXT, rootkeyfile TEXT)`,
		`INSERT INTO nodelist VALUES ('node2.example.org','192.168.1.11',22,1,'2025-10-01 12:00','/secret/key')`,
	}); err != nil {
		return err
	}
	// Media live in their own database in current CBSD.
	os.Remove(filepath.Join(dbdir, "storage_media.sqlite"))
	md, err := sql.Open("sqlite", filepath.Join(dbdir, "storage_media.sqlite"))
	if err != nil {
		return err
	}
	defer md.Close()
	iso := filepath.Join(dir, "src", "iso")
	if err := run(md, []string{
		`CREATE TABLE media (idx INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, path TEXT, type TEXT, jname TEXT, size INTEGER)`,
		fmt.Sprintf(`INSERT INTO media (name,path,type,jname,size) VALUES
			('iso-FreeBSD-14.3','%[1]s/FreeBSD-14.3.iso','iso','vm_freebsd',1288490188),
			('web-alpine-3.20','%[1]s/upload/alpine-3.20.iso','iso','-',%[2]d),
			('iso-Gone-1.0.iso','%[1]s/Gone-1.0.iso','iso','vm_debian',0),
			('hdd-vm_freebsd','/usr/jails/vm/vm_freebsd/dsk1.vhd','hdd','vm_freebsd',21474836480)`, iso, len(FakeISO())),
	}); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(iso, "upload"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(iso, "upload", "alpine-3.20.iso"), FakeISO(), 0o644); err != nil {
		return err
	}
	// iso-Gone-1.0.iso stays registered without a file.
	if err := os.WriteFile(filepath.Join(iso, "FreeBSD-14.3.iso"), FakeISO(), 0o644); err != nil {
		return err
	}
	// bstart.log of a VM that failed to start, as CBSD writes it.
	vdir := filepath.Join(dir, "jails-system", "vm_freebsd")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(vdir, "bstart.log"), []byte("Mon Oct 27 08:50:01 UTC 2026\nBoot from CD\n"+
		"cmd: env LIB9P_LOGGING=/usr/jails/jails-system/vm_freebsd/cbsd_lib9p.log /usr/sbin/bhyve -A -H -P -c 2 -m 2147483648 "+
		"-s 29,fbuf,tcp=127.0.0.1:5900,w=1024,h=768,password=secret123 vm_freebsd\n-----\n"+
		"vm exit[0]\n\treason\t\tVMX\n\trip\t\t0x0000000000000000\nbhyve exited with code 4\n"), 0o644); err != nil {
		return err
	}
	for name, body := range profiles {
		if err := os.WriteFile(filepath.Join(pdir, name), []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// FakeISO returns a minimal file that passes the ISO 9660 signature check.
func FakeISO() []byte {
	b := make([]byte, 0x8800)
	copy(b[0x8001:], "CD001")
	return b
}
