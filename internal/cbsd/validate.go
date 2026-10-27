package cbsd

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// CBSD scripts interpolate argument values into shell code and SQL queries,
// so every value that reaches the CLI must pass a strict allow-list. Nothing
// here is ever passed through a shell by cbsd-web itself (exec without sh).

var (
	// Names of existing environments (may come from older installs).
	reExistingName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	// Names for new environments: CBSD-friendly, no dots/dashes (used in ZFS datasets, SQL, rc vars).
	reNewName   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
	reHostname  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$`)
	reSize      = regexp.MustCompile(`^[1-9][0-9]{0,6}[mMgGtT]$`)
	reProfile   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`)
	reVer       = regexp.MustCompile(`^(native|[0-9]{1,2}(\.[0-9x]{1,2})?)$`)
	rePkg       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+/-]{0,63}$`)
	reIface     = regexp.MustCompile(`^(auto|0|[a-z][a-z0-9_.]{0,15})$`)
	reSnapName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	reOSType    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	reArch      = regexp.MustCompile(`^(amd64|i386|arm64|aarch64|riscv64|x86_64)$`)
	reNodeName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	rePlainText = regexp.MustCompile(`^[\p{L}\p{N} _.,:;@()/+-]{0,200}$`)
)

func ValidExistingName(s string) bool { return reExistingName.MatchString(s) }
func ValidNewName(s string) bool      { return reNewName.MatchString(s) }

// FieldError reports which form field is wrong, so the UI can highlight it.
type FieldError struct{ Field, Msg string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

func ferr(field, format string, a ...any) error {
	return &FieldError{Field: field, Msg: fmt.Sprintf(format, a...)}
}

// validIP4List accepts CBSD ip4_addr forms: DHCP, 0, REALDHCP, or a comma list
// of IPv4/IPv6 addresses with optional /prefix and optional "iface#" prefix.
func validIP4List(s string) bool {
	switch s {
	case "DHCP", "DHCPv6", "REALDHCP", "0":
		return true
	}
	if len(s) > 512 {
		return false
	}
	for _, part := range strings.Split(s, ",") {
		if i := strings.IndexByte(part, '#'); i >= 0 {
			if !reIface.MatchString(part[:i]) {
				return false
			}
			part = part[i+1:]
		}
		if strings.Contains(part, "/") {
			if _, _, err := net.ParseCIDR(part); err != nil {
				return false
			}
		} else if net.ParseIP(part) == nil {
			return false
		}
	}
	return true
}

// validPkgList accepts up to 64 package names separated by single spaces.
func validPkgList(s string) bool {
	parts := strings.Split(s, " ")
	if len(parts) > 64 {
		return false
	}
	for _, p := range parts {
		if !rePkg.MatchString(p) {
			return false
		}
	}
	return true
}

func validIP(s string) bool { return net.ParseIP(s) != nil }

func boolArg(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// JailCreate is the web form for 'cbsd jcreate'.
type JailCreate struct {
	Name       string `json:"jname"`
	Hostname   string `json:"host_hostname"`
	IP4        string `json:"ip4_addr"`
	Ver        string `json:"ver"`
	Arch       string `json:"arch"`
	BaseRW     bool   `json:"baserw"`
	VNet       bool   `json:"vnet"`
	Interface  string `json:"interface"`
	AutoStart  bool   `json:"astart"`
	RunASAP    bool   `json:"runasap"`
	PkgBoot    bool   `json:"pkg_bootstrap"`
	PkgList    string `json:"pkglist"`
	AllowRaw   bool   `json:"allow_raw_sockets"`
	MountPorts bool   `json:"mount_ports"`
	MountSrc   bool   `json:"mount_src"`
}

// Args validates the form and returns jcreate arguments.
func (j *JailCreate) Args() ([]string, error) {
	if !ValidNewName(j.Name) {
		return nil, ferr("jname", "латиница, цифры и _, начинается с буквы, до 32 символов")
	}
	if j.Hostname == "" {
		j.Hostname = j.Name
	}
	if !reHostname.MatchString(j.Hostname) || len(j.Hostname) > 253 {
		return nil, ferr("host_hostname", "некорректное имя хоста")
	}
	if j.IP4 == "" {
		j.IP4 = "DHCP"
	}
	if !validIP4List(j.IP4) {
		return nil, ferr("ip4_addr", "ожидается DHCP или список IP/префиксов через запятую")
	}
	if j.Ver == "" {
		j.Ver = "native"
	}
	if !reVer.MatchString(j.Ver) {
		return nil, ferr("ver", "версия базы вида 14.2 или native")
	}
	if j.Arch != "" && !reArch.MatchString(j.Arch) {
		return nil, ferr("arch", "неизвестная архитектура")
	}
	if j.Interface == "" {
		j.Interface = "auto"
	}
	if !reIface.MatchString(j.Interface) {
		return nil, ferr("interface", "некорректный интерфейс")
	}
	if j.PkgList != "" && !validPkgList(j.PkgList) {
		return nil, ferr("pkglist", "список пакетов через пробел")
	}
	args := []string{"jcreate",
		"jname=" + j.Name,
		"host_hostname=" + j.Hostname,
		"ip4_addr=" + j.IP4,
		"ver=" + j.Ver,
		"baserw=" + boolArg(j.BaseRW),
		"vnet=" + boolArg(j.VNet),
		"interface=" + j.Interface,
		"astart=" + boolArg(j.AutoStart),
		"runasap=" + boolArg(j.RunASAP),
		"pkg_bootstrap=" + boolArg(j.PkgBoot),
		"allow_raw_sockets=" + boolArg(j.AllowRaw),
		"mount_ports=" + boolArg(j.MountPorts),
		"mount_src=" + boolArg(j.MountSrc),
	}
	if j.Arch != "" {
		args = append(args, "arch="+j.Arch)
	}
	if j.PkgList != "" {
		// cbsd expects a single argument; spaces are safe because exec bypasses the shell
		// and the regexp forbids every shell metacharacter.
		args = append(args, "pkglist="+j.PkgList)
	}
	return args, nil
}

// VMCreate is the web form for 'cbsd bcreate' / 'cbsd xcreate'.
type VMCreate struct {
	Name      string `json:"jname"`
	OSType    string `json:"vm_os_type"`
	Profile   string `json:"vm_os_profile"`
	CPUs      int    `json:"vm_cpus"`
	RAM       string `json:"vm_ram"`
	ImgSize   string `json:"imgsize"`
	IP4       string `json:"ip4_addr"`
	Interface string `json:"interface"`
	AutoStart bool   `json:"astart"`
	RunASAP   bool   `json:"runasap"`
	VNCBind   string `json:"bhyve_vnc_tcp_bind"`
	VNCPass   string `json:"vnc_password"`
	CIIP4     string `json:"ci_ip4_addr"`
	CIGW4     string `json:"ci_gw4"`
	CIUser    string `json:"ci_user_add"`
}

var reVNCPass = regexp.MustCompile(`^[A-Za-z0-9_.@%+=-]{6,32}$`)
var reCIUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Args validates the form. emulator is "bhyve" or "xen"; pubkeyPath is an
// already-written authorized_keys file or "".
func (v *VMCreate) Args(emulator, pubkeyPath string) ([]string, error) {
	if !ValidNewName(v.Name) {
		return nil, ferr("jname", "латиница, цифры и _, начинается с буквы, до 32 символов")
	}
	if !reOSType.MatchString(v.OSType) {
		return nil, ferr("vm_os_type", "выберите тип ОС")
	}
	if !reProfile.MatchString(v.Profile) {
		return nil, ferr("vm_os_profile", "выберите профиль")
	}
	if v.CPUs < 1 || v.CPUs > 256 {
		return nil, ferr("vm_cpus", "от 1 до 256")
	}
	if !reSize.MatchString(v.RAM) {
		return nil, ferr("vm_ram", "размер вида 1g или 512m")
	}
	if !reSize.MatchString(v.ImgSize) {
		return nil, ferr("imgsize", "размер вида 20g")
	}
	if v.IP4 == "" {
		v.IP4 = "DHCP"
	}
	if !validIP4List(v.IP4) {
		return nil, ferr("ip4_addr", "ожидается DHCP или IP-адрес")
	}
	if v.Interface == "" {
		v.Interface = "auto"
	}
	if !reIface.MatchString(v.Interface) {
		return nil, ferr("interface", "некорректный интерфейс")
	}
	cmd := "bcreate"
	if emulator == "xen" {
		cmd = "xcreate"
	}
	args := []string{cmd,
		"jname=" + v.Name,
		"vm_os_type=" + v.OSType,
		"vm_os_profile=" + v.Profile,
		"vm_cpus=" + strconv.Itoa(v.CPUs),
		"vm_ram=" + strings.ToLower(v.RAM),
		"imgsize=" + strings.ToLower(v.ImgSize),
		"ip4_addr=" + v.IP4,
		"interface=" + v.Interface,
		"astart=" + boolArg(v.AutoStart),
		"runasap=" + boolArg(v.RunASAP),
	}
	if emulator == "bhyve" {
		switch v.VNCBind {
		case "", "127.0.0.1":
			args = append(args, "bhyve_vnc_tcp_bind=127.0.0.1")
		case "0.0.0.0":
			args = append(args, "bhyve_vnc_tcp_bind=0.0.0.0")
		default:
			if !validIP(v.VNCBind) {
				return nil, ferr("bhyve_vnc_tcp_bind", "IP-адрес")
			}
			args = append(args, "bhyve_vnc_tcp_bind="+v.VNCBind)
		}
		if v.VNCPass != "" {
			if !reVNCPass.MatchString(v.VNCPass) {
				return nil, ferr("vnc_password", "6-32 символа: буквы, цифры, _.@%%+=-")
			}
			args = append(args, "vnc_password="+v.VNCPass)
		}
	}
	if v.CIIP4 != "" {
		if !validIP4List(v.CIIP4) {
			return nil, ferr("ci_ip4_addr", "IP-адрес")
		}
		args = append(args, "ci_ip4_addr="+v.CIIP4)
	}
	if v.CIGW4 != "" {
		if !validIP(v.CIGW4) {
			return nil, ferr("ci_gw4", "IP-адрес шлюза")
		}
		args = append(args, "ci_gw4="+v.CIGW4)
	}
	if v.CIUser != "" {
		if !reCIUser.MatchString(v.CIUser) {
			return nil, ferr("ci_user_add", "имя пользователя")
		}
		args = append(args, "ci_user_add="+v.CIUser)
	}
	if pubkeyPath != "" {
		args = append(args, "ci_user_pubkey="+pubkeyPath)
	}
	return args, nil
}

var rePubKey = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/]{40,}={0,3}( [A-Za-z0-9@._+-]{0,64})?$`)

// ValidPubKey checks a single OpenSSH public key line.
func ValidPubKey(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) <= 8192 && rePubKey.MatchString(s)
}

// VMUpdate holds editable settings of an existing VM (cbsd bset/xset).
type VMUpdate struct {
	CPUs      *int    `json:"vm_cpus"`
	RAM       *string `json:"vm_ram"`
	AutoStart *bool   `json:"astart"`
}

func (u *VMUpdate) Args(emulator, name string) ([]string, error) {
	cmd := "bset"
	if emulator == "xen" {
		cmd = "xset"
	}
	args := []string{cmd, "jname=" + name}
	if u.CPUs != nil {
		if *u.CPUs < 1 || *u.CPUs > 256 {
			return nil, ferr("vm_cpus", "от 1 до 256")
		}
		args = append(args, "vm_cpus="+strconv.Itoa(*u.CPUs))
	}
	if u.RAM != nil {
		if !reSize.MatchString(*u.RAM) {
			return nil, ferr("vm_ram", "размер вида 1g или 512m")
		}
		args = append(args, "vm_ram="+strings.ToLower(*u.RAM))
	}
	if u.AutoStart != nil {
		args = append(args, "astart="+boolArg(*u.AutoStart))
	}
	if len(args) == 2 {
		return nil, ferr("", "нет изменений")
	}
	return args, nil
}

// JailUpdate holds editable settings of an existing jail (cbsd jset).
type JailUpdate struct {
	AutoStart *bool   `json:"astart"`
	IP4       *string `json:"ip4_addr"`
	Hostname  *string `json:"host_hostname"`
}

func (u *JailUpdate) Args(name string) ([]string, error) {
	args := []string{"jset", "jname=" + name}
	if u.AutoStart != nil {
		args = append(args, "astart="+boolArg(*u.AutoStart))
	}
	if u.IP4 != nil {
		if !validIP4List(*u.IP4) {
			return nil, ferr("ip4_addr", "ожидается DHCP или список IP")
		}
		args = append(args, "ip4_addr="+*u.IP4)
	}
	if u.Hostname != nil {
		if !reHostname.MatchString(*u.Hostname) {
			return nil, ferr("host_hostname", "некорректное имя хоста")
		}
		args = append(args, "host_hostname="+*u.Hostname)
	}
	if len(args) == 2 {
		return nil, ferr("", "нет изменений")
	}
	return args, nil
}

// BaseFetch is the form for fetching a FreeBSD base ('cbsd repo action=get sources=base').
type BaseFetch struct {
	Ver  string `json:"ver"`
	Arch string `json:"arch"`
}

func (b *BaseFetch) Args() ([]string, error) {
	if !reVer.MatchString(b.Ver) || b.Ver == "native" {
		return nil, ferr("ver", "версия вида 14.2")
	}
	args := []string{"repo", "action=get", "sources=base", "ver=" + b.Ver, "inter=0"}
	if b.Arch != "" {
		if !reArch.MatchString(b.Arch) {
			return nil, ferr("arch", "неизвестная архитектура")
		}
		args = append(args, "arch="+b.Arch)
	}
	return args, nil
}

// InitEnv is the setup wizard form; it becomes an initenv.conf file.
type InitEnv struct {
	Workdir     string `json:"workdir"`
	NodeName    string `json:"nodename"`
	NodeIP      string `json:"nodeip"`
	Nameservers string `json:"jnameserver"`
	IPPool      string `json:"nodeippool"`
	NatIP       string `json:"natip"`
	NatEnable   string `json:"nat_enable"`
	ZFS         bool   `json:"zfsfeat"`
	FbsdRepo    bool   `json:"fbsdrepo"`
	Parallel    int    `json:"parallel"`
}

var reWorkdir = regexp.MustCompile(`^/[A-Za-z0-9_./-]{1,200}$`)

// Conf validates the form and renders initenv.conf content.
func (e *InitEnv) Conf() (string, error) {
	if e.Workdir == "" {
		e.Workdir = "/usr/jails"
	}
	if !reWorkdir.MatchString(e.Workdir) || strings.Contains(e.Workdir, "..") {
		return "", ferr("workdir", "абсолютный путь")
	}
	if e.NodeName == "" {
		e.NodeName = "auto"
	}
	if e.NodeName != "auto" && !reHostname.MatchString(e.NodeName) {
		return "", ferr("nodename", "имя узла")
	}
	if e.NodeIP == "" {
		e.NodeIP = "auto"
	}
	if e.NodeIP != "auto" && !validIP(e.NodeIP) {
		return "", ferr("nodeip", "IP-адрес")
	}
	if e.Nameservers == "" {
		e.Nameservers = "8.8.8.8,8.8.4.4"
	}
	for _, ns := range strings.Split(e.Nameservers, ",") {
		if !validIP(ns) {
			return "", ferr("jnameserver", "IP-адреса через запятую")
		}
	}
	if e.IPPool == "" {
		e.IPPool = "auto"
	}
	if e.IPPool != "auto" {
		for _, p := range strings.Fields(e.IPPool) {
			if _, _, err := net.ParseCIDR(p); err != nil {
				return "", ferr("nodeippool", "сети вида 10.0.0.0/24 через пробел")
			}
		}
	}
	if e.NatIP == "" {
		e.NatIP = "auto"
	}
	if e.NatIP != "auto" && !validIP(e.NatIP) {
		return "", ferr("natip", "IP-адрес")
	}
	switch e.NatEnable {
	case "":
		e.NatEnable = "pf"
	case "pf", "ipfw", "ipfilter", "0":
	default:
		return "", ferr("nat_enable", "pf, ipfw, ipfilter или 0")
	}
	if e.Parallel <= 0 {
		e.Parallel = 5
	}
	if e.Parallel > 64 {
		return "", ferr("parallel", "не более 64")
	}
	var b strings.Builder
	w := func(k, v string) { fmt.Fprintf(&b, "%s=\"%s\"\n", k, v) }
	w("workdir", e.Workdir)
	w("nodename", e.NodeName)
	w("nodeip", e.NodeIP)
	w("nodeip6", "auto")
	w("jnameserver", e.Nameservers)
	w("nodeippool", e.IPPool)
	w("nodeip6pool", "fde4:8dba:82e1::/64")
	w("natip", e.NatIP)
	w("nat_enable", e.NatEnable)
	w("mdtmp", "8")
	w("ipfw_enable", "1")
	w("zfsfeat", boolArg(e.ZFS))
	w("hammerfeat", "0")
	w("fbsdrepo", boolArg(e.FbsdRepo))
	w("repo", "http://convectix.com")
	w("jail_interface", "auto")
	w("parallel", strconv.Itoa(e.Parallel))
	w("stable", "auto")
	w("bridge", "auto")
	w("default_vs", "0")
	w("statsd_bhyve_enable", "0")
	w("statsd_jail_enable", "0")
	w("statsd_hoster_enable", "0")
	for _, k := range []string{"initenv_modify_sudoers", "initenv_modify_rcconf_hostname",
		"initenv_modify_rcconf_cbsd_workdir", "initenv_modify_rcconf_cbsd_enable",
		"initenv_modify_rcconf_rcshutdown_timeout", "initenv_modify_syctl_rcshutdown_timeout",
		"initenv_modify_rcconf_cbsdrsyncd_enable", "initenv_modify_rcconf_cbsdrsyncd_flags",
		"initenv_modify_cbsd_homedir"} {
		w(k, "1")
	}
	return b.String(), nil
}

// ValidSnapName validates snapshot names.
func ValidSnapName(s string) bool { return reSnapName.MatchString(s) }

// ValidNodeName validates node names.
func ValidNodeName(s string) bool { return reNodeName.MatchString(s) }

// ValidDescription validates a free-text description shown in the UI only.
func ValidDescription(s string) bool { return rePlainText.MatchString(s) }
