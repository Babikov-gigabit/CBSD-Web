package cbsd

import (
	"context"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ParamKind tells the UI which control to draw and the server how to validate.
type ParamKind string

const (
	KindBool ParamKind = "bool"
	KindInt  ParamKind = "int"
	KindEnum ParamKind = "enum"
	KindText ParamKind = "text"
)

// Param describes one jail setting that 'cbsd jset' accepts (share/jail-arg).
type Param struct {
	Name    string    `json:"name"`
	Group   string    `json:"group"`
	Label   string    `json:"label"`
	Help    string    `json:"help,omitempty"`
	Kind    ParamKind `json:"kind"`
	Options []string  `json:"options,omitempty"`
	Min     int       `json:"min,omitempty"`
	Max     int       `json:"max,omitempty"`
	// Live params are applied by jset to a running jail; the others need a restart.
	Live bool `json:"live"`
	// Admin params run host-side commands or touch the base; only admins change them.
	Admin bool `json:"admin,omitempty"`
	// Secret params (passwords) are never sent to the browser.
	Secret bool `json:"secret,omitempty"`

	valid func(string) bool
}

// Param groups in display order.
var ParamGroups = []string{"Основные", "Сеть", "Разрешения", "Файловые системы", "IPC", "Процессы и ресурсы", "Хуки и команды"}

var (
	reTags    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}(,[A-Za-z0-9_.-]{1,32}){0,15}$`)
	reMAC     = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`)
	reCPUSet  = regexp.MustCompile(`^[0-9]{1,3}([-,][0-9]{1,3}){0,63}$`)
	reHook    = regexp.MustCompile(`^[A-Za-z0-9_./=:,+@%-]{1,256}$`)
	reAbsPath = regexp.MustCompile(`^/[A-Za-z0-9_./-]{1,255}$`)
)

func orZero(f func(string) bool) func(string) bool {
	return func(s string) bool { return s == "0" || f(s) }
}

func validNameservers(s string) bool {
	parts := strings.Split(s, ",")
	if len(parts) > 8 {
		return false
	}
	for _, p := range parts {
		if net.ParseIP(p) == nil {
			return false
		}
	}
	return true
}

func b(name, group, label, help string, live bool) Param {
	return Param{Name: name, Group: group, Label: label, Help: help, Kind: KindBool, Live: live}
}

func n(name, group, label, help string, min, max int, live bool) Param {
	return Param{Name: name, Group: group, Label: label, Help: help, Kind: KindInt, Min: min, Max: max, Live: live}
}

func t(name, group, label, help string, live bool, valid func(string) bool) Param {
	return Param{Name: name, Group: group, Label: label, Help: help, Kind: KindText, Live: live, valid: valid}
}

func hook(name, label, help string) Param {
	return Param{Name: name, Group: "Хуки и команды", Label: label, Help: help + " Одна команда без пробелов (путь к скрипту) или 0.", Kind: KindText, Admin: true, valid: orZero(reHook.MatchString)}
}

func perm(name, label, help string) Param { return b(name, "Разрешения", label, help, true) }

// JailParams lists every jset parameter the UI edits. Structural parameters
// (path, data, rcconf, basename, emulator, gid, zfs_encryption, ...) are left
// to the CLI on purpose: changing them on a live jail breaks it.
var JailParams = []Param{
	t("host_hostname", "Основные", "Имя хоста", "FQDN клетки.", true, reHostname.MatchString),
	t("ip4_addr", "Основные", "IP-адреса", "Через запятую, можно с префиксом и интерфейсом: em0#10.0.0.5/24. DHCP, REALDHCP или 0.", true, validIP4List),
	t("jdomain", "Основные", "Домен", "Домен для resolv.conf, 0 — не задан.", false, orZero(reHostname.MatchString)),
	t("jnameserver", "Основные", "DNS-серверы", "IP через запятую, 0 — как на хосте.", false, orZero(validNameservers)),
	b("astart", "Основные", "Автозапуск", "Запускать при загрузке хоста.", true),
	n("b_order", "Основные", "Порядок запуска", "Меньше — раньше.", 0, 9999, true),
	n("boot_delay", "Основные", "Задержка после запуска, с", "Пауза перед запуском следующей клетки.", 0, 3600, true),
	b("protected", "Основные", "Защита от удаления", "", true),
	b("hidden", "Основные", "Скрыть в списках", "", true),
	t("tags", "Основные", "Теги", "Через запятую, 0 — нет.", false, orZero(reTags.MatchString)),

	b("vnet", "Сеть", "VNET (свой сетевой стек)", "Отдельный стек с epair-интерфейсом в мосте.", false),
	t("interface", "Сеть", "Интерфейс хоста", "auto, 0 (не назначать алиасы) или имя: em0, bridge1.", false, reIface.MatchString),
	t("nic_hwaddr", "Сеть", "MAC-адрес (VNET)", "0 — случайный.", false, orZero(reMAC.MatchString)),
	t("ci_gw4", "Сеть", "Шлюз IPv4 (VNET)", "0 — не задан.", false, orZero(validIP)),
	b("floatresolv", "Сеть", "Подстраивать resolv.conf", "Подставлять DNS из ip4_addr.", true),
	b("mkhostsfile", "Сеть", "Создавать /etc/hosts", "", false),
	n("exec_fib", "Сеть", "Таблица маршрутизации (FIB)", "", 0, 255, false),

	perm("allow_raw_sockets", "Raw-сокеты", "Нужно для ping и traceroute."),
	perm("allow_reserved_ports", "Привилегированные порты", "Порты ниже 1024 без root."),
	perm("allow_mount", "Монтирование", "Разрешить mount внутри клетки (нужен enforce_statfs < 2)."),
	perm("allow_nullfs", "nullfs", ""),
	perm("allow_tmpfs", "tmpfs", ""),
	perm("allow_fdescfs", "fdescfs", ""),
	perm("allow_procfs", "procfs", ""),
	perm("allow_fusefs", "fusefs", ""),
	perm("allow_linprocfs", "linprocfs", ""),
	perm("allow_linsysfs", "linsysfs", ""),
	perm("allow_zfs", "ZFS", "Управление делегированными наборами ZFS."),
	perm("allow_devfs", "devfs", ""),
	perm("allow_sysvipc", "SysV IPC (устар.)", "Старый общий флаг; лучше задайте sysvsem/sysvshm/sysvmsg."),
	perm("allow_vmm", "bhyve внутри клетки (vmm)", ""),
	perm("allow_kmem", "/dev/kmem", "Опасно: доступ к памяти ядра."),
	perm("allow_read_msgbuf", "Чтение dmesg", ""),
	perm("allow_mlock", "mlock", ""),
	perm("allow_nfsd", "Сервер NFS", ""),
	perm("allow_unprivileged_proc_debug", "Отладка процессов без root", ""),
	perm("allow_suser", "root внутри клетки", "Отключение лишает root привилегий."),
	perm("allow_extattr", "Расширенные атрибуты", ""),
	perm("allow_chflags", "chflags", ""),
	perm("allow_adjtime", "adjtime", ""),
	perm("allow_settime", "Установка времени", ""),
	perm("allow_dying", "Запуск при «умирающей» клетке", ""),

	b("mount_devfs", "Файловые системы", "Монтировать devfs", "", false),
	n("devfs_ruleset", "Файловые системы", "Набор правил devfs", "4 — стандартный для клеток.", 0, 65535, true),
	b("mount_fdescfs", "Файловые системы", "Монтировать fdescfs", "", true),
	b("mount_procfs", "Файловые системы", "Монтировать procfs", "", true),
	b("mount_linprocfs", "Файловые системы", "Монтировать linprocfs", "", true),
	b("mount_linsysfs", "Файловые системы", "Монтировать linsysfs", "", true),
	b("mount_src", "Файловые системы", "Подключить /usr/src хоста", "", true),
	b("mount_ports", "Файловые системы", "Подключить /usr/ports хоста", "", true),
	b("mount_obj", "Файловые системы", "Подключить /usr/obj", "", false),
	{Name: "enforce_statfs", Group: "Файловые системы", Label: "enforce_statfs", Help: "2 — видны только свои ФС, 1 — ниже корня клетки, 0 — все.", Kind: KindEnum, Options: []string{"0", "1", "2"}},
	{Name: "baserw", Group: "Файловые системы", Label: "База доступна на запись", Help: "Своя копия базы вместо общей read-only.", Kind: KindBool, Admin: true},
	{Name: "ver", Group: "Файловые системы", Label: "Версия базы", Help: "Например 14.2 или native. Должна быть загружена.", Kind: KindText, Admin: true, valid: reVer.MatchString},

	{Name: "sysvsem", Group: "IPC", Label: "Семафоры SysV", Kind: KindEnum, Options: []string{"new", "inherit", "disable"}},
	{Name: "sysvshm", Group: "IPC", Label: "Разделяемая память SysV", Help: "new нужен, например, для PostgreSQL.", Kind: KindEnum, Options: []string{"new", "inherit", "disable"}},
	{Name: "sysvmsg", Group: "IPC", Label: "Очереди сообщений SysV", Kind: KindEnum, Options: []string{"new", "inherit", "disable"}},

	t("cpuset", "Процессы и ресурсы", "Привязка к ядрам CPU", "Например 0-3 или 1,3. 0 — без привязки.", true, orZero(reCPUSet.MatchString)),
	n("childrenmax", "Процессы и ресурсы", "Вложенных клеток, максимум", "", 0, 9999, false),
	b("persist", "Процессы и ресурсы", "persist", "Клетка живёт без процессов.", false),
	n("stop_timeout", "Процессы и ресурсы", "Тайм-аут остановки, с", "", 0, 3600, false),
	n("exec_timeout", "Процессы и ресурсы", "Тайм-аут команд запуска, с", "0 — без ограничения.", 0, 86400, false),

	hook("exec_start", "exec_start", "Команда запуска внутри клетки (по умолчанию /bin/sh /etc/rc)."),
	hook("exec_stop", "exec_stop", "Команда остановки внутри клетки."),
	hook("exec_prestart", "exec_prestart", "Внутри клетки до запуска."),
	hook("exec_prestop", "exec_prestop", "Внутри клетки до остановки."),
	hook("exec_master_prestart", "exec_master_prestart", "На хосте до запуска."),
	hook("exec_master_poststart", "exec_master_poststart", "На хосте после запуска."),
	hook("exec_master_prestop", "exec_master_prestop", "На хосте до остановки."),
	hook("exec_master_poststop", "exec_master_poststop", "На хосте после остановки."),
	hook("mnt_start", "mnt_start", "Скрипт монтирования на хосте вместо стандартного."),
	hook("mnt_stop", "mnt_stop", "Скрипт размонтирования на хосте."),
	{Name: "exec_consolelog", Group: "Хуки и команды", Label: "Журнал консоли", Help: "Путь к файлу на хосте или 0.", Kind: KindText, Live: true, Admin: true, valid: orZero(reAbsPath.MatchString)},
}

var paramIndex = func() map[string]*Param {
	m := map[string]*Param{}
	for i := range JailParams {
		m[JailParams[i].Name] = &JailParams[i]
	}
	return m
}()

// LookupParam returns the spec of a jail parameter.
func LookupParam(name string) (*Param, bool) {
	p, ok := paramIndex[name]
	return p, ok
}

// Validate checks a value for this parameter.
func (p *Param) Validate(v string) bool {
	switch p.Kind {
	case KindBool:
		return v == "0" || v == "1"
	case KindInt:
		i, err := strconv.Atoi(v)
		return err == nil && i >= p.Min && i <= p.Max && strconv.Itoa(i) == v
	case KindEnum:
		for _, o := range p.Options {
			if v == o {
				return true
			}
		}
		return false
	default:
		return p.valid != nil && p.valid(v)
	}
}

// JailConfigUpdate is a set of jset changes.
type JailConfigUpdate struct {
	Values  map[string]string `json:"values"`
	Restart bool              `json:"restart"`
}

// Args validates the update and returns jset arguments. isAdmin gates Admin
// params; running reports whether the jail is up, because jset silently skips
// non-live params on a running jail unless autorestart=1.
func (u *JailConfigUpdate) Args(name string, isAdmin, running bool) ([]string, error) {
	if len(u.Values) == 0 {
		return nil, ferr("", "нет изменений")
	}
	if len(u.Values) > len(JailParams) {
		return nil, ferr("", "слишком много параметров")
	}
	args := []string{"jset", "jname=" + name}
	needRestart := false
	// Stable order keeps the command line and the audit log readable.
	for _, p := range JailParams {
		v, ok := u.Values[p.Name]
		if !ok {
			continue
		}
		if p.Admin && !isAdmin {
			return nil, ferr(p.Name, "этот параметр меняет только администратор")
		}
		if !p.Validate(v) {
			return nil, ferr(p.Name, "недопустимое значение")
		}
		if !p.Live {
			needRestart = true
		}
		args = append(args, p.Name+"="+v)
	}
	for k := range u.Values {
		if _, ok := paramIndex[k]; !ok {
			return nil, ferr(k, "неизвестный параметр")
		}
	}
	if running && needRestart {
		if !u.Restart {
			return nil, ferr("restart", "часть параметров применяется только перезапуском: отметьте «Перезапустить клетку»")
		}
		args = append(args, "autorestart=1")
	}
	return args, nil
}

// JailConfig reads the current values of all JailParams from local::jails.
func (d *DB) JailConfig(ctx context.Context, name string) (map[string]string, error) {
	want := make([]string, 0, len(JailParams)+1)
	want = append(want, "jname")
	for _, p := range JailParams {
		want = append(want, p.Name)
	}
	rows, err := d.selectAvailable(ctx, "local", "jails", want, "jname = ?", name)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	out := map[string]string{}
	for k, v := range rows[0] {
		if k != "jname" {
			out[k] = str(v)
		}
	}
	return out, nil
}

// RctlParam is one resource limit 'cbsd jrctl mode=set' accepts.
type RctlParam struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Help  string `json:"help,omitempty"`
	Size  bool   `json:"size,omitempty"` // accepts k/m/g/t suffix
}

// RctlParams mirrors share/rctl.conf (RCTL and RCTL_EXTRA without cpu).
var RctlParams = []RctlParam{
	{"memoryuse", "Память (RSS)", "Например 2g.", true},
	{"vmemoryuse", "Адресное пространство", "", true},
	{"swapuse", "Swap", "", true},
	{"memorylocked", "Заблокированная память", "", true},
	{"datasize", "Сегмент данных", "", true},
	{"stacksize", "Стек", "", true},
	{"coredumpsize", "Размер core-дампа", "", true},
	{"pcpu", "CPU, %", "Процент одного ядра: 200 — два ядра.", false},
	{"nice", "Приоритет (nice)", "От -20 (выше) до 20 (ниже).", false},
	{"maxproc", "Процессов", "", false},
	{"nthr", "Потоков", "", false},
	{"openfiles", "Открытых файлов", "", false},
	{"pseudoterminals", "Псевдотерминалов", "", false},
	{"wallclock", "Время работы, с", "", false},
	{"fsquota", "Квота ФС", "Например 20g (ZFS).", true},
	{"bw", "Полоса сети", "Ограничение трафика.", false},
	{"readbps", "Чтение с диска, байт/с", "", true},
	{"writebps", "Запись на диск, байт/с", "", true},
	{"readiops", "Чтение, операций/с", "", false},
	{"writeiops", "Запись, операций/с", "", false},
	{"msgqqueued", "SysV: сообщений в очереди", "", false},
	{"msgqsize", "SysV: размер очереди", "", true},
	{"nmsgq", "SysV: очередей", "", false},
	{"nsem", "SysV: семафоров", "", false},
	{"nsemop", "SysV: операций semop", "", false},
	{"nshm", "SysV: сегментов памяти", "", false},
	{"shmsize", "SysV: разделяемая память", "", true},
}

var (
	reRctlSize = regexp.MustCompile(`^[0-9]{1,15}[kKmMgGtT]?$`)
	reRctlNum  = regexp.MustCompile(`^[0-9]{1,15}$`)
	reNice     = regexp.MustCompile(`^-?[0-9]{1,2}$`)
)

func validRctl(p RctlParam, v string) bool {
	switch {
	case p.Name == "nice":
		i, err := strconv.Atoi(v)
		return reNice.MatchString(v) && err == nil && i >= -20 && i <= 20
	case p.Size:
		return reRctlSize.MatchString(v)
	default:
		return reRctlNum.MatchString(v)
	}
}

// RctlArgs validates limits and returns 'jrctl mode=set' arguments. "0" removes a limit.
func RctlArgs(name string, values map[string]string) ([]string, error) {
	if len(values) == 0 {
		return nil, ferr("", "нет изменений")
	}
	known := map[string]bool{}
	args := []string{"jrctl", "mode=set", "jname=" + name}
	for _, p := range RctlParams {
		known[p.Name] = true
		v, ok := values[p.Name]
		if !ok {
			continue
		}
		if !validRctl(p, v) {
			return nil, ferr(p.Name, "ожидается число%s", map[bool]string{true: " с необязательным суффиксом k/m/g/t", false: ""}[p.Size])
		}
		args = append(args, p.Name+"="+v)
	}
	for k := range values {
		if !known[k] {
			return nil, ferr(k, "неизвестный параметр")
		}
	}
	return args, nil
}

// JailLimits reads configured limits from jails-system/NAME/helpers/jrctl.sqlite.
// The file is created by CBSD on the first 'jrctl mode=set', so a missing file
// just means no limits. It may also be unreadable for the unprivileged daemon.
func (d *DB) JailLimits(ctx context.Context, name string) (map[string]string, error) {
	path := filepath.Join(d.workdir, "jails-system", name, "helpers", "jrctl.sqlite")
	c, err := openRO(path)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	rows, err := c.QueryContext(ctx, "SELECT param, cur FROM forms")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v any
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[str(k)] = str(v)
	}
	return out, rows.Err()
}
