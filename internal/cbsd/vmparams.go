package cbsd

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// VM settings that 'cbsd bset' / 'cbsd xset' accept (share/bhyve.conf and
// share/xen.conf MYCOL), with the same Param model as jail settings. bset
// writes them to local::bhyve; a running VM picks them up on its next start.

// VMParamGroups in display order.
var VMParamGroups = []string{"Основные", "Загрузка", "Консоль VNC", "Устройства", "Поведение", "Тонкая настройка bhyve", "Хуки"}

var (
	reResolution = regexp.MustCompile(`^[1-9][0-9]{2,3}x[1-9][0-9]{2,3}$`)
	reKbdLayout  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,31}$`)
)

func vmSize(s string) bool { return reSize.MatchString(s) }

func vmHook(name, label, help string) Param {
	return Param{Name: name, Group: "Хуки", Label: label, Help: help + " Путь к скрипту без пробелов или 0.", Kind: KindText, Admin: true, valid: orZero(reHook.MatchString)}
}

var onAction = []string{"destroy", "restart"}

// BhyveParams lists the bhyve settings the UI edits. Paths, wrappers,
// debugger, jailed/chrooted runs and disk layout stay with the CLI.
var BhyveParams = []Param{
	n("vm_cpus", "Основные", "vCPU", "", 1, 256, false),
	t("vm_ram", "Основные", "RAM", "Например 4g или 512m.", false, vmSize),
	b("astart", "Основные", "Автозапуск", "Запускать при загрузке хоста.", true),
	n("boot_delay", "Основные", "Задержка после запуска, с", "Пауза перед запуском следующей ВМ.", 0, 3600, true),
	b("protected", "Основные", "Защита от удаления", "", true),
	b("hidden", "Основные", "Скрыть в списках", "", true),
	t("tags", "Основные", "Теги", "Через запятую, 0 — нет.", true, orZero(reTags.MatchString)),
	t("ip4_addr", "Основные", "IP-адрес", "Для cloud-init и справки: DHCP или 10.0.0.5/24.", false, validIP4List),
	t("cpuset", "Основные", "Привязка к ядрам CPU", "Например 0-3 или 1,3. 0 — без привязки.", false, orZero(reCPUSet.MatchString)),

	{Name: "vm_boot", Group: "Загрузка", Label: "Загрузка с", Help: "cd — с ISO (установка), hdd — с диска.", Kind: KindEnum, Options: []string{"hdd", "cd"}},
	{Name: "vm_efi", Group: "Загрузка", Label: "Прошивка", Help: "uefi — обычный UEFI, uefi_csm — с поддержкой BIOS, none — bhyveload (только FreeBSD).", Kind: KindEnum, Options: []string{"uefi", "uefi_csm", "none"}},
	{Name: "cd_boot_firmware", Group: "Загрузка", Label: "Прошивка при загрузке с CD", Kind: KindEnum, Options: []string{"bhyve", "refind"}},
	{Name: "hdd_boot_firmware", Group: "Загрузка", Label: "Прошивка при загрузке с диска", Kind: KindEnum, Options: []string{"bhyve", "refind"}},
	b("cd_vnc_wait", "Загрузка", "Ждать подключения VNC при загрузке с CD", "Гость стартует только после подключения к консоли, чтобы не пропустить установщик.", false),

	t("bhyve_vnc_tcp_bind", "Консоль VNC", "VNC слушает", "127.0.0.1 — только через SSH-туннель или консоль в браузере; 0.0.0.0 — все интерфейсы.", false, validIP),
	n("vm_vnc_port", "Консоль VNC", "Порт VNC", "0 — выбрать автоматически, 1 — отключить VNC.", 0, 65535, false),
	t("bhyve_vnc_resolution", "Консоль VNC", "Разрешение экрана", "Например 1024x768 или 1920x1080.", false, reResolution.MatchString),
	{Name: "vnc_password", Group: "Консоль VNC", Label: "Пароль VNC", Help: "6–32 символа: буквы, цифры, _.@%+=-. Текущий не показывается.", Kind: KindText, Admin: true, Secret: true, valid: reVNCPass.MatchString},
	{Name: "bhyve_vnc_vgaconf", Group: "Консоль VNC", Label: "VGA", Help: "io — по умолчанию; off нужен некоторым гостям (OpenBSD).", Kind: KindEnum, Options: []string{"io", "on", "off"}},
	t("bhyve_vnc_kbdlayout", "Консоль VNC", "Раскладка клавиатуры", "Имя из /usr/share/bhyve/kbdlayout, например ru; 0 — по умолчанию.", false, orZero(reKbdLayout.MatchString)),

	b("fbuf", "Устройства", "Видеоадаптер (framebuffer)", "Без него нет консоли VNC.", false),
	b("xhci", "Устройства", "USB-контроллер xHCI", "", false),
	b("tablet", "Устройства", "USB-планшет", "Точный указатель мыши в VNC.", false),
	b("virtio_rnd", "Устройства", "virtio-rnd", "Генератор случайных чисел для гостя.", false),
	{Name: "soundhw", Group: "Устройства", Label: "Звук", Kind: KindEnum, Options: []string{"none", "hda"}},
	{Name: "vm_hostbridge", Group: "Устройства", Label: "Host bridge", Help: "amd_hostbridge нужен некоторым гостям на AMD.", Kind: KindEnum, Options: []string{"hostbridge", "amd_hostbridge"}},
	{Name: "tpm", Group: "Устройства", Label: "TPM", Help: "new — эмуляция (swtpm, нужна Windows 11), 0 — нет.", Kind: KindEnum, Options: []string{"0", "new"}, Admin: true},

	{Name: "on_poweroff", Group: "Поведение", Label: "При выключении гостя", Kind: KindEnum, Options: onAction},
	{Name: "on_reboot", Group: "Поведение", Label: "При перезагрузке гостя", Kind: KindEnum, Options: onAction},
	{Name: "on_crash", Group: "Поведение", Label: "При сбое", Kind: KindEnum, Options: onAction},
	b("double_acpi", "Поведение", "Двойной ACPI-сигнал при остановке", "Помогает гостям, которые игнорируют первый.", true),

	b("bhyve_generate_acpi", "Тонкая настройка bhyve", "Таблицы ACPI (-A)", "Нужно FreeBSD/amd64 и большинству гостей.", false),
	b("bhyve_wire_memory", "Тонкая настройка bhyve", "Закрепить память (-S)", "Память гостя не уходит в swap; нужно для PCI passthrough.", false),
	b("bhyve_rts_keeps_utc", "Тонкая настройка bhyve", "Часы в UTC (-u)", "Выключите для Windows.", false),
	b("bhyve_force_msi_irq", "Тонкая настройка bhyve", "MSI вместо MSI-X (-W)", "", false),
	b("bhyve_x2apic_mode", "Тонкая настройка bhyve", "x2APIC (-x)", "", false),
	b("bhyve_mptable_gen", "Тонкая настройка bhyve", "Таблица MPtable", "Выключение соответствует -Y.", false),
	b("bhyve_ignore_msr_acc", "Тонкая настройка bhyve", "Игнорировать неизвестные MSR (-w)", "Помогает некоторым Linux и Windows.", false),

	vmHook("mnt_start", "mnt_start", "Скрипт на хосте до запуска."),
	vmHook("mnt_stop", "mnt_stop", "Скрипт на хосте после остановки."),
}

// XenParams lists the Xen settings the UI edits.
var XenParams = []Param{
	n("vm_cpus", "Основные", "vCPU", "", 1, 256, false),
	t("vm_ram", "Основные", "RAM", "Например 4g или 512m.", false, vmSize),
	b("astart", "Основные", "Автозапуск", "Запускать при загрузке хоста.", true),
	b("protected", "Основные", "Защита от удаления", "", true),
	b("hidden", "Основные", "Скрыть в списках", "", true),
	t("ip4_addr", "Основные", "IP-адрес", "Для cloud-init и справки: DHCP или 10.0.0.5/24.", false, validIP4List),

	{Name: "vm_boot", Group: "Загрузка", Label: "Загрузка с", Help: "cd — с ISO (установка), hdd — с диска.", Kind: KindEnum, Options: []string{"hdd", "cd"}},
	b("cd_vnc_wait", "Загрузка", "Ждать подключения VNC при загрузке с CD", "", false),

	t("xen_vnc_tcp_bind", "Консоль VNC", "VNC слушает", "127.0.0.1 или 0.0.0.0.", false, validIP),
	n("vm_vnc_port", "Консоль VNC", "Порт VNC", "0 — выбрать автоматически, 1 — отключить VNC.", 0, 65535, false),
	t("xen_vnc_resolution", "Консоль VNC", "Разрешение экрана", "Например 1024x768.", false, reResolution.MatchString),
	{Name: "vnc_password", Group: "Консоль VNC", Label: "Пароль VNC", Help: "6–32 символа. Текущий не показывается.", Kind: KindText, Admin: true, Secret: true, valid: reVNCPass.MatchString},

	{Name: "soundhw", Group: "Устройства", Label: "Звук", Kind: KindEnum, Options: []string{"none", "hda"}},
	b("xen_hap", "Устройства", "HAP (аппаратный пейджинг)", "", false),
	b("xen_nestedhvm", "Устройства", "Вложенная виртуализация", "", false),

	{Name: "on_poweroff", Group: "Поведение", Label: "При выключении гостя", Kind: KindEnum, Options: onAction},
	{Name: "on_reboot", Group: "Поведение", Label: "При перезагрузке гостя", Kind: KindEnum, Options: onAction},
	{Name: "on_crash", Group: "Поведение", Label: "При сбое", Kind: KindEnum, Options: onAction},
}

// VMParamsFor returns the settings list of an emulator ("bhyve" or "xen").
func VMParamsFor(emulator string) []Param {
	if emulator == "xen" {
		return XenParams
	}
	return BhyveParams
}

// VMConfigUpdate is a set of bset/xset changes.
type VMConfigUpdate struct {
	Values  map[string]string `json:"values"`
	Restart bool              `json:"restart"`
}

// Args validates the update and returns bset/xset arguments.
func (u *VMConfigUpdate) Args(emulator, name string, isAdmin bool) ([]string, error) {
	params := VMParamsFor(emulator)
	if len(u.Values) == 0 {
		return nil, ferr("", "нет изменений")
	}
	if len(u.Values) > len(params) {
		return nil, ferr("", "слишком много параметров")
	}
	known := map[string]bool{}
	for _, p := range params {
		known[p.Name] = true
	}
	for k := range u.Values {
		if !known[k] {
			return nil, ferr(k, "неизвестный параметр")
		}
	}
	cmd := "bset"
	if emulator == "xen" {
		cmd = "xset"
	}
	args := []string{cmd, "jname=" + name}
	for _, p := range params {
		v, ok := u.Values[p.Name]
		if !ok {
			continue
		}
		if p.Admin && !isAdmin {
			return nil, ferr(p.Name, "этот параметр меняет только администратор")
		}
		if p.Name == "vm_ram" {
			v = strings.ToLower(v)
		}
		if !p.Validate(v) {
			return nil, ferr(p.Name, "недопустимое значение")
		}
		args = append(args, p.Name+"="+v)
	}
	return args, nil
}

// VMConfig reads the current values of a VM's settings from local::bhyve or
// local::xen. Secret values are reported only as set or not set.
func (d *DB) VMConfig(ctx context.Context, emulator, name string) (map[string]string, map[string]bool, error) {
	params := VMParamsFor(emulator)
	want := make([]string, 0, len(params)+1)
	want = append(want, "jname")
	for _, p := range params {
		want = append(want, p.Name)
	}
	table := "bhyve"
	if emulator == "xen" {
		table = "xen"
	}
	// ip4_addr, astart, protected and hidden are also kept in local::jails,
	// which the rest of the UI shows; that copy wins.
	rows, err := d.selectAvailable(ctx, "local", table, want, "jname = ?", name)
	if err != nil || len(rows) == 0 {
		return nil, nil, err
	}
	out := map[string]string{}
	for k, v := range rows[0] {
		if k != "jname" {
			out[k] = str(v)
		}
	}
	jrows, err := d.selectAvailable(ctx, "local", "jails", []string{"ip4_addr", "astart", "protected", "hidden"}, "jname = ?", name)
	if err == nil && len(jrows) > 0 {
		for k, v := range jrows[0] {
			out[k] = str(v)
		}
	}
	if ram, ok := out["vm_ram"]; ok {
		out["vm_ram"] = humanRAM(ram)
	}
	secret := map[string]bool{}
	for _, p := range params {
		if p.Secret {
			if v, ok := out[p.Name]; ok {
				secret[p.Name] = v != "" && v != "0"
				out[p.Name] = ""
			}
		}
	}
	return out, secret, nil
}

// humanRAM turns CBSD's byte count into the size form bset accepts.
func humanRAM(s string) string {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return s
	}
	const mb, gb = 1 << 20, 1 << 30
	if n%gb == 0 {
		return strconv.FormatInt(n/gb, 10) + "g"
	}
	return strconv.FormatInt(n/mb, 10) + "m"
}
