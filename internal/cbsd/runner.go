package cbsd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Runner executes the cbsd CLI without a shell, with a sanitized environment.
type Runner struct {
	Cmd     []string // e.g. [/usr/local/bin/sudo -n /usr/local/bin/cbsd]
	Workdir string
	Timeout time.Duration
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]`)

// StripANSI removes terminal escape sequences that cbsd prints even with NOCOLOR.
func StripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

func (r *Runner) env() []string {
	return []string{
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
		"NOCOLOR=1",
		"NOINTER=1",
		"TERM=dumb",
		"LANG=C.UTF-8",
		"workdir=" + r.Workdir,
	}
}

func (r *Runner) command(ctx context.Context, base []string, args []string) *exec.Cmd {
	full := append(append([]string{}, base[1:]...), args...)
	cmd := exec.CommandContext(ctx, base[0], full...)
	cmd.Env = r.env()
	cmd.Stdin = nil // never let cbsd wait for interactive input
	setProcessGroup(cmd)
	cmd.WaitDelay = 10 * time.Second
	return cmd
}

// Stream runs cbsd with args, writing combined output to out.
func (r *Runner) Stream(ctx context.Context, out io.Writer, args ...string) error {
	return r.StreamWith(ctx, r.Cmd, out, args...)
}

// StreamWith runs an arbitrary configured base command (e.g. initenv).
func (r *Runner) StreamWith(ctx context.Context, base []string, out io.Writer, args ...string) error {
	if len(base) == 0 {
		return errors.New("command not configured")
	}
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	cmd := r.command(ctx, base, args)
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

// Output runs a short read-only cbsd command and returns its cleaned output.
func (r *Runner) Output(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var buf bytes.Buffer
	cmd := r.command(ctx, r.Cmd, args)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return strings.TrimSpace(StripANSI(buf.String())), err
}

// Action is a lifecycle operation on an existing environment.
type Action string

const (
	ActStart   Action = "start"
	ActStop    Action = "stop"
	ActRestart Action = "restart"
	ActRemove  Action = "remove"
)

// Emulators known to the UI and the CLI prefix CBSD uses for each.
var emuPrefix = map[string]string{"jail": "j", "bhyve": "b", "xen": "x", "qemu": "q"}

// ActionArgs maps an action on an environment of a given emulator to cbsd args.
func ActionArgs(emulator string, a Action, name string) ([]string, error) {
	p, ok := emuPrefix[emulator]
	if !ok {
		return nil, errors.New("unsupported emulator")
	}
	if !ValidExistingName(name) {
		return nil, errors.New("invalid name")
	}
	var verb string
	switch a {
	case ActStart:
		verb = "start"
	case ActStop:
		verb = "stop"
	case ActRestart:
		if emulator == "xen" || emulator == "qemu" {
			return nil, errors.New("restart is not supported for " + emulator)
		}
		verb = "restart"
	case ActRemove:
		verb = "remove"
	default:
		return nil, errors.New("unknown action")
	}
	return []string{p + verb, "jname=" + name}, nil
}

// SnapshotArgs builds jsnapshot/bsnapshot arguments (ZFS only on the CBSD side).
func SnapshotArgs(emulator, mode, name, snap string) ([]string, error) {
	if !ValidExistingName(name) {
		return nil, errors.New("invalid name")
	}
	var cmd string
	switch emulator {
	case "jail":
		cmd = "jsnapshot"
	case "bhyve":
		cmd = "bsnapshot"
	default:
		return nil, errors.New("snapshots are supported for jails and bhyve VMs")
	}
	switch mode {
	case "create", "destroy", "rollback":
	default:
		return nil, errors.New("invalid snapshot mode")
	}
	if !ValidSnapName(snap) {
		return nil, ferr("snapname", "латиница, цифры, _.-")
	}
	return []string{cmd, "mode=" + mode, "jname=" + name, "snapname=" + snap}, nil
}

// CloneArgs builds jclone/bclone arguments.
func CloneArgs(emulator, from, to, hostname string) ([]string, error) {
	if !ValidExistingName(from) {
		return nil, errors.New("invalid source name")
	}
	if !ValidNewName(to) {
		return nil, ferr("new", "латиница, цифры и _, начинается с буквы")
	}
	switch emulator {
	case "jail":
		if hostname == "" {
			hostname = to
		}
		if !reHostname.MatchString(hostname) {
			return nil, ferr("host_hostname", "некорректное имя хоста")
		}
		return []string{"jclone", "old=" + from, "new=" + to, "host_hostname=" + hostname, "ip4_addr=DHCP"}, nil
	case "bhyve":
		return []string{"bclone", "old=" + from, "new=" + to}, nil
	}
	return nil, errors.New("clone is supported for jails and bhyve VMs")
}
