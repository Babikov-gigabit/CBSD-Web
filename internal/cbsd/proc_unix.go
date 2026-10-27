//go:build unix

package cbsd

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts cbsd and all its children into their own process group,
// so a cancelled or timed-out job kills the whole tree, not just the parent.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}
