//go:build unix

package server

import "syscall"

// diskFree returns the bytes available to unprivileged users on p's filesystem.
func diskFree(p string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(p, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
