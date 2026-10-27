package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"

	"github.com/cbsd-web/cbsd-web/internal/audit"
	"github.com/cbsd-web/cbsd-web/internal/auth"
)

const (
	maxTerminalsPerUser = 4
	maxTerminals        = 16
)

// terminals counts open jail shells per user to bound resource use.
type terminals struct {
	mu     sync.Mutex
	byUser map[string]int
	total  int
}

func (t *terminals) acquire(user string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.byUser == nil {
		t.byUser = map[string]int{}
	}
	if t.total >= maxTerminals || t.byUser[user] >= maxTerminalsPerUser {
		return false
	}
	t.total++
	t.byUser[user]++
	return true
}

func (t *terminals) release(user string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.total--
	if t.byUser[user]--; t.byUser[user] <= 0 {
		delete(t.byUser, user)
	}
}

type termMsg struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

func (s *Server) terminalAllowed(role auth.Role) bool {
	switch s.cfg.TerminalRole {
	case "operator":
		return role.Allows(auth.RoleOperator)
	case "admin":
		return role.Allows(auth.RoleAdmin)
	}
	return false
}

// handleTerminal opens 'cbsd jlogin' for a running jail (or 'blogin'/'xlogin',
// the serial console of a VM) on a pty and bridges it to a WebSocket. Browsers cannot set headers on WebSocket requests, so the
// CSRF token comes in the query string and Origin must match the host.
func (s *Server) handleTerminal(w http.ResponseWriter, r *http.Request) {
	rc := sessionFrom(r)
	if !s.terminalAllowed(rc.sess.Role) {
		writeErr(w, http.StatusForbidden, "терминал недоступен для вашей роли")
		return
	}
	if r.Header.Get("Origin") == "" || !s.sameOrigin(r) || !auth.CSRFValid(rc.sess, r.URL.Query().Get("csrf")) {
		s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "csrf.reject", Target: r.URL.Path})
		writeErr(w, http.StatusForbidden, "CSRF-проверка не пройдена")
		return
	}
	e := s.loadEnv(w, r)
	if e == nil {
		return
	}
	login := map[string][]string{
		"jail": {"jlogin", "jname=" + e.Name},
		// remote=1 stops CBSD from offering to log in on another node.
		"bhyve": {"blogin", "jname=" + e.Name, "remote=1"},
		"xen":   {"xlogin", "jname=" + e.Name, "remote=1"},
	}[e.Emulator]
	if login == nil {
		writeErr(w, http.StatusBadRequest, "терминал недоступен для "+e.Emulator)
		return
	}
	if e.Status != 1 {
		writeErr(w, http.StatusConflict, "окружение не запущено")
		return
	}
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))
	if cols < 20 || cols > 500 {
		cols = 120
	}
	if rows < 5 || rows > 200 {
		rows = 32
	}
	if !s.terms.acquire(rc.sess.User) {
		writeErr(w, http.StatusTooManyRequests, "открыто слишком много терминалов")
		return
	}
	defer s.terms.release(rc.sess.User)

	// The server's read/write timeouts would otherwise kill the long-lived socket.
	ctl := http.NewResponseController(w)
	_ = ctl.SetReadDeadline(time.Time{})
	_ = ctl.SetWriteDeadline(time.Time{})

	conn, err := websocket.Accept(w, r, nil) // verifies Origin against Host
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(64 << 10)

	base := s.cfg.CBSDCommand
	args := append(append([]string{}, base[1:]...), login...)
	cmd := exec.Command(base[0], args...)
	cmd.Env = []string{
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin",
		"TERM=xterm-256color",
		"LANG=C.UTF-8",
		"workdir=" + s.cfg.Workdir,
	}
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		conn.Close(websocket.StatusInternalError, "не удалось запустить "+login[0])
		return
	}
	started := time.Now()
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "terminal.open", Target: e.Name})

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var lastActive atomic.Int64
	touch := func() { lastActive.Store(time.Now().UnixNano()) }
	touch()

	// pty -> browser
	go func() {
		defer cancel()
		buf := make([]byte, 32<<10)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				touch()
				wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
				werr := conn.Write(wctx, websocket.MessageBinary, buf[:n])
				wcancel()
				if werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	// browser -> pty
	go func() {
		defer cancel()
		for {
			typ, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			touch()
			if typ == websocket.MessageText {
				var m termMsg
				if json.Unmarshal(data, &m) == nil && m.Type == "resize" && m.Cols >= 20 && m.Cols <= 500 && m.Rows >= 5 && m.Rows <= 200 {
					_ = pty.Setsize(ptmx, &pty.Winsize{Cols: m.Cols, Rows: m.Rows})
				}
				continue
			}
			if _, err := ptmx.Write(data); err != nil {
				return
			}
		}
	}()
	// idle and session watchdog
	go func() {
		idle := time.Duration(s.cfg.TerminalIdleMinutes) * time.Minute
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, lastActive.Load())) > idle {
					conn.Close(websocket.StatusNormalClosure, "закрыт по бездействию")
					cancel()
					return
				}
				if _, ok := s.sessions.Get(rc.token); !ok {
					conn.Close(websocket.StatusPolicyViolation, "сессия завершена")
					cancel()
					return
				}
			}
		}
	}()

	<-ctx.Done()
	// Closing the master hangs up the session; jlogin and the shell get SIGHUP.
	// For a VM only the tmux client goes away; the VM keeps running.
	ptmx.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
		<-done
	}
	conn.Close(websocket.StatusNormalClosure, "сеанс завершён")
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "terminal.close", Target: e.Name,
		Detail: map[string]string{"duration": time.Since(started).Round(time.Second).String()}})
}
