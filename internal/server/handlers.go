package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cbsd-web/cbsd-web/internal/audit"
	"github.com/cbsd-web/cbsd-web/internal/auth"
	"github.com/cbsd-web/cbsd-web/internal/cbsd"
	"github.com/cbsd-web/cbsd-web/internal/hoststat"
)

// ---------- session ----------

type loginReq struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r, s.cfg)
	var req loginReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.User = strings.ToLower(strings.TrimSpace(req.User))
	if len(req.User) > 64 {
		req.User = req.User[:64]
	}
	for _, key := range []string{"ip:" + ip, "u:" + req.User} {
		if blocked, left := s.limiter.Blocked(key); blocked {
			w.Header().Set("Retry-After", strconv.Itoa(int(left.Seconds())+1))
			writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("слишком много попыток, повторите через %d мин.", int(left.Minutes())+1))
			return
		}
	}
	u, ok := s.users.Verify(req.User, req.Password)
	if !ok {
		s.limiter.Fail("ip:" + ip)
		s.limiter.Fail("u:" + req.User)
		s.audit.Log(audit.Entry{User: req.User, IP: ip, Event: "login", Result: "fail"})
		writeErr(w, http.StatusUnauthorized, "неверное имя пользователя или пароль")
		return
	}
	s.limiter.Reset("ip:" + ip)
	s.limiter.Reset("u:" + req.User)
	token, sess := s.sessions.Create(u.Name, u.Role, ip)
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: http.SameSiteStrictMode,
	})
	s.audit.Log(audit.Entry{User: u.Name, IP: ip, Event: "login", Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"user": sess.User, "role": sess.Role, "csrf": sess.CSRF, "version": s.version, "terminal": s.terminalAllowed(sess.Role)})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessions.Get(s.cookieToken(r))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "требуется вход", "has_users": s.users.Count() > 0})
		return
	}
	u, exists := s.users.Get(sess.User)
	if !exists {
		writeErr(w, http.StatusUnauthorized, "требуется вход")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": sess.User, "role": u.Role, "csrf": sess.CSRF, "version": s.version, "terminal": s.terminalAllowed(u.Role)})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	rc := sessionFrom(r)
	s.sessions.Delete(rc.token)
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.SecureCookies(), SameSite: http.SameSiteStrictMode})
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "logout"})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------- overview ----------

type cachedVersion struct {
	mu  sync.Mutex
	at  time.Time
	val string
	err string
}

var cbsdVersion cachedVersion

func (s *Server) cbsdVersion(ctx context.Context) (string, string) {
	cbsdVersion.mu.Lock()
	defer cbsdVersion.mu.Unlock()
	if time.Since(cbsdVersion.at) < 5*time.Minute {
		return cbsdVersion.val, cbsdVersion.err
	}
	out, err := s.runner.Output(ctx, 15*time.Second, "version")
	cbsdVersion.at = time.Now()
	if err != nil {
		cbsdVersion.val, cbsdVersion.err = "", firstLine(out, err)
	} else {
		cbsdVersion.val, cbsdVersion.err = firstLine(out, nil), ""
	}
	return cbsdVersion.val, cbsdVersion.err
}

func firstLine(out string, err error) string {
	out = strings.TrimSpace(out)
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		out = out[:i]
	}
	if out == "" && err != nil {
		return err.Error()
	}
	if len(out) > 300 {
		out = out[:300]
	}
	return out
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	type counts struct {
		Total   int `json:"total"`
		Running int `json:"running"`
	}
	res := map[string]any{
		"host":        s.sys.Get(ctx),
		"workdir":     s.cfg.Workdir,
		"initialized": s.db.Exists("local"),
		"web_version": s.version,
		"busy":        s.jobs.Busy(),
	}
	ver, verr := s.cbsdVersion(ctx)
	res["cbsd_version"], res["cbsd_error"] = ver, verr
	if s.db.Exists("local") {
		envs, err := s.db.Envs(ctx, "")
		if err != nil {
			res["db_error"] = dbErrorMessage(err)
		}
		c := map[string]*counts{"jail": {}, "bhyve": {}, "xen": {}, "qemu": {}}
		for _, e := range envs {
			cc, ok := c[e.Emulator]
			if !ok {
				continue
			}
			cc.Total++
			if e.Status == 1 {
				cc.Running++
			}
		}
		res["counts"] = c
		if loc, err := s.db.Local(ctx); err == nil {
			res["node"] = loc
		}
	}
	recent := s.jobs.List()
	if len(recent) > 8 {
		recent = recent[:8]
	}
	res["recent_jobs"] = recent
	writeJSON(w, http.StatusOK, res)
}

// ---------- environments ----------

var emulators = map[string]bool{"jail": true, "bhyve": true, "xen": true, "qemu": true}

func (s *Server) handleEnvs(w http.ResponseWriter, r *http.Request) {
	emu := r.URL.Query().Get("emulator")
	if emu != "" && !emulators[emu] {
		writeErr(w, http.StatusBadRequest, "неизвестный эмулятор")
		return
	}
	if !s.db.Exists("local") {
		writeJSON(w, http.StatusOK, map[string]any{"envs": []any{}, "initialized": false})
		return
	}
	envs, err := s.db.Envs(r.Context(), emu)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, dbErrorMessage(err))
		return
	}
	showHidden := r.URL.Query().Get("hidden") == "1"
	out := envs[:0]
	for _, e := range envs {
		if e.Hidden && !showHidden {
			continue
		}
		out = append(out, e)
	}
	if out == nil {
		out = []cbsd.Env{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"envs": out, "busy": s.jobs.Busy(), "initialized": true})
}

func (s *Server) loadEnv(w http.ResponseWriter, r *http.Request) *cbsd.Env {
	name := r.PathValue("name")
	if !cbsd.ValidExistingName(name) {
		writeErr(w, http.StatusBadRequest, "некорректное имя")
		return nil
	}
	e, err := s.db.Env(r.Context(), name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, dbErrorMessage(err))
		return nil
	}
	if e == nil {
		writeErr(w, http.StatusNotFound, "окружение не найдено")
		return nil
	}
	return e
}

func (s *Server) handleEnv(w http.ResponseWriter, r *http.Request) {
	e := s.loadEnv(w, r)
	if e == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"env": e, "busy_job": s.jobs.Busy()[e.Name]})
}

// submit starts a cbsd job, audits it and answers 202 with the job.
func (s *Server) submit(w http.ResponseWriter, r *http.Request, title, target string, args []string, cleanup func()) {
	s.submitSteps(w, r, title, target, [][]string{args}, nil, func(error) {
		if cleanup != nil {
			cleanup()
		}
	})
}

// submitSteps runs several cbsd commands in one job, stopping at the first
// failure. finally runs after the steps whatever happened (e.g. starting a
// jail that the steps stopped); onDone (if set) gets the job's result.
func (s *Server) submitSteps(w http.ResponseWriter, r *http.Request, title, target string, steps, finally [][]string, onDone func(error)) {
	rc := sessionFrom(r)
	run := func(ctx context.Context, out io.Writer) (err error) {
		if onDone != nil {
			defer func() { onDone(err) }()
		}
		step := func(ctx context.Context, args []string) error {
			fmt.Fprintf(out, "$ cbsd %s\n", strings.Join(args, " "))
			st := &ansiStripper{w: out}
			err := s.runner.Stream(ctx, st, args...)
			st.Flush()
			if err != nil {
				return fmt.Errorf("cbsd %s: %w", args[0], err)
			}
			return nil
		}
		defer func() {
			// Runs even after a cancel, so a stopped jail comes back up.
			fctx := context.WithoutCancel(ctx)
			for _, args := range finally {
				if ferr := step(fctx, args); ferr != nil && err == nil {
					err = ferr
				}
			}
		}()
		for _, args := range steps {
			if err := step(ctx, args); err != nil {
				return err
			}
		}
		return nil
	}
	j, err := s.jobs.Submit(rc.sess.User, title, target, run)
	if err != nil {
		if onDone != nil {
			onDone(err)
		}
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	cmds := make([]string, len(steps))
	for i, st := range steps {
		cmds[i] = st[0]
	}
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "job.start", Target: target,
		Detail: map[string]string{"job": j.ID, "title": title, "cmd": strings.Join(cmds, ",")}})
	writeJSON(w, http.StatusAccepted, map[string]any{"job": j.Snapshot()})
}

type actionReq struct {
	Action string `json:"action"`
}

func (s *Server) handleEnvAction(w http.ResponseWriter, r *http.Request) {
	e := s.loadEnv(w, r)
	if e == nil {
		return
	}
	var req actionReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a := cbsd.Action(req.Action)
	if a == cbsd.ActRemove {
		if !sessionFrom(r).sess.Role.Allows(auth.RoleAdmin) {
			writeErr(w, http.StatusForbidden, "удаление доступно только администратору")
			return
		}
		if e.Protected {
			writeErr(w, http.StatusConflict, "окружение защищено от удаления (protected=1)")
			return
		}
	}
	args, err := cbsd.ActionArgs(e.Emulator, a, e.Name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.submit(w, r, actionTitle(a)+" "+e.Name, e.Name, args, nil)
}

func actionTitle(a cbsd.Action) string {
	switch a {
	case cbsd.ActStart:
		return "Запуск"
	case cbsd.ActStop:
		return "Остановка"
	case cbsd.ActRestart:
		return "Перезапуск"
	case cbsd.ActRemove:
		return "Удаление"
	}
	return string(a)
}

func (s *Server) handleEnvUpdate(w http.ResponseWriter, r *http.Request) {
	e := s.loadEnv(w, r)
	if e == nil {
		return
	}
	var args []string
	var err error
	switch e.Emulator {
	case "jail":
		var u cbsd.JailUpdate
		if err = readJSON(r, &u); err == nil {
			args, err = u.Args(e.Name)
		}
	case "bhyve", "xen":
		var u cbsd.VMUpdate
		if err = readJSON(r, &u); err == nil {
			args, err = u.Args(e.Emulator, e.Name)
		}
	default:
		err = errors.New("изменение настроек не поддерживается для " + e.Emulator)
	}
	if err != nil {
		writeFieldErr(w, err)
		return
	}
	s.submit(w, r, "Настройки "+e.Name, e.Name, args, nil)
}

func (s *Server) handleSnapshotList(w http.ResponseWriter, r *http.Request) {
	e := s.loadEnv(w, r)
	if e == nil {
		return
	}
	if e.Emulator != "jail" && e.Emulator != "bhyve" {
		writeJSON(w, http.StatusOK, map[string]any{"supported": false})
		return
	}
	out, err := s.runner.Output(r.Context(), 60*time.Second, cbsd.ListSnapshotArgs(e.Name)...)
	snaps := cbsd.ParseSnapshots(out)
	res := map[string]any{"supported": true}
	if err != nil {
		res["error"] = firstLine(out, err)
	}
	type item struct {
		cbsd.Snapshot
		Path string `json:"path,omitempty"` // browsable copy of a jail snapshot
		Used uint64 `json:"used,omitempty"` // space only this snapshot holds
	}
	items := make([]item, 0, len(snaps))
	used := map[string]map[string]uint64{}
	mounts := map[string]string{}
	for _, sn := range snaps {
		it := item{Snapshot: sn}
		if _, ok := used[sn.Dataset]; !ok {
			used[sn.Dataset] = hoststat.SnapshotUsed(r.Context(), sn.Dataset)
			if ds, err := hoststat.DatasetOf(r.Context(), sn.Dataset); err == nil && ds != nil {
				mounts[sn.Dataset] = ds.Mountpoint
			}
		}
		it.Used = used[sn.Dataset][sn.Dataset+"@"+sn.Name]
		if mp := mounts[sn.Dataset]; e.Emulator == "jail" && strings.HasPrefix(mp, "/") {
			it.Path = mp + "/.zfs/snapshot/" + sn.Name
		}
		items = append(items, it)
	}
	res["snapshots"] = items
	if len(snaps) == 0 && err == nil {
		res["text"] = out
	}
	writeJSON(w, http.StatusOK, res)
}

type snapReq struct {
	Mode     string `json:"mode"`
	SnapName string `json:"snapname"`
	SaveAs   string `json:"save_as,omitempty"` // rollback: keep the current state as this new jail
	// try: run the snapshot as a separate jail New (ZFS clone), optionally
	// snapshotting the current state as Keep first; Start boots it.
	New   string `json:"new,omitempty"`
	Keep  string `json:"keep,omitempty"`
	Start bool   `json:"start,omitempty"`
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	e := s.loadEnv(w, r)
	if e == nil {
		return
	}
	var req snapReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Mode != "create" && !sessionFrom(r).sess.Role.Allows(auth.RoleAdmin) {
		writeErr(w, http.StatusForbidden, "откат и удаление снимков доступны только администратору")
		return
	}
	if req.Mode == "rollback" {
		s.rollback(w, r, e, req.SnapName, req.SaveAs)
		return
	}
	if req.Mode == "try" {
		s.trySnapshot(w, r, e, req)
		return
	}
	if req.Mode == "destroyall" {
		req.SnapName = "*"
	}
	if req.SnapName == "" && req.Mode == "create" {
		req.SnapName = "web" + time.Now().Format("20060102150405")
	}
	args, err := cbsd.SnapshotArgs(e.Emulator, req.Mode, e.Name, req.SnapName)
	if err != nil {
		writeFieldErr(w, err)
		return
	}
	title := map[string]string{"create": "Снимок", "rollback": "Откат к снимку", "destroy": "Удаление снимка"}[req.Mode] + " " + e.Name + "@" + req.SnapName
	if req.Mode == "destroyall" {
		title = "Удаление всех снимков " + e.Name
	}
	s.submit(w, r, title, e.Name, args, nil)
}

type cloneReq struct {
	New      string `json:"new"`
	Hostname string `json:"host_hostname"`
}

func (s *Server) handleClone(w http.ResponseWriter, r *http.Request) {
	e := s.loadEnv(w, r)
	if e == nil {
		return
	}
	var req cloneReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if ex, _ := s.db.Env(r.Context(), req.New); ex != nil {
		writeFieldErr(w, &cbsd.FieldError{Field: "new", Msg: "имя уже занято"})
		return
	}
	args, err := cbsd.CloneArgs(e.Emulator, e.Name, req.New, req.Hostname)
	if err != nil {
		writeFieldErr(w, err)
		return
	}
	steps, finally := [][]string{args}, [][]string(nil)
	if e.Emulator == "jail" && e.Status == 1 {
		// jclone refuses a running jail; stop it for a consistent copy and start it again.
		steps = [][]string{{"jstop", "jname=" + e.Name}, args}
		finally = [][]string{{"jstart", "jname=" + e.Name}}
	}
	s.submitSteps(w, r, "Клонирование "+e.Name+" → "+req.New, e.Name, steps, finally, nil)
}

func (s *Server) requireInitialized(w http.ResponseWriter) bool {
	if !s.db.Exists("local") {
		writeErr(w, http.StatusConflict, "CBSD не инициализирован: выполните первичную настройку")
		return false
	}
	return true
}

func (s *Server) handleJailCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireInitialized(w) {
		return
	}
	var req cbsd.JailCreate
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	args, err := req.Args()
	if err != nil {
		writeFieldErr(w, err)
		return
	}
	if ex, _ := s.db.Env(r.Context(), req.Name); ex != nil {
		writeFieldErr(w, &cbsd.FieldError{Field: "jname", Msg: "имя уже занято"})
		return
	}
	s.submit(w, r, "Создание клетки "+req.Name, req.Name, args, nil)
}

type vmCreateReq struct {
	cbsd.VMCreate
	PubKey string `json:"ci_user_pubkey"`
}

func (s *Server) handleVMCreate(w http.ResponseWriter, r *http.Request) {
	emu := r.PathValue("emulator")
	if emu != "bhyve" && emu != "xen" {
		writeErr(w, http.StatusBadRequest, "поддерживаются bhyve и xen")
		return
	}
	if !s.requireInitialized(w) {
		return
	}
	var req vmCreateReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.profiles.Has(emu, req.OSType, req.Profile) {
		writeFieldErr(w, &cbsd.FieldError{Field: "vm_os_profile", Msg: "профиль не найден"})
		return
	}
	if ex, _ := s.db.Env(r.Context(), req.Name); ex != nil {
		writeFieldErr(w, &cbsd.FieldError{Field: "jname", Msg: "имя уже занято"})
		return
	}
	// The key is passed to CBSD as a file path, never inline, so it cannot
	// break CBSD's argument parsing.
	keyPath, cleanup := "", func() {}
	if k := strings.TrimSpace(req.PubKey); k != "" {
		if !cbsd.ValidPubKey(k) {
			writeFieldErr(w, &cbsd.FieldError{Field: "ci_user_pubkey", Msg: "ожидается одна строка открытого ключа OpenSSH"})
			return
		}
		dir := filepath.Join(s.cfg.DataDir, "pubkeys")
		if err := ensureDir(dir); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		keyPath = filepath.Join(dir, auth.RandomToken()+".pub")
		if err := os.WriteFile(keyPath, []byte(k+"\n"), 0o640); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		cleanup = func() { os.Remove(keyPath) }
	}
	args, err := req.Args(emu, keyPath)
	if err != nil {
		cleanup()
		writeFieldErr(w, err)
		return
	}
	s.submit(w, r, "Создание ВМ "+req.Name, req.Name, args, cleanup)
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	emu := r.URL.Query().Get("emulator")
	if emu != "bhyve" && emu != "xen" {
		emu = "bhyve"
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": s.profiles.For(emu)})
}

func rowsOrEmpty(rows []cbsd.Row) []cbsd.Row {
	if rows == nil {
		return []cbsd.Row{}
	}
	return rows
}

func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	if !s.db.Exists("local") {
		writeJSON(w, http.StatusOK, map[string]any{"images": []any{}, "media": []any{}})
		return
	}
	img, err1 := s.db.Images(r.Context())
	med, err2 := s.db.Media(r.Context())
	if err := errors.Join(err1, err2); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"images": rowsOrEmpty(img), "media": rowsOrEmpty(med)})
}

func (s *Server) handleBases(w http.ResponseWriter, r *http.Request) {
	if !s.db.Exists("local") {
		writeJSON(w, http.StatusOK, map[string]any{"bases": []any{}})
		return
	}
	rows, err := s.db.Bases(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bases": rowsOrEmpty(rows)})
}

func (s *Server) handleBaseFetch(w http.ResponseWriter, r *http.Request) {
	if !s.requireInitialized(w) {
		return
	}
	var req cbsd.BaseFetch
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	args, err := req.Args()
	if err != nil {
		writeFieldErr(w, err)
		return
	}
	s.submit(w, r, "Загрузка базы FreeBSD "+req.Ver, "base:"+req.Ver, args, nil)
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Nodes(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": rowsOrEmpty(rows)})
}

// ---------- jobs ----------

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"jobs": s.jobs.List()})
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	j := s.jobs.Get(r.PathValue("id"))
	if j == nil {
		writeErr(w, http.StatusNotFound, "задача не найдена")
		return
	}
	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	data, next, _ := j.Output(off)
	writeJSON(w, http.StatusOK, map[string]any{"job": j.Snapshot(), "output": string(data), "offset": next})
}

// handleJobStream streams job output as Server-Sent Events.
func (s *Server) handleJobStream(w http.ResponseWriter, r *http.Request) {
	j := s.jobs.Get(r.PathValue("id"))
	if j == nil {
		writeErr(w, http.StatusNotFound, "задача не найдена")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ch, unsub := j.Subscribe()
	defer unsub()
	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	send := func(event string, v any) bool {
		b, _ := json.Marshal(v)
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	for {
		data, next, finished := j.Output(off)
		if len(data) > 0 || off != next {
			if !send("out", map[string]any{"data": string(data), "offset": next}) {
				return
			}
			off = next
		}
		if finished {
			send("end", j.Snapshot())
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-ch:
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		}
	}
}

func (s *Server) handleJobCancel(w http.ResponseWriter, r *http.Request) {
	rc := sessionFrom(r)
	j := s.jobs.Get(r.PathValue("id"))
	if j == nil {
		writeErr(w, http.StatusNotFound, "задача не найдена")
		return
	}
	if j.Snapshot().User != rc.sess.User && !rc.sess.Role.Allows(auth.RoleAdmin) {
		writeErr(w, http.StatusForbidden, "можно отменять только свои задачи")
		return
	}
	s.jobs.Cancel(j.ID)
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "job.cancel", Target: j.ID})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------- setup ----------

type check struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var checks []check
	add := func(c check) { checks = append(checks, c) }

	add(check{ID: "os", Title: "ОС FreeBSD", OK: runtime.GOOS == "freebsd", Detail: runtime.GOOS + "/" + runtime.GOARCH,
		Hint: "CBSD работает на FreeBSD (и производных)."})

	bin := s.cfg.CBSDCommand[len(s.cfg.CBSDCommand)-1]
	_, err := os.Stat(bin)
	add(check{ID: "cbsd_bin", Title: "CBSD установлен", OK: err == nil, Detail: bin,
		Hint: "Установите пакет: pkg install -y cbsd"})

	ver, verr := s.cbsdVersion(ctx)
	add(check{ID: "cbsd_exec", Title: "Запуск cbsd через sudo", OK: verr == "", Detail: firstNonEmpty(ver, verr),
		Hint: "Проверьте правило sudo из deploy/sudoers (пользователь cbsdweb, NOPASSWD для /usr/local/bin/cbsd)."})

	_, err = os.Stat(s.cfg.Workdir)
	add(check{ID: "workdir", Title: "Рабочий каталог", OK: err == nil, Detail: s.cfg.Workdir,
		Hint: "На ZFS создайте отдельный датасет: zfs create -o mountpoint=/usr/jails zroot/jails"})

	add(check{ID: "initenv", Title: "CBSD инициализирован (initenv)", OK: s.db.Exists("local"),
		Detail: filepath.Join(s.cfg.Workdir, "var/db/local.sqlite"), Hint: "Запустите мастер первичной настройки ниже."})

	if s.db.Exists("local") {
		err := s.db.Readable(ctx, "local")
		add(check{ID: "db_access", Title: "Доступ веб-интерфейса к базам CBSD", OK: err == nil, Detail: errText(err),
			Hint: dbAccessHint})
	}

	rc, _ := os.ReadFile("/etc/rc.conf")
	enabled := strings.Contains(string(rc), `cbsdd_enable="YES"`) || strings.Contains(string(rc), "cbsdd_enable=YES")
	add(check{ID: "rcconf", Title: "Автозапуск cbsdd", OK: enabled, Hint: "sysrc cbsdd_enable=YES (initenv делает это сам)."})

	hi := s.sys.Get(ctx)
	add(check{ID: "vmm", Title: "Модуль vmm (bhyve)", OK: hi.VMMLoaded, Hint: "kldload vmm; sysrc kld_list+=vmm — нужно только для bhyve."})

	writeJSON(w, http.StatusOK, map[string]any{"checks": checks, "workdir": s.cfg.Workdir, "initialized": s.db.Exists("local")})
}

const dbAccessHint = "Базы CBSD доступны только группе cbsd. Добавьте в неё пользователя веб-интерфейса и перезапустите службу: pw groupmod cbsd -m cbsdweb && service cbsdweb restart"

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// dbErrorMessage turns a database error into an actionable message for the UI.
func dbErrorMessage(err error) string {
	if cbsd.IsPermission(err) {
		return "нет прав на чтение баз CBSD (" + err.Error() + "). " + dbAccessHint
	}
	return "ошибка чтения базы CBSD: " + err.Error()
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

func (s *Server) handleInitenv(w http.ResponseWriter, r *http.Request) {
	var req cbsd.InitEnv
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	conf, err := req.Conf()
	if err != nil {
		writeFieldErr(w, err)
		return
	}
	if len(s.cfg.InitenvCommand) == 0 {
		writeErr(w, http.StatusConflict, "initenv_command не настроен")
		return
	}
	if err := ensureDir(s.cfg.DataDir); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	path := filepath.Join(s.cfg.DataDir, "initenv-"+auth.RandomToken()[:12]+".conf")
	if err := os.WriteFile(path, []byte(conf), 0o640); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rc := sessionFrom(r)
	runner := *s.runner
	runner.Workdir = req.Workdir
	run := func(ctx context.Context, out io.Writer) error {
		defer os.Remove(path)
		fmt.Fprintf(out, "# initenv.conf\n%s\n$ env workdir=%s %s %s\n", conf, req.Workdir, strings.Join(s.cfg.InitenvCommand, " "), path)
		st := &ansiStripper{w: out}
		err := runner.StreamWith(ctx, s.cfg.InitenvCommand, st, path)
		st.Flush()
		if err == nil && req.Workdir != s.cfg.Workdir {
			fmt.Fprintf(out, "\nВнимание: рабочий каталог отличается от настроенного (%s). Укажите \"workdir\": %q в конфигурации cbsd-web и перезапустите службу.\n", s.cfg.Workdir, req.Workdir)
		}
		cbsdVersion.mu.Lock()
		cbsdVersion.at = time.Time{}
		cbsdVersion.mu.Unlock()
		return err
	}
	j, err := s.jobs.Submit(rc.sess.User, "Первичная настройка CBSD (initenv)", "initenv", run)
	if err != nil {
		os.Remove(path)
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "job.start", Target: "initenv", Detail: map[string]string{"job": j.ID, "workdir": req.Workdir}})
	writeJSON(w, http.StatusAccepted, map[string]any{"job": j.Snapshot()})
}

// ---------- users ----------

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"users": s.users.List()})
}

type userSetReq struct {
	Password string    `json:"password"`
	Role     auth.Role `json:"role"`
}

func (s *Server) handleUserSet(w http.ResponseWriter, r *http.Request) {
	rc := sessionFrom(r)
	name := r.PathValue("user")
	var req userSetReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.users.Set(name, req.Password, req.Role); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if name != rc.sess.User || req.Password != "" {
		s.sessions.DeleteUser(name)
	}
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "user.set", Target: name, Detail: map[string]string{"role": string(req.Role), "password_changed": strconv.FormatBool(req.Password != "")}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	rc := sessionFrom(r)
	name := r.PathValue("user")
	if name == rc.sess.User {
		writeErr(w, http.StatusConflict, "нельзя удалить самого себя")
		return
	}
	if err := s.users.Delete(name); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.sessions.DeleteUser(name)
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "user.delete", Target: name})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type pwReq struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

func (s *Server) handleOwnPassword(w http.ResponseWriter, r *http.Request) {
	rc := sessionFrom(r)
	var req pwReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u, ok := s.users.Verify(rc.sess.User, req.Current)
	if !ok {
		s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "password.change", Result: "fail"})
		writeErr(w, http.StatusForbidden, "текущий пароль неверен")
		return
	}
	if err := s.users.Set(u.Name, req.New, u.Role); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.sessions.DeleteUser(u.Name)
	s.audit.Log(audit.Entry{User: u.Name, IP: rc.ip, Event: "password.change", Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "relogin": true})
}

// handleAudit returns the newest audit entries (reads only the file tail).
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries := []json.RawMessage{}
	f, err := os.Open(s.cfg.AuditLog)
	if err == nil {
		defer f.Close()
		const tail = 256 << 10
		if st, err := f.Stat(); err == nil && st.Size() > tail {
			f.Seek(st.Size()-tail, io.SeekStart)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		first := true
		for sc.Scan() {
			line := sc.Bytes()
			if first {
				first = false
				if !json.Valid(line) {
					continue // partial line after Seek
				}
			}
			if json.Valid(line) {
				entries = append(entries, append(json.RawMessage(nil), line...))
			}
		}
	}
	for i, k := 0, len(entries)-1; i < k; i, k = i+1, k-1 {
		entries[i], entries[k] = entries[k], entries[i]
	}
	if len(entries) > 300 {
		entries = entries[:300]
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// ansiStripper removes terminal escapes from streamed cbsd output.
type ansiStripper struct {
	w   io.Writer
	buf []byte
}

func (a *ansiStripper) Write(p []byte) (int, error) {
	a.buf = append(a.buf, p...)
	// Hold back a trailing partial escape sequence.
	cut := len(a.buf)
	if i := lastIndexByte(a.buf, 0x1b); i >= 0 && len(a.buf)-i < 16 {
		cut = i
	}
	if cut > 0 {
		if _, err := io.WriteString(a.w, cbsd.StripANSI(string(a.buf[:cut]))); err != nil {
			return 0, err
		}
		a.buf = append(a.buf[:0], a.buf[cut:]...)
	}
	return len(p), nil
}

// Flush writes whatever is still buffered.
func (a *ansiStripper) Flush() {
	if len(a.buf) > 0 {
		io.WriteString(a.w, cbsd.StripANSI(string(a.buf)))
		a.buf = a.buf[:0]
	}
}

func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// ---------- jail configuration and limits ----------

func (s *Server) loadJail(w http.ResponseWriter, r *http.Request) *cbsd.Env {
	e := s.loadEnv(w, r)
	if e != nil && e.Emulator != "jail" {
		writeErr(w, http.StatusBadRequest, "доступно только для клеток")
		return nil
	}
	return e
}

func (s *Server) handleJailConfig(w http.ResponseWriter, r *http.Request) {
	e := s.loadJail(w, r)
	if e == nil {
		return
	}
	vals, err := s.db.JailConfig(r.Context(), e.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, dbErrorMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"groups": cbsd.ParamGroups, "params": cbsd.JailParams, "values": vals,
		"running": e.Status == 1, "busy_job": s.jobs.Busy()[e.Name],
	})
}

func (s *Server) handleJailConfigSet(w http.ResponseWriter, r *http.Request) {
	e := s.loadJail(w, r)
	if e == nil {
		return
	}
	var u cbsd.JailConfigUpdate
	if err := readJSON(r, &u); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	args, err := u.Args(e.Name, sessionFrom(r).sess.Role.Allows(auth.RoleAdmin), e.Status == 1)
	if err != nil {
		writeFieldErr(w, err)
		return
	}
	s.submit(w, r, "Настройки "+e.Name, e.Name, args, nil)
}

func (s *Server) handleJailLimits(w http.ResponseWriter, r *http.Request) {
	e := s.loadJail(w, r)
	if e == nil {
		return
	}
	res := map[string]any{"params": cbsd.RctlParams, "running": e.Status == 1}
	vals, err := s.db.JailLimits(r.Context(), e.Name)
	switch {
	case err == nil:
		res["values"] = vals
	case errors.Is(err, os.ErrNotExist):
		res["values"] = map[string]string{}
	default:
		res["values_error"] = "не удалось прочитать текущие лимиты: " + errText(err)
	}
	if e.Status == 1 {
		// Current usage straight from rctl(8), as key=value lines.
		out, err := s.runner.Output(r.Context(), 15*time.Second, "jrctl", "mode=show", "jname="+e.Name)
		if err == nil {
			usage := map[string]string{}
			for _, line := range strings.Split(out, "\n") {
				if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k != "" {
					usage[k] = v
				}
			}
			res["usage"] = usage
		}
	}
	writeJSON(w, http.StatusOK, res)
}

type limitsReq struct {
	Values map[string]string `json:"values"`
}

func (s *Server) handleJailLimitsSet(w http.ResponseWriter, r *http.Request) {
	e := s.loadJail(w, r)
	if e == nil {
		return
	}
	var req limitsReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	args, err := cbsd.RctlArgs(e.Name, req.Values)
	if err != nil {
		writeFieldErr(w, err)
		return
	}
	s.submit(w, r, "Лимиты "+e.Name, e.Name, args, nil)
}
