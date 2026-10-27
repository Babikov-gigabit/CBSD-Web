// Package server wires HTTP routes, security middleware and handlers.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cbsd-web/cbsd-web/internal/audit"
	"github.com/cbsd-web/cbsd-web/internal/auth"
	"github.com/cbsd-web/cbsd-web/internal/cbsd"
	"github.com/cbsd-web/cbsd-web/internal/config"
	"github.com/cbsd-web/cbsd-web/internal/jobs"
	"github.com/cbsd-web/cbsd-web/internal/snaphist"
	"github.com/cbsd-web/cbsd-web/internal/sysinfo"
)

type Server struct {
	cfg      *config.Config
	users    *auth.Store
	sessions *auth.Sessions
	limiter  *auth.Limiter
	audit    *audit.Logger
	runner   *cbsd.Runner
	db       *cbsd.DB
	profiles *cbsd.Profiles
	jobs     *jobs.Manager
	sys      *sysinfo.Collector
	static   *staticFS
	terms    terminals
	hist     *snaphist.Store
	isos     isoGate
	version  string
}

func New(cfg *config.Config, users *auth.Store, al *audit.Logger, version string) (*Server, error) {
	st, err := newStaticFS()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		users:    users,
		sessions: auth.NewSessions(time.Duration(cfg.SessionIdleMinutes)*time.Minute, time.Duration(cfg.SessionMaxHours)*time.Hour),
		limiter:  auth.NewLimiter(5, 15*time.Minute, 15*time.Minute),
		audit:    al,
		runner:   &cbsd.Runner{Cmd: cfg.CBSDCommand, Workdir: cfg.Workdir, Timeout: time.Duration(cfg.CommandTimeoutMinutes) * time.Minute},
		db:       cbsd.NewDB(cfg.Workdir),
		profiles: cbsd.NewProfiles(cfg.Workdir, cfg.DistDir),
		jobs:     jobs.NewManager(cfg.MaxConcurrentJobs),
		sys:      sysinfo.NewCollector(cfg.Workdir),
		static:   st,
		version:  version,
	}
	if s.hist, err = snaphist.Open(filepath.Join(cfg.DataDir, "snapshot-history.json")); err != nil {
		log.Printf("snapshot history: %v (starting empty)", err)
		s.hist = snaphist.NewAt(filepath.Join(cfg.DataDir, "snapshot-history.json"))
	}
	s.jobs.OnEnd = func(j jobs.Snapshot) {
		s.audit.Log(audit.Entry{User: j.User, Event: "job.end", Target: j.Target, Result: string(j.State),
			Detail: map[string]string{"job": j.ID, "title": j.Title, "error": j.Error}})
	}
	return s, nil
}

func (s *Server) Close() {
	s.jobs.Shutdown()
	s.db.Close()
}

// Handler returns the root handler with all middleware applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public endpoints.
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /api/session", s.handleSession)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	// Authenticated endpoints, by minimum role.
	v, o, a := auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin
	s.route(mux, "POST /api/logout", v, s.handleLogout)
	s.route(mux, "GET /api/overview", v, s.handleOverview)
	s.route(mux, "GET /api/envs", v, s.handleEnvs)
	s.route(mux, "GET /api/envs/{name}", v, s.handleEnv)
	s.route(mux, "POST /api/envs/{name}/action", o, s.handleEnvAction)
	s.route(mux, "PATCH /api/envs/{name}", o, s.handleEnvUpdate)
	s.route(mux, "GET /api/envs/{name}/config", v, s.handleJailConfig)
	s.route(mux, "PATCH /api/envs/{name}/config", o, s.handleJailConfigSet)
	s.route(mux, "GET /api/envs/{name}/limits", v, s.handleJailLimits)
	s.route(mux, "PUT /api/envs/{name}/limits", o, s.handleJailLimitsSet)
	s.route(mux, "GET /api/envs/{name}/terminal", v, s.handleTerminal)
	s.route(mux, "GET /api/envs/{name}/stats", v, s.handleEnvStats)
	s.route(mux, "GET /api/envs/{name}/vnc", v, s.handleVNCInfo)
	s.route(mux, "GET /api/envs/{name}/vnc/ws", v, s.handleVNCProxy)
	s.route(mux, "GET /api/envs/{name}/snapshots", v, s.handleSnapshotList)
	s.route(mux, "POST /api/envs/{name}/snapshots", o, s.handleSnapshot)
	s.route(mux, "GET /api/envs/{name}/snapshots/graph", v, s.handleSnapshotGraph)
	s.route(mux, "DELETE /api/envs/{name}/snapshots/history", o, s.handleSnapshotHistoryDelete)
	s.route(mux, "POST /api/envs/{name}/clone", o, s.handleClone)
	s.route(mux, "POST /api/jails", o, s.handleJailCreate)
	s.route(mux, "POST /api/vms/{emulator}", o, s.handleVMCreate)
	s.route(mux, "GET /api/profiles", v, s.handleProfiles)
	s.route(mux, "GET /api/images", v, s.handleImages)
	s.route(mux, "GET /api/isos", v, s.handleISOs)
	s.route(mux, "POST "+isoUploadPath, a, s.handleISOUpload)
	s.route(mux, "POST /api/isos/fetch", a, s.handleISOFetch)
	s.route(mux, "DELETE /api/isos/{file}", a, s.handleISODelete)
	s.route(mux, "GET /api/bases", v, s.handleBases)
	s.route(mux, "POST /api/bases", a, s.handleBaseFetch)
	s.route(mux, "GET /api/nodes", v, s.handleNodes)
	s.route(mux, "GET /api/jobs", v, s.handleJobs)
	s.route(mux, "GET /api/jobs/{id}", v, s.handleJob)
	s.route(mux, "GET /api/jobs/{id}/stream", v, s.handleJobStream)
	s.route(mux, "POST /api/jobs/{id}/cancel", o, s.handleJobCancel)
	s.route(mux, "GET /api/setup", v, s.handleSetupStatus)
	s.route(mux, "POST /api/setup/initenv", a, s.handleInitenv)
	s.route(mux, "GET /api/users", a, s.handleUsers)
	s.route(mux, "PUT /api/users/{user}", a, s.handleUserSet)
	s.route(mux, "DELETE /api/users/{user}", a, s.handleUserDelete)
	s.route(mux, "POST /api/me/password", v, s.handleOwnPassword)
	s.route(mux, "GET /api/audit", a, s.handleAudit)

	mux.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "not found")
	}))
	mux.Handle("/", s.static)

	return s.recoverer(s.securityHeaders(s.clientFilter(mux)))
}

type ctxKey struct{}

type reqCtx struct {
	sess  auth.Session
	token string
	ip    string
}

func sessionFrom(r *http.Request) reqCtx {
	v, _ := r.Context().Value(ctxKey{}).(reqCtx)
	return v
}

// route registers a handler guarded by authentication, CSRF and role checks.
func (s *Server) route(mux *http.ServeMux, pattern string, need auth.Role, h http.HandlerFunc) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		token := s.cookieToken(r)
		sess, ok := s.sessions.Get(token)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "требуется вход")
			return
		}
		// Re-check the role on every request so demotions apply immediately.
		u, exists := s.users.Get(sess.User)
		if !exists {
			s.sessions.DeleteUser(sess.User)
			writeErr(w, http.StatusUnauthorized, "требуется вход")
			return
		}
		sess.Role = u.Role
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.sameOrigin(r) || !auth.CSRFValid(sess, r.Header.Get("X-CSRF-Token")) {
				s.audit.Log(audit.Entry{User: sess.User, IP: clientIP(r, s.cfg), Event: "csrf.reject", Target: r.URL.Path})
				writeErr(w, http.StatusForbidden, "CSRF-проверка не пройдена")
				return
			}
		}
		if !sess.Role.Allows(need) {
			writeErr(w, http.StatusForbidden, "недостаточно прав")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, reqCtx{sess: sess, token: token, ip: clientIP(r, s.cfg)})
		h(w, r.WithContext(ctx))
	})
}

func (s *Server) cookieName() string {
	if s.cfg.SecureCookies() {
		return "__Host-cbsdweb"
	}
	return "cbsdweb"
}

func (s *Server) cookieToken(r *http.Request) string {
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return ""
	}
	return c.Value
}

// sameOrigin rejects cross-site requests that carry an Origin or Referer from elsewhere.
func (s *Server) sameOrigin(r *http.Request) bool {
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" && sf != "none" {
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true // non-browser client; CSRF token still required
	}
	host := r.Host
	if s.cfg.BehindProxy {
		if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
			host = fh
		}
	}
	return o == "https://"+host || o == "http://"+host
}

func clientIP(r *http.Request, cfg *config.Config) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if cfg.BehindProxy {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				if p := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(p) != nil {
					return p
				}
			}
		}
	}
	return host
}

func (s *Server) clientFilter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := net.ParseIP(clientIP(r, s.cfg))
		if ip == nil || !s.cfg.ClientAllowed(ip) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// style-src allows inline styles because xterm.js injects <style> for the
		// terminal; scripts stay strictly 'self'.
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if s.cfg.SecureCookies() {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
			// ISO uploads stream large bodies; that handler sets its own limit.
			if r.URL.Path != isoUploadPath {
				r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.Printf("panic %s %s: %v", r.Method, r.URL.Path, v)
				writeErr(w, http.StatusInternalServerError, "внутренняя ошибка")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeFieldErr(w http.ResponseWriter, err error) {
	var fe *cbsd.FieldError
	if errors.As(err, &fe) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": fe.Msg, "field": fe.Field})
		return
	}
	writeErr(w, http.StatusBadRequest, err.Error())
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("некорректный JSON: " + err.Error())
	}
	if dec.More() {
		return errors.New("лишние данные после JSON")
	}
	return nil
}

// ListenAndServe runs the HTTP(S) server until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second, // SSE handlers lift this per request
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	if s.cfg.TLSEnabled() {
		tc, err := s.tlsConfig()
		if err != nil {
			return err
		}
		srv.TLSConfig = tc
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() {
		if srv.TLSConfig != nil {
			errc <- srv.ServeTLS(ln, "", "")
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	scheme := "http"
	if srv.TLSConfig != nil {
		scheme = "https"
	}
	log.Printf("cbsd-web %s listening on %s://%s (workdir %s)", s.version, scheme, s.cfg.Listen, s.cfg.Workdir)
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		return err
	}
}

func ensureDir(p string) error { return os.MkdirAll(filepath.Clean(p), 0o750) }
