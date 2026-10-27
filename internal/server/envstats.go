package server

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/cbsd-web/cbsd-web/internal/audit"
	"github.com/cbsd-web/cbsd-web/internal/auth"
	"github.com/cbsd-web/cbsd-web/internal/hoststat"
)

// handleEnvStats reports network interfaces with traffic counters, process
// usage and disk space of one environment. The browser derives rates from
// two consecutive samples.
func (s *Server) handleEnvStats(w http.ResponseWriter, r *http.Request) {
	e := s.loadEnv(w, r)
	if e == nil {
		return
	}
	ctx := r.Context()
	res := map[string]any{"at": time.Now().UnixMilli(), "running": e.Status == 1}
	var ips []string
	for _, a := range strings.Split(e.IP4, ",") {
		if a = strings.TrimSpace(a); a != "" && a != "0" {
			ips = append(ips, a)
		}
	}
	res["ips"] = ips
	res["interface"] = e.Interface
	res["vnet"] = e.VNet
	if nics, err := hoststat.NICs(ctx, e.Name); err == nil {
		if nics == nil {
			nics = []hoststat.NIC{}
		}
		res["nics"] = nics
	} else {
		res["nics_error"] = "счётчики интерфейсов недоступны: " + errText(err)
	}
	if e.Status == 1 && e.JID > 0 {
		var p hoststat.Procs
		var err error
		if e.Emulator == "jail" {
			p, err = hoststat.JailProcs(ctx, e.JID)
		} else {
			p, err = hoststat.PidProcs(ctx, e.JID) // CBSD keeps the VM's pid in jid
		}
		if err == nil || p.Count > 0 {
			res["procs"] = p
		}
	}
	data := filepath.Join(s.cfg.Workdir, "jails-data", e.Name+"-data")
	if ds, err := hoststat.DatasetOf(ctx, data); err == nil && ds != nil {
		res["disk"] = ds
	}
	writeJSON(w, http.StatusOK, res)
}

// vncTarget is where the VM's VNC server listens; wildcard binds are reached via loopback.
func vncTarget(bind string, port int64) string {
	host := bind
	if ip := net.ParseIP(host); host == "" || ip == nil || ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.FormatInt(port, 10))
}

// handleVNCInfo returns connection details; the password only to users who may open the console.
func (s *Server) handleVNCInfo(w http.ResponseWriter, r *http.Request) {
	e := s.loadEnv(w, r)
	if e == nil {
		return
	}
	if e.Emulator != "bhyve" && e.Emulator != "xen" {
		writeErr(w, http.StatusBadRequest, "VNC есть только у виртуальных машин")
		return
	}
	rc := sessionFrom(r)
	res := map[string]any{"port": e.VNCPort, "bind": e.VNCBind, "resolution": e.VNCRes, "has_password": e.HasVNCPass,
		"running": e.Status == 1, "console": s.terminalAllowed(rc.sess.Role), "auto": e.VNCAuto, "off": e.VNCOff}
	if s.terminalAllowed(rc.sess.Role) {
		res["password"] = e.VNCPassword
		s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "vnc.info", Target: e.Name})
	}
	writeJSON(w, http.StatusOK, res)
}

// handleVNCProxy bridges noVNC (WebSocket) to the VM's VNC TCP port.
func (s *Server) handleVNCProxy(w http.ResponseWriter, r *http.Request) {
	rc := sessionFrom(r)
	if !s.terminalAllowed(rc.sess.Role) {
		writeErr(w, http.StatusForbidden, "консоль недоступна для вашей роли")
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
	if (e.Emulator != "bhyve" && e.Emulator != "xen") || e.VNCPort <= 0 || e.VNCPort > 65535 {
		writeErr(w, http.StatusBadRequest, "у окружения нет VNC")
		return
	}
	if e.Status != 1 {
		writeErr(w, http.StatusConflict, "виртуальная машина не запущена")
		return
	}
	if !s.terms.acquire(rc.sess.User) {
		writeErr(w, http.StatusTooManyRequests, "открыто слишком много консолей")
		return
	}
	defer s.terms.release(rc.sess.User)

	d := net.Dialer{Timeout: 5 * time.Second}
	tcp, err := d.DialContext(r.Context(), "tcp", vncTarget(e.VNCBind, e.VNCPort))
	if err != nil {
		writeErr(w, http.StatusBadGateway, "VNC-сервер ВМ не отвечает")
		return
	}
	defer tcp.Close()

	ctl := http.NewResponseController(w)
	_ = ctl.SetReadDeadline(time.Time{})
	_ = ctl.SetWriteDeadline(time.Time{})
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"binary"}})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 20)
	started := time.Now()
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "vnc.open", Target: e.Name})

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	nc := websocket.NetConn(ctx, conn, websocket.MessageBinary)
	idle := time.Duration(s.cfg.TerminalIdleMinutes) * time.Minute
	go func() {
		defer cancel()
		buf := make([]byte, 64<<10)
		for {
			_ = tcp.SetReadDeadline(time.Now().Add(idle))
			n, err := tcp.Read(buf)
			if n > 0 {
				if _, werr := nc.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer cancel()
		buf := make([]byte, 64<<10)
		for {
			n, err := nc.Read(buf)
			if n > 0 {
				if _, werr := tcp.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, ok := s.sessions.Get(rc.token); !ok {
					cancel()
					return
				}
			}
		}
	}()
	<-ctx.Done()
	tcp.Close()
	conn.Close(websocket.StatusNormalClosure, "")
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "vnc.close", Target: e.Name,
		Detail: map[string]string{"duration": time.Since(started).Round(time.Second).String()}})
}
