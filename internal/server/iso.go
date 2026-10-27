package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cbsd-web/cbsd-web/internal/audit"
	"github.com/cbsd-web/cbsd-web/internal/cbsd"
)

// ISO images uploaded from the browser or downloaded by URL are stored in
// <workdir>/src/iso/upload, inside CBSD's own ISO directory, and registered
// with 'cbsd media mode=register'. Files are written by the unprivileged
// daemon itself (never through sudo), so the only privileged step is the
// registration, whose arguments pass the same allow-lists as everything else.

const (
	isoUploadPath  = "/api/isos/upload"
	isoMaxParallel = 2                 // uploads and downloads at once
	isoIdleTimeout = 2 * time.Minute   // abort a transfer that stalls this long
	isoSpareSpace  = 512 << 20         // keep this much free after a transfer
	isoBufSize     = 1 << 20           // copy buffer
	isoProgressGap = 3 * time.Second   // job log progress interval
	isoFetchHeader = 60 * time.Second  // wait for response headers
	isoMaxURL      = 2048              // characters
	isoRegisterMax = 2 * time.Minute   // 'cbsd media' runtime
	isoDialTimeout = 30 * time.Second  // TCP connect
	isoTLSTimeout  = 30 * time.Second  // TLS handshake
	isoMaxRedirect = 5                 // HTTP redirects
	isoSigOffset   = 0x8001            // volume descriptor identifier
	isoSigLen      = 5                 // "CD001" (ISO 9660) or "BEA01" (UDF)
	isoMinSize     = isoSigOffset + 16 // smaller files cannot be ISO images
)

var reSHA256 = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// isoGate limits parallel transfers and stops two transfers of one name.
type isoGate struct {
	mu   sync.Mutex
	busy map[string]bool
}

func (g *isoGate) acquire(name string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.busy == nil {
		g.busy = map[string]bool{}
	}
	if g.busy[name] {
		return errors.New("этот образ уже загружается")
	}
	if len(g.busy) >= isoMaxParallel {
		return errors.New("уже идут две загрузки ISO, дождитесь их окончания")
	}
	g.busy[name] = true
	return nil
}

func (g *isoGate) release(name string) {
	g.mu.Lock()
	delete(g.busy, name)
	g.mu.Unlock()
}

func (s *Server) isoRoot() string { return filepath.Join(s.cfg.Workdir, "src", "iso") }
func (s *Server) isoDir() string  { return filepath.Join(s.isoRoot(), "upload") }
func (s *Server) isoMax() int64   { return int64(s.cfg.ISOMaxSizeGB) << 30 }

// isoInfo is one row of the ISO list: a registered ISO medium, a file in the
// upload directory, or both.
type isoInfo struct {
	File       string   `json:"file,omitempty"` // name in the upload directory
	Media      string   `json:"media,omitempty"`
	Path       string   `json:"path"`
	Size       int64    `json:"size"`
	Modified   string   `json:"modified,omitempty"`
	AttachedTo []string `json:"attached_to"`
	Uploaded   bool     `json:"uploaded"`          // stored by cbsd-web, may be deleted here
	Registered bool     `json:"registered"`        // known to 'cbsd media'
	Usable     bool     `json:"usable"`            // can be chosen when creating a VM
	Missing    bool     `json:"missing,omitempty"` // registered, but the file is gone
}

func (s *Server) listISOs(ctx context.Context) ([]isoInfo, error) {
	byPath := map[string]*isoInfo{}
	var order []string
	if s.db.Exists("local") || s.db.Exists("storage_media") {
		rows, err := s.db.Media(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if r.Str("type") != "iso" {
				continue
			}
			p := filepath.Clean(r.Str("path"))
			it, ok := byPath[p]
			if !ok {
				it = &isoInfo{Path: p, Media: r.Str("name"), Size: r.Num("size"), AttachedTo: []string{}, Registered: true}
				byPath[p] = it
				order = append(order, p)
			}
			if j := r.Str("jname"); j != "" && j != "-" && !contains(it.AttachedTo, j) {
				it.AttachedTo = append(it.AttachedTo, j)
			}
		}
	}
	if ents, err := os.ReadDir(s.isoDir()); err == nil {
		for _, e := range ents {
			if !e.Type().IsRegular() || !cbsd.ValidISOFile(e.Name()) {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			p := filepath.Join(s.isoDir(), e.Name())
			it, ok := byPath[p]
			if !ok {
				it = &isoInfo{Path: p, Media: cbsd.ISOMediaName(e.Name()), AttachedTo: []string{}}
				byPath[p] = it
				order = append(order, p)
			}
			it.File, it.Uploaded = e.Name(), true
			it.Size = fi.Size()
			it.Modified = fi.ModTime().UTC().Format(time.RFC3339)
		}
	}
	out := make([]isoInfo, 0, len(order))
	for _, p := range order {
		it := byPath[p]
		_, rel := s.isoRel(it.Path)
		// bstart silently falls back to downloading the profile's ISO when the
		// media file is gone, so such entries must not be offered.
		if _, err := os.Stat(it.Path); errors.Is(err, fs.ErrNotExist) {
			it.Missing = true
		}
		it.Usable = rel != "" && cbsd.ValidMediaName(it.Media) && !it.Missing
		out = append(out, *it)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Uploaded != out[j].Uploaded {
			return out[i].Uploaded
		}
		return strings.ToLower(out[i].Media) < strings.ToLower(out[j].Media)
	})
	return out, nil
}

// isoRel returns p relative to CBSD's ISO directory, or "" when it is outside
// it or contains characters that must not reach CBSD.
func (s *Server) isoRel(p string) (string, string) {
	rel, err := filepath.Rel(s.isoRoot(), filepath.Clean(p))
	if err != nil || !cbsd.ValidMediaRel(filepath.ToSlash(rel)) {
		return p, ""
	}
	return p, filepath.ToSlash(rel)
}

// isoForVM resolves a media name chosen in the VM form to its path under
// CBSD's ISO directory.
func (s *Server) isoForVM(ctx context.Context, media string) (string, error) {
	if !cbsd.ValidMediaName(media) {
		return "", errors.New("некорректное имя образа")
	}
	list, err := s.listISOs(ctx)
	if err != nil {
		return "", err
	}
	for _, it := range list {
		if it.Media == media && it.Usable {
			_, rel := s.isoRel(it.Path)
			return rel, nil
		}
	}
	return "", errors.New("образ не найден")
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) handleISOs(w http.ResponseWriter, r *http.Request) {
	list, err := s.listISOs(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{"isos": list, "dir": s.isoDir(), "max_bytes": s.isoMax(), "writable": false}
	if err := s.isoDirReady(); err == nil {
		resp["writable"] = true
	} else {
		resp["dir_error"] = err.Error()
	}
	if free, err := diskFree(existingParent(s.isoDir())); err == nil {
		resp["free_bytes"] = free
	}
	writeJSON(w, http.StatusOK, resp)
}

// isoDirReady creates the upload directory if possible and checks that the
// daemon may write to it.
func (s *Server) isoDirReady() error {
	if !s.db.Exists("local") {
		return errors.New("CBSD не инициализирован: выполните первичную настройку")
	}
	dir := s.isoDir()
	if err := os.MkdirAll(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("нет каталога %s: запустите scripts/install.sh ещё раз, он создаст его", dir)
	}
	if err := syscall.Access(dir, 2 /* W_OK */); err != nil {
		return fmt.Errorf("нет прав на запись в %s: запустите scripts/install.sh ещё раз или выполните chown cbsdweb %s", dir, dir)
	}
	return nil
}

func existingParent(p string) string {
	for {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		p = parent
	}
}

func fmtSize(n int64) string {
	units := []string{"Б", "КБ", "МБ", "ГБ", "ТБ"}
	f, i := float64(n), 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[0])
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

// isoStored is the result of a finished transfer.
type isoStored struct {
	File   string `json:"file"`
	Media  string `json:"media"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// storeISO streams src into the upload directory as file. size is the
// expected length (-1 when unknown); wantSHA is an optional hex checksum.
// The file only appears under its final name after every check passed, and
// is never overwritten.
func (s *Server) storeISO(ctx context.Context, file string, src io.Reader, size int64, wantSHA string, progress func(int64)) (*isoStored, error) {
	if err := s.isoDirReady(); err != nil {
		return nil, err
	}
	dir := s.isoDir()
	final := filepath.Join(dir, file)
	if _, err := os.Lstat(final); err == nil {
		return nil, errors.New("образ с таким именем уже есть")
	}
	max := s.isoMax()
	if size > max {
		return nil, fmt.Errorf("образ больше допустимого (%s)", fmtSize(max))
	}
	if free, err := diskFree(dir); err == nil && size > 0 && uint64(size)+isoSpareSpace > free {
		return nil, fmt.Errorf("мало места: свободно %s, нужно %s", fmtSize(int64(free)), fmtSize(size))
	}
	tmp, err := os.CreateTemp(dir, ".upload-*.part")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()
	h := sha256.New()
	dst := io.MultiWriter(tmp, h)
	if progress != nil {
		dst = io.MultiWriter(dst, progressWriter(progress))
	}
	n, err := io.CopyBuffer(dst, io.LimitReader(src, max+1), make([]byte, isoBufSize))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, fmt.Errorf("образ больше допустимого (%s)", fmtSize(max))
		}
		if ctx.Err() != nil {
			return nil, errors.New("загрузка отменена")
		}
		return nil, fmt.Errorf("загрузка прервана: %w", err)
	}
	if n > max {
		return nil, fmt.Errorf("образ больше допустимого (%s)", fmtSize(max))
	}
	if size >= 0 && n != size {
		return nil, fmt.Errorf("загрузка прервана: получено %d из %d байт", n, size)
	}
	if err := checkISOSignature(tmp, n); err != nil {
		return nil, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if wantSHA != "" && !strings.EqualFold(sum, wantSHA) {
		return nil, fmt.Errorf("контрольная сумма не совпадает: получено %s", sum)
	}
	if err := tmp.Sync(); err != nil {
		return nil, err
	}
	if err := tmp.Chmod(0o644); err != nil {
		return nil, err
	}
	// Link fails if the name appeared meanwhile, so nothing is ever replaced.
	if err := os.Link(tmpName, final); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, errors.New("образ с таким именем уже есть")
		}
		return nil, err
	}
	return &isoStored{File: file, Media: cbsd.ISOMediaName(file), Path: final, Size: n, SHA256: sum}, nil
}

func checkISOSignature(f *os.File, size int64) error {
	bad := errors.New("файл не похож на ISO-образ (нет сигнатуры ISO 9660/UDF)")
	if size < isoMinSize {
		return bad
	}
	sig := make([]byte, isoSigLen)
	if _, err := f.ReadAt(sig, isoSigOffset); err != nil {
		return bad
	}
	if string(sig) != "CD001" && string(sig) != "BEA01" {
		return bad
	}
	return nil
}

type progressWriter func(int64)

func (p progressWriter) Write(b []byte) (int, error) { p(int64(len(b))); return len(b), nil }

// registerISO adds a stored ISO to CBSD's media list. On failure the file is
// removed again, so the upload directory only holds registered images.
func (s *Server) registerISO(ctx context.Context, st *isoStored, out io.Writer) error {
	args := []string{"media", "mode=register", "name=" + st.Media, "path=" + st.Path, "type=iso"}
	if out != nil {
		fmt.Fprintf(out, "$ cbsd %s\n", strings.Join(args, " "))
	}
	res, err := s.runner.Output(ctx, isoRegisterMax, args...)
	if out != nil && res != "" {
		fmt.Fprintln(out, res)
	}
	if err != nil {
		os.Remove(st.Path)
		if res == "" {
			res = err.Error()
		}
		return fmt.Errorf("cbsd media register: %s", res)
	}
	return nil
}

// deadlineReader extends the connection's read deadline while data keeps
// arriving, so a large upload is not cut by the server's ReadTimeout but a
// stalled one still ends.
type deadlineReader struct {
	r    io.Reader
	rc   *http.ResponseController
	last time.Time
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	if now := time.Now(); now.Sub(d.last) > time.Second {
		d.last = now
		_ = d.rc.SetReadDeadline(now.Add(isoIdleTimeout))
	}
	return d.r.Read(p)
}

// handleISOUpload receives a raw ISO body: POST /api/isos/upload?name=x.iso.
// The generic 64 KiB body limit is lifted for this one route only (see
// securityHeaders); authentication, CSRF and the admin role were checked
// before any of the body is read.
func (s *Server) handleISOUpload(w http.ResponseWriter, r *http.Request) {
	rc := sessionFrom(r)
	file := r.URL.Query().Get("name")
	if !cbsd.ValidISOFile(file) {
		writeFieldErr(w, &cbsd.FieldError{Field: "name", Msg: "имя файла: латиница, цифры, . _ -, до 63 символов, окончание .iso"})
		return
	}
	if r.ContentLength <= 0 {
		writeErr(w, http.StatusLengthRequired, "не указан размер файла")
		return
	}
	if r.ContentLength > s.isoMax() {
		writeErr(w, http.StatusRequestEntityTooLarge, "образ больше допустимого ("+fmtSize(s.isoMax())+")")
		return
	}
	wantSHA := strings.TrimSpace(r.Header.Get("X-Content-SHA256"))
	if wantSHA != "" && !reSHA256.MatchString(wantSHA) {
		writeErr(w, http.StatusBadRequest, "SHA-256: ожидается 64 шестнадцатеричных символа")
		return
	}
	if err := s.isos.acquire(file); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	defer s.isos.release(file)

	ctl := http.NewResponseController(w)
	_ = ctl.SetWriteDeadline(time.Time{})
	body := &deadlineReader{r: http.MaxBytesReader(w, r.Body, s.isoMax()), rc: ctl}
	st, err := s.storeISO(r.Context(), file, body, r.ContentLength, wantSHA, nil)
	if err == nil {
		err = s.registerISO(context.WithoutCancel(r.Context()), st, nil)
	}
	_ = ctl.SetReadDeadline(time.Time{})
	if err != nil {
		s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "iso.upload", Target: file, Result: "error", Detail: map[string]string{"error": err.Error()}})
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "iso.upload", Target: file, Result: "ok",
		Detail: map[string]string{"size": fmt.Sprint(st.Size), "sha256": st.SHA256}})
	writeJSON(w, http.StatusOK, st)
}

type isoFetchReq struct {
	URL    string `json:"url"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

func (s *Server) handleISOFetch(w http.ResponseWriter, r *http.Request) {
	rc := sessionFrom(r)
	var req isoFetchReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := url.Parse(strings.TrimSpace(req.URL))
	if err != nil || len(req.URL) > isoMaxURL || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
		writeFieldErr(w, &cbsd.FieldError{Field: "url", Msg: "ожидается адрес http:// или https:// без логина и пароля"})
		return
	}
	file := strings.TrimSpace(req.Name)
	if file == "" {
		file = path.Base(u.Path)
	}
	if !cbsd.ValidISOFile(file) {
		writeFieldErr(w, &cbsd.FieldError{Field: "name", Msg: "имя файла: латиница, цифры, . _ -, до 63 символов, окончание .iso"})
		return
	}
	sum := strings.TrimSpace(req.SHA256)
	if sum != "" && !reSHA256.MatchString(sum) {
		writeFieldErr(w, &cbsd.FieldError{Field: "sha256", Msg: "64 шестнадцатеричных символа"})
		return
	}
	if err := s.isoDirReady(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if _, err := os.Lstat(filepath.Join(s.isoDir(), file)); err == nil {
		writeFieldErr(w, &cbsd.FieldError{Field: "name", Msg: "образ с таким именем уже есть"})
		return
	}
	if err := s.isos.acquire(file); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	src := u.String()
	run := func(ctx context.Context, out io.Writer) error {
		defer s.isos.release(file)
		return s.fetchISO(ctx, src, file, sum, out)
	}
	j, err := s.jobs.Submit(rc.sess.User, "Загрузка ISO "+file, "iso:"+file, run)
	if err != nil {
		s.isos.release(file)
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "iso.fetch", Target: file, Result: "queued",
		Detail: map[string]string{"job": j.ID, "url": src}})
	writeJSON(w, http.StatusAccepted, map[string]any{"job": j.Snapshot()})
}

func (s *Server) isoClient() *http.Client {
	allowPrivate := s.cfg.ISOFetchAllowPrivate
	dialer := &net.Dialer{
		Timeout: isoDialTimeout,
		// Checked on the address actually dialled, so DNS tricks and
		// redirects cannot reach internal hosts.
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || (!allowPrivate && !publicIP(ip)) {
				return fmt.Errorf("адрес %s во внутренней сети: скачивание запрещено (iso_fetch_allow_private)", host)
			}
			return nil
		},
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   isoTLSTimeout,
		ResponseHeaderTimeout: isoFetchHeader,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= isoMaxRedirect {
			return errors.New("слишком много перенаправлений")
		}
		if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
			return errors.New("перенаправление на неподдерживаемый адрес")
		}
		return nil
	}}
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func publicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || cgnat.Contains(ip))
}

// idleReader cancels the transfer when no data arrives for isoIdleTimeout.
type idleReader struct {
	r io.Reader
	t *time.Timer
}

func (i *idleReader) Read(p []byte) (int, error) {
	n, err := i.r.Read(p)
	if n > 0 {
		i.t.Reset(isoIdleTimeout)
	}
	return n, err
}

func (s *Server) fetchISO(ctx context.Context, src, file, wantSHA string, out io.Writer) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	fmt.Fprintf(out, "Скачивание %s\n", src)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "cbsd-web/"+s.version)
	resp, err := s.isoClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("сервер ответил %s", resp.Status)
	}
	size := resp.ContentLength
	if size > 0 {
		fmt.Fprintf(out, "Размер: %s\n", fmtSize(size))
	} else {
		fmt.Fprintln(out, "Размер не сообщён сервером")
	}
	stall := time.AfterFunc(isoIdleTimeout, func() { cancel(errors.New("нет данных от сервера " + isoIdleTimeout.String())) })
	defer stall.Stop()

	var got int64
	start, last := time.Now(), time.Now()
	progress := func(n int64) {
		got += n
		if time.Since(last) < isoProgressGap {
			return
		}
		last = time.Now()
		speed := float64(got) / time.Since(start).Seconds()
		if size > 0 {
			fmt.Fprintf(out, "  %s из %s (%d%%), %s/с\n", fmtSize(got), fmtSize(size), got*100/size, fmtSize(int64(speed)))
		} else {
			fmt.Fprintf(out, "  %s, %s/с\n", fmtSize(got), fmtSize(int64(speed)))
		}
	}
	st, err := s.storeISO(ctx, file, &idleReader{r: resp.Body, t: stall}, size, wantSHA, progress)
	if err != nil {
		if c := context.Cause(ctx); c != nil && !errors.Is(c, context.Canceled) {
			return c
		}
		return err
	}
	fmt.Fprintf(out, "Получено %s за %s\nSHA-256: %s\n", fmtSize(st.Size), time.Since(start).Round(time.Second), st.SHA256)
	if wantSHA != "" {
		fmt.Fprintln(out, "Контрольная сумма совпадает")
	}
	return s.registerISO(context.WithoutCancel(ctx), st, out)
}

// handleISODelete removes an uploaded ISO that no VM uses.
func (s *Server) handleISODelete(w http.ResponseWriter, r *http.Request) {
	rc := sessionFrom(r)
	file := r.PathValue("file")
	if !cbsd.ValidISOFile(file) {
		writeErr(w, http.StatusBadRequest, "некорректное имя файла")
		return
	}
	p := filepath.Join(s.isoDir(), file)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		writeErr(w, http.StatusNotFound, "образ не найден")
		return
	}
	if err := s.isos.acquire(file); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	defer s.isos.release(file)
	list, err := s.listISOs(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, it := range list {
		if it.Path != p {
			continue
		}
		if len(it.AttachedTo) > 0 {
			writeErr(w, http.StatusConflict, "образ подключён к ВМ "+strings.Join(it.AttachedTo, ", ")+": сначала отключите его")
			return
		}
		if it.Registered && cbsd.ValidMediaName(it.Media) {
			res, err := s.runner.Output(r.Context(), isoRegisterMax, "media", "mode=unregister", "name="+it.Media, "path="+p, "type=iso")
			if err != nil {
				if res == "" {
					res = err.Error()
				}
				writeErr(w, http.StatusInternalServerError, "cbsd media unregister: "+res)
				return
			}
		}
	}
	if err := os.Remove(p); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "iso.delete", Target: file, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
