package server

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cbsd-web/cbsd-web/internal/cbsd"
)

// Logs of one environment, for finding out why it did not start:
// CBSD's own logs in <workdir>/jails-system/NAME/*.log (bstart.log holds the
// bhyve command line and its output), matching lines of the system log, and
// the output of recent web jobs for this environment.

const (
	logTailBytes   = 128 << 10 // per file
	logSysScan     = 2 << 20   // how much of the system log to scan
	logSysLines    = 150       // matching system log lines to keep
	logJobsShown   = 5         // recent jobs of this environment
	logMaxFiles    = 10        // *.log files per environment
	systemLogPath  = "/var/log/messages"
	logPermissionH = "нет прав на чтение у пользователя cbsdweb (он должен входить в группу cbsd, а файл быть доступен группе)"
)

// Passwords appear in bhyve and bcreate command lines (VNC password).
var rePassword = regexp.MustCompile(`(password=)[^,\s"']+`)

func redactLog(s string) string { return rePassword.ReplaceAllString(s, "${1}***") }

type logSource struct {
	Kind     string `json:"kind"` // file, system, job
	Title    string `json:"title"`
	Path     string `json:"path,omitempty"`
	Modified string `json:"modified,omitempty"`
	Size     int64  `json:"size,omitempty"`
	State    string `json:"state,omitempty"` // job state
	Text     string `json:"text"`
	Cut      bool   `json:"cut,omitempty"` // only the end is shown
	Error    string `json:"error,omitempty"`
}

// tailFile returns up to max bytes from the end of a regular file, starting
// at a line boundary.
func tailFile(p string, max int64) (text string, size int64, mod time.Time, cut bool, err error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return "", 0, time.Time{}, false, err
	}
	if !fi.Mode().IsRegular() {
		return "", 0, time.Time{}, false, errors.New("не обычный файл")
	}
	f, err := os.Open(p)
	if err != nil {
		return "", 0, time.Time{}, false, err
	}
	defer f.Close()
	off := int64(0)
	if fi.Size() > max {
		off, cut = fi.Size()-max, true
	}
	b, err := io.ReadAll(io.NewSectionReader(f, off, fi.Size()-off))
	if err != nil {
		return "", 0, time.Time{}, false, err
	}
	if cut {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return strings.ToValidUTF8(cbsd.StripANSI(string(b)), "?"), fi.Size(), fi.ModTime(), cut, nil
}

func logErr(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return logPermissionH
	}
	return err.Error()
}

func (s *Server) handleEnvLogs(w http.ResponseWriter, r *http.Request) {
	e := s.loadEnv(w, r)
	if e == nil {
		return
	}
	var out []logSource

	dir := filepath.Join(s.cfg.Workdir, "jails-system", e.Name)
	files, err := filepath.Glob(filepath.Join(dir, "*.log"))
	if err != nil {
		files = nil
	}
	if len(files) == 0 {
		if _, serr := os.Stat(dir); errors.Is(serr, fs.ErrPermission) {
			out = append(out, logSource{Kind: "file", Title: "Журналы CBSD", Path: dir, Error: logPermissionH})
		}
	}
	// Newest first: the log of the last start is the interesting one.
	sort.Slice(files, func(i, j int) bool {
		a, _ := os.Stat(files[i])
		b, _ := os.Stat(files[j])
		return a != nil && b != nil && a.ModTime().After(b.ModTime())
	})
	if len(files) > logMaxFiles {
		files = files[:logMaxFiles]
	}
	for _, p := range files {
		src := logSource{Kind: "file", Title: filepath.Base(p), Path: p}
		if src.Title == "bstart.log" {
			src.Title = "bstart.log — запуск bhyve"
		}
		text, size, mod, cut, err := tailFile(p, logTailBytes)
		if err != nil {
			src.Error = logErr(err)
		} else {
			src.Text, src.Size, src.Cut = redactLog(text), size, cut
			src.Modified = mod.UTC().Format(time.RFC3339)
		}
		out = append(out, src)
	}

	if sys := s.systemLogLines(e); sys != nil {
		out = append(out, *sys)
	}

	shown := 0
	for _, js := range s.jobs.List() {
		if shown >= logJobsShown {
			break
		}
		if js.Target != e.Name {
			continue
		}
		j := s.jobs.Get(js.ID)
		if j == nil {
			continue
		}
		data, _, _ := j.Output(0)
		text := string(data)
		if len(text) > logTailBytes {
			text = text[len(text)-logTailBytes:]
		}
		if js.Error != "" {
			text += "\n[" + js.Error + "]\n"
		}
		out = append(out, logSource{Kind: "job", Title: js.Title, State: string(js.State),
			Modified: js.Created.UTC().Format(time.RFC3339), Text: redactLog(text)})
		shown++
	}
	if out == nil {
		out = []logSource{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": out})
}

// systemLogLines picks the last lines of the system log that mention the
// environment (and, for VMs, bhyve/vmm kernel messages).
func (s *Server) systemLogLines(e *cbsd.Env) *logSource {
	text, _, _, _, err := tailFile(systemLogPath, logSysScan)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	src := &logSource{Kind: "system", Title: "Системный журнал (" + systemLogPath + ")", Path: systemLogPath}
	if err != nil {
		src.Error = logErr(err)
		return src
	}
	vm := e.Emulator == "bhyve" || e.Emulator == "xen"
	var keep []string
	for _, ln := range strings.Split(text, "\n") {
		if strings.Contains(ln, e.Name) || (vm && (strings.Contains(ln, "bhyve") || strings.Contains(ln, "vmm"))) {
			keep = append(keep, ln)
		}
	}
	if len(keep) > logSysLines {
		keep, src.Cut = keep[len(keep)-logSysLines:], true
	}
	src.Text = redactLog(strings.Join(keep, "\n"))
	return src
}
