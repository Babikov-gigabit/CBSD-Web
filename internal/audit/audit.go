// Package audit writes an append-only JSON-lines log of security-relevant events.
package audit

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Logger struct {
	mu sync.Mutex
	f  *os.File
}

type Entry struct {
	Time   time.Time         `json:"time"`
	User   string            `json:"user,omitempty"`
	IP     string            `json:"ip,omitempty"`
	Event  string            `json:"event"`
	Target string            `json:"target,omitempty"`
	Result string            `json:"result,omitempty"`
	Detail map[string]string `json:"detail,omitempty"`
}

// Open opens (or creates with mode 0600) the audit log. An empty path logs to stderr.
func Open(path string) (*Logger, error) {
	if path == "" {
		return &Logger{}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f}, nil
}

func (l *Logger) Log(e Entry) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		log.Printf("audit %s", b)
		return
	}
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		log.Printf("audit write: %v", err)
	}
}

func (l *Logger) Close() error {
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}
