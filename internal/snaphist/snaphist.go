// Package snaphist remembers what ZFS itself forgets: rollbacks made from the
// UI (with the snapshots they destroyed) and branches saved as new
// environments, so the snapshot graph can show abandoned and saved lines.
package snaphist

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Lost is a snapshot destroyed by a rollback.
type Lost struct {
	Name    string `json:"name"`
	Created string `json:"created,omitempty"`
	Written uint64 `json:"written,omitempty"`
}

// Event is one rollback, optionally with the pre-rollback state saved as Branch.
type Event struct {
	Type   string    `json:"type"` // "rollback"
	At     time.Time `json:"at"`
	User   string    `json:"user"`
	To     string    `json:"to"`               // snapshot rolled back to
	Lost   []Lost    `json:"lost,omitempty"`   // newer snapshots destroyed by zfs rollback -r
	Branch string    `json:"branch,omitempty"` // environment holding the saved state
}

const maxPerEnv = 100

type Store struct {
	path string
	mu   sync.Mutex
	data map[string][]Event
}

// NewAt returns an empty store that saves to path.
func NewAt(path string) *Store { return &Store{path: path, data: map[string][]Event{}} }

func Open(path string) (*Store, error) {
	s := &Store{path: path, data: map[string][]Event{}}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &s.data); err != nil {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, err
	}
	return s, nil
}

// Events returns a copy of an environment's history, oldest first.
func (s *Store) Events(env string) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.data[env]...)
}

// Add records an event and saves the store atomically.
func (s *Store) Add(env string, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := append(s.data[env], e)
	if len(l) > maxPerEnv {
		l = l[len(l)-maxPerEnv:]
	}
	s.data[env] = l
	b, err := json.MarshalIndent(s.data, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
