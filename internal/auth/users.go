// Package auth implements local users, sessions, CSRF tokens and login throttling.
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type Role string

const (
	RoleViewer   Role = "viewer"   // read-only
	RoleOperator Role = "operator" // start/stop/create
	RoleAdmin    Role = "admin"    // destroy, setup, users
)

func (r Role) Valid() bool { return r == RoleViewer || r == RoleOperator || r == RoleAdmin }

func (r Role) level() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	}
	return 0
}

// Allows reports whether r has at least the privileges of need.
func (r Role) Allows(need Role) bool { return r.level() >= need.level() && need.level() > 0 }

type User struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
	Role Role   `json:"role"`
}

type userFile struct {
	Users []User `json:"users"`
}

// Store keeps users in a JSON file (mode 0600) with bcrypt hashes.
type Store struct {
	mu    sync.RWMutex
	path  string
	users map[string]User
	dummy []byte
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,31}$`)

// BcryptCost is the work factor for password hashes (lowered only in tests).
var BcryptCost = 12

// MinPasswordLen is enforced for every password set through this package.
const MinPasswordLen = 10

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, users: map[string]User{}}
	// Hash compared against when the user does not exist, so timing does not reveal valid names.
	d, err := bcrypt.GenerateFromPassword([]byte("cbsd-web-timing-equalizer"), BcryptCost)
	if err != nil {
		return nil, err
	}
	s.dummy = d
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var uf userFile
	if err := json.Unmarshal(b, &uf); err != nil {
		return nil, fmt.Errorf("users file: %w", err)
	}
	for _, u := range uf.Users {
		if !nameRe.MatchString(u.Name) || !u.Role.Valid() {
			return nil, fmt.Errorf("users file: invalid entry %q", u.Name)
		}
		s.users[u.Name] = u
	}
	return s, nil
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// Verify checks a password in constant-ish time regardless of whether the user exists.
func (s *Store) Verify(name, password string) (User, bool) {
	s.mu.RLock()
	u, ok := s.users[name]
	s.mu.RUnlock()
	if !ok || len(password) > 72 {
		_ = bcrypt.CompareHashAndPassword(s.dummy, []byte(password))
		return User{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password)) != nil {
		return User{}, false
	}
	return u, true
}

func (s *Store) Get(name string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[name]
	return u, ok
}

// List returns users without password hashes.
func (s *Store) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, User{Name: u.Name, Role: u.Role})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func ValidatePassword(p string) error {
	if len(p) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(p) > 72 {
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}

// Set creates or updates a user. Empty password keeps the existing hash.
func (s *Store) Set(name, password string, role Role) error {
	if !nameRe.MatchString(name) {
		return errors.New("invalid user name (a-z, 0-9, _ . -, 2-32 chars)")
	}
	if !role.Valid() {
		return errors.New("invalid role")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, exists := s.users[name]
	if password != "" || !exists {
		if err := ValidatePassword(password); err != nil {
			return err
		}
		h, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
		if err != nil {
			return err
		}
		u.Hash = string(h)
	}
	if exists && u.Role == RoleAdmin && role != RoleAdmin && s.adminCountLocked() == 1 {
		return errors.New("cannot demote the last admin")
	}
	u.Name, u.Role = name, role
	s.users[name] = u
	return s.saveLocked()
}

func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return errors.New("no such user")
	}
	if u.Role == RoleAdmin && s.adminCountLocked() == 1 {
		return errors.New("cannot delete the last admin")
	}
	delete(s.users, name)
	return s.saveLocked()
}

func (s *Store) adminCountLocked() int {
	n := 0
	for _, u := range s.users {
		if u.Role == RoleAdmin {
			n++
		}
	}
	return n
}

func (s *Store) saveLocked() error {
	uf := userFile{}
	for _, u := range s.users {
		uf.Users = append(uf.Users, u)
	}
	sort.Slice(uf.Users, func(i, j int) bool { return uf.Users[i].Name < uf.Users[j].Name })
	b, err := json.MarshalIndent(uf, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".users-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
