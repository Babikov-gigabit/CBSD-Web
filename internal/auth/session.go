package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

type Session struct {
	User     string
	Role     Role
	CSRF     string
	IP       string
	Created  time.Time
	LastSeen time.Time
}

// Sessions is an in-memory session store. Only SHA-256 digests of tokens are
// kept, so a memory dump does not yield usable cookies.
type Sessions struct {
	mu     sync.Mutex
	m      map[[32]byte]*Session
	idle   time.Duration
	maxAge time.Duration
}

func NewSessions(idle, maxAge time.Duration) *Sessions {
	s := &Sessions{m: map[[32]byte]*Session{}, idle: idle, maxAge: maxAge}
	go s.gc()
	return s
}

func RandomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Sessions) Create(user string, role Role, ip string) (token string, sess Session) {
	token = RandomToken()
	now := time.Now()
	ss := &Session{User: user, Role: role, CSRF: RandomToken(), IP: ip, Created: now, LastSeen: now}
	s.mu.Lock()
	s.m[sha256.Sum256([]byte(token))] = ss
	s.mu.Unlock()
	return token, *ss
}

// Get validates the token and refreshes its idle timer.
func (s *Sessions) Get(token string) (Session, bool) {
	if token == "" || len(token) > 128 {
		return Session{}, false
	}
	k := sha256.Sum256([]byte(token))
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	ss, ok := s.m[k]
	if !ok {
		return Session{}, false
	}
	if now.Sub(ss.LastSeen) > s.idle || now.Sub(ss.Created) > s.maxAge {
		delete(s.m, k)
		return Session{}, false
	}
	ss.LastSeen = now
	return *ss, true
}

func (s *Sessions) Delete(token string) {
	s.mu.Lock()
	delete(s.m, sha256.Sum256([]byte(token)))
	s.mu.Unlock()
}

// DeleteUser revokes all sessions of a user (password change, role change, deletion).
func (s *Sessions) DeleteUser(user string) {
	s.mu.Lock()
	for k, ss := range s.m {
		if ss.User == user {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
}

func (s *Sessions) gc() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for k, ss := range s.m {
			if now.Sub(ss.LastSeen) > s.idle || now.Sub(ss.Created) > s.maxAge {
				delete(s.m, k)
			}
		}
		s.mu.Unlock()
	}
}

// CSRFValid compares tokens in constant time.
func CSRFValid(sess Session, got string) bool {
	return got != "" && subtle.ConstantTimeCompare([]byte(sess.CSRF), []byte(got)) == 1
}

// Limiter throttles failed logins per key (client IP and user name).
type Limiter struct {
	mu      sync.Mutex
	fails   map[string][]time.Time
	max     int
	window  time.Duration
	lockout time.Duration
}

func NewLimiter(max int, window, lockout time.Duration) *Limiter {
	return &Limiter{fails: map[string][]time.Time{}, max: max, window: window, lockout: lockout}
}

// Blocked reports whether key is locked out and for how long.
func (l *Limiter) Blocked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.prune(key)
	if len(f) >= l.max {
		left := l.lockout - time.Since(f[len(f)-1])
		if left > 0 {
			return true, left
		}
	}
	return false, 0
}

func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[key] = append(l.prune(key), time.Now())
	if len(l.fails) > 100000 { // bound memory under a distributed attack
		l.fails = map[string][]time.Time{}
	}
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.fails, key)
	l.mu.Unlock()
}

func (l *Limiter) prune(key string) []time.Time {
	f := l.fails[key]
	keep := f[:0]
	horizon := l.window
	if l.lockout > horizon {
		horizon = l.lockout
	}
	for _, t := range f {
		if time.Since(t) < horizon {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fails, key)
		return nil
	}
	l.fails[key] = keep
	return keep
}
