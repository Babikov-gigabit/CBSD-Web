// Package jobs runs long cbsd operations in the background with a bounded
// worker pool, per-environment locking and live output streaming.
package jobs

import (
	"context"
	"errors"
	"io"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type State string

const (
	Queued   State = "queued"
	Running  State = "running"
	Done     State = "done"
	Failed   State = "failed"
	Canceled State = "canceled"
)

const maxOutput = 1 << 20 // keep at most 1 MiB of output per job
const keepJobs = 300

// RunFunc does the work, writing progress to out.
type RunFunc func(ctx context.Context, out io.Writer) error

type Job struct {
	ID       string    `json:"id"`
	User     string    `json:"user"`
	Title    string    `json:"title"`
	Target   string    `json:"target,omitempty"`
	State    State     `json:"state"`
	Error    string    `json:"error,omitempty"`
	Created  time.Time `json:"created"`
	Started  time.Time `json:"started,omitzero"`
	Finished time.Time `json:"finished,omitzero"`

	mu      sync.Mutex
	out     []byte
	dropped int
	subs    map[chan struct{}]struct{}
	cancel  context.CancelFunc
	run     RunFunc
}

// Snapshot is a copy safe to serialize.
type Snapshot struct {
	ID       string    `json:"id"`
	User     string    `json:"user"`
	Title    string    `json:"title"`
	Target   string    `json:"target,omitempty"`
	State    State     `json:"state"`
	Error    string    `json:"error,omitempty"`
	Created  time.Time `json:"created"`
	Started  time.Time `json:"started,omitzero"`
	Finished time.Time `json:"finished,omitzero"`
}

func (j *Job) Snapshot() Snapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	return Snapshot{j.ID, j.User, j.Title, j.Target, j.State, j.Error, j.Created, j.Started, j.Finished}
}

// Write implements io.Writer for the job's output buffer.
func (j *Job) Write(p []byte) (int, error) {
	j.mu.Lock()
	j.out = append(j.out, p...)
	if over := len(j.out) - maxOutput; over > 0 {
		j.out = append(j.out[:0:0], j.out[over:]...)
		j.dropped += over
	}
	for ch := range j.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	j.mu.Unlock()
	return len(p), nil
}

// Output returns output starting at absolute offset off, the next offset,
// and whether the job is finished.
func (j *Job) Output(off int) (data []byte, next int, finished bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	start := off - j.dropped
	if start < 0 {
		start = 0
	}
	if start > len(j.out) {
		start = len(j.out)
	}
	data = append([]byte(nil), j.out[start:]...)
	next = j.dropped + len(j.out)
	finished = j.State == Done || j.State == Failed || j.State == Canceled
	return
}

// Subscribe returns a channel signalled on new output or state change.
func (j *Job) Subscribe() (ch chan struct{}, unsubscribe func()) {
	ch = make(chan struct{}, 1)
	j.mu.Lock()
	if j.subs == nil {
		j.subs = map[chan struct{}]struct{}{}
	}
	j.subs[ch] = struct{}{}
	j.mu.Unlock()
	return ch, func() {
		j.mu.Lock()
		delete(j.subs, ch)
		j.mu.Unlock()
	}
}

func (j *Job) setState(s State, err error) {
	j.mu.Lock()
	j.State = s
	now := time.Now()
	switch s {
	case Running:
		j.Started = now
	case Done, Failed, Canceled:
		j.Finished = now
		if err != nil {
			j.Error = err.Error()
		}
	}
	for ch := range j.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	j.mu.Unlock()
}

// Manager owns all jobs.
type Manager struct {
	mu      sync.Mutex
	jobs    map[string]*Job
	order   []string
	busy    map[string]string // target -> job id
	sem     chan struct{}
	seq     atomic.Uint64
	OnEnd   func(Snapshot)
	ctx     context.Context
	cancelA context.CancelFunc
}

var ErrBusy = errors.New("для этого окружения уже выполняется операция")

func NewManager(concurrency int) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{jobs: map[string]*Job{}, busy: map[string]string{}, sem: make(chan struct{}, concurrency), ctx: ctx, cancelA: cancel}
}

// Submit queues a job. target (environment name, or "" for global) is locked
// for the job's lifetime so conflicting operations cannot run concurrently.
func (m *Manager) Submit(user, title, target string, run RunFunc) (*Job, error) {
	m.mu.Lock()
	if target != "" {
		if id, ok := m.busy[target]; ok {
			m.mu.Unlock()
			return nil, errors.Join(ErrBusy, errors.New("job "+id))
		}
	}
	id := strconv.FormatInt(time.Now().Unix(), 36) + "-" + strconv.FormatUint(m.seq.Add(1), 36)
	ctx, cancel := context.WithCancel(m.ctx)
	j := &Job{ID: id, User: user, Title: title, Target: target, State: Queued, Created: time.Now(), cancel: cancel, run: run}
	m.jobs[id] = j
	m.order = append(m.order, id)
	if target != "" {
		m.busy[target] = id
	}
	m.trimLocked()
	m.mu.Unlock()

	go m.exec(ctx, j)
	return j, nil
}

func (m *Manager) exec(ctx context.Context, j *Job) {
	defer func() {
		m.mu.Lock()
		if j.Target != "" && m.busy[j.Target] == j.ID {
			delete(m.busy, j.Target)
		}
		m.mu.Unlock()
		if m.OnEnd != nil {
			m.OnEnd(j.Snapshot())
		}
	}()
	select {
	case m.sem <- struct{}{}:
	case <-ctx.Done():
		j.setState(Canceled, ctx.Err())
		return
	}
	defer func() { <-m.sem }()
	j.setState(Running, nil)
	err := j.run(ctx, j)
	switch {
	case ctx.Err() != nil:
		j.setState(Canceled, errors.New("отменено"))
	case err != nil:
		j.setState(Failed, err)
	default:
		j.setState(Done, nil)
	}
}

func (m *Manager) trimLocked() {
	for len(m.order) > keepJobs {
		id := m.order[0]
		j := m.jobs[id]
		if s := j.Snapshot().State; s == Queued || s == Running {
			break
		}
		delete(m.jobs, id)
		m.order = m.order[1:]
	}
}

func (m *Manager) Get(id string) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.jobs[id]
}

// List returns jobs newest first.
func (m *Manager) List() []Snapshot {
	m.mu.Lock()
	js := make([]*Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		js = append(js, j)
	}
	m.mu.Unlock()
	out := make([]Snapshot, len(js))
	for i, j := range js {
		out[i] = j.Snapshot()
	}
	sort.Slice(out, func(i, k int) bool { return out[i].Created.After(out[k].Created) })
	return out
}

// Busy returns the targets with active jobs.
func (m *Manager) Busy() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.busy))
	for k, v := range m.busy {
		out[k] = v
	}
	return out
}

func (m *Manager) Cancel(id string) bool {
	j := m.Get(id)
	if j == nil {
		return false
	}
	j.cancel()
	return true
}

// Shutdown cancels everything.
func (m *Manager) Shutdown() { m.cancelA() }
