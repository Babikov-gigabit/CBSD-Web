package snaphist

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRemove(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "h.json"))
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 27, 7, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		s.Add("web1", Event{Type: "rollback", At: t0.Add(time.Duration(i) * time.Minute), To: "s"})
	}
	s.Add("db1", Event{Type: "rollback", At: t0, To: "s"})
	if n, err := s.Remove("web1", t0, t0.Add(2*time.Minute), t0.Add(time.Hour)); err != nil || n != 2 {
		t.Fatalf("remove two: %d %v", n, err)
	}
	ev := s.Events("web1")
	if len(ev) != 2 || !ev[0].At.Equal(t0.Add(time.Minute)) || !ev[1].At.Equal(t0.Add(3*time.Minute)) {
		t.Fatalf("left: %v", ev)
	}
	if len(s.Events("db1")) != 1 {
		t.Fatal("other env touched")
	}
	if n, _ := s.Remove("web1"); n != 2 || len(s.Events("web1")) != 0 {
		t.Fatalf("remove all: %d", n)
	}
	r, _ := Open(s.path)
	if len(r.Events("web1")) != 0 || len(r.Events("db1")) != 1 {
		t.Fatal("not saved")
	}
}
