package server

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/cbsd-web/cbsd-web/internal/audit"
	"github.com/cbsd-web/cbsd-web/internal/cbsd"
	"github.com/cbsd-web/cbsd-web/internal/hoststat"
	"github.com/cbsd-web/cbsd-web/internal/snaphist"
)

// envDataset finds the ZFS dataset behind an environment: from CBSD's own
// snapshot list when there is one, else the dataset mounted at its data dir.
func (s *Server) envDataset(ctx context.Context, name string) (string, []cbsd.Snapshot) {
	out, _ := s.runner.Output(ctx, 60*time.Second, cbsd.ListSnapshotArgs(name)...)
	snaps := cbsd.ParseSnapshots(out)
	if len(snaps) > 0 {
		return snaps[0].Dataset, snaps
	}
	if ds, err := hoststat.DatasetOf(ctx, filepath.Join(s.cfg.Workdir, "jails-data", name+"-data")); err == nil && ds != nil {
		return ds.Name, nil
	}
	return "", nil
}

type graphRef struct {
	Dataset string `json:"dataset"`
	Snap    string `json:"snap,omitempty"`
	Env     string `json:"env,omitempty"` // CBSD environment owning the dataset, if known
}

// envOfDataset maps a CBSD data dataset (".../<name>-data") to its environment.
func envOfDataset(ds, mountpoint string, known map[string]bool) string {
	for _, cand := range []string{filepath.Base(mountpoint), ds[strings.LastIndexByte(ds, '/')+1:]} {
		if n, ok := strings.CutSuffix(cand, "-data"); ok && known[n] {
			return n
		}
	}
	// CBSD's own snapshot datasets are named <pool>/<jname>.
	if n := ds[strings.LastIndexByte(ds, '/')+1:]; known[n] {
		return n
	}
	return ""
}

func (s *Server) handleSnapshotGraph(w http.ResponseWriter, r *http.Request) {
	e := s.loadEnv(w, r)
	if e == nil {
		return
	}
	ctx := r.Context()
	ds, cbsdSnaps := s.envDataset(ctx, e.Name)
	known := map[string]bool{}
	if envs, err := s.db.Envs(ctx, ""); err == nil {
		for _, x := range envs {
			known[x.Name] = true
		}
	}
	// A saved branch disappears from the graph once its jail is removed.
	hist := s.hist.Events(e.Name)
	for i := range hist {
		if hist[i].Branch != "" && !known[hist[i].Branch] {
			hist[i].Branch = ""
		}
	}
	res := map[string]any{"env": e.Name, "dataset": ds, "history": hist, "now": time.Now().Unix()}
	if ds == "" {
		res["error"] = "не удалось определить набор ZFS окружения (нужен ZFS)"
		writeJSON(w, http.StatusOK, res)
		return
	}
	cbsdNames := map[string]bool{}
	for _, sn := range cbsdSnaps {
		cbsdNames[sn.Name] = true
	}
	type node struct {
		hoststat.ZSnap
		CBSD bool `json:"cbsd"` // made by CBSD (can be rolled back from the UI)
	}
	zs, err := hoststat.ZFSSnapshots(ctx, ds)
	if err != nil {
		res["error"] = "zfs list: " + errText(err)
	}
	nodes := make([]node, 0, len(zs))
	for _, z := range zs {
		nodes = append(nodes, node{ZSnap: z, CBSD: cbsdNames[z.Name]})
	}
	res["snapshots"] = nodes
	props, _ := hoststat.DatasetProps(ctx, ds)
	res["current"] = props

	if props.Origin != "" {
		pds, psnap, _ := strings.Cut(props.Origin, "@")
		res["parent"] = graphRef{Dataset: pds, Snap: psnap, Env: envOfDataset(pds, "", known)}
	}
	branches := []graphRef{}
	pool, _, _ := strings.Cut(ds, "/")
	if clones, err := hoststat.Clones(ctx, pool); err == nil {
		for _, c := range clones {
			if snap, ok := strings.CutPrefix(c.Origin, ds+"@"); ok {
				branches = append(branches, graphRef{Dataset: c.Name, Snap: snap, Env: envOfDataset(c.Name, c.Mountpoint, known)})
			}
		}
	}
	res["branches"] = branches
	writeJSON(w, http.StatusOK, res)
}

// rollback runs 'jsnapshot mode=rollback' and records what it destroys. With
// saveAs, the current state is first copied to a new jail (rsync, so the copy
// does not depend on snapshots the rollback removes).
func (s *Server) rollback(w http.ResponseWriter, r *http.Request, e *cbsd.Env, snap, saveAs string) {
	args, err := cbsd.SnapshotArgs(e.Emulator, "rollback", e.Name, snap)
	if err != nil {
		writeFieldErr(w, err)
		return
	}
	steps := [][]string{}
	if saveAs != "" {
		if e.Emulator != "jail" {
			writeFieldErr(w, &cbsd.FieldError{Field: "save_as", Msg: "сохранение ветки доступно только для клеток"})
			return
		}
		if ex, _ := s.db.Env(r.Context(), saveAs); ex != nil {
			writeFieldErr(w, &cbsd.FieldError{Field: "save_as", Msg: "имя уже занято"})
			return
		}
		cl, err := cbsd.CloneArgs("jail", e.Name, saveAs, strings.ReplaceAll(saveAs, "_", "-"))
		if err != nil {
			writeFieldErr(w, &cbsd.FieldError{Field: "save_as", Msg: err.(*cbsd.FieldError).Msg})
			return
		}
		steps = append(steps, append(cl, "clone_method=rsync"))
	}
	steps = append(steps, args)
	var finally [][]string
	if e.Status == 1 {
		// jclone refuses a running jail and rolling back a live filesystem is
		// unsafe: stop first, start again afterwards (also if a step fails).
		stop, _ := cbsd.ActionArgs(e.Emulator, cbsd.ActStop, e.Name)
		start, _ := cbsd.ActionArgs(e.Emulator, cbsd.ActStart, e.Name)
		steps = append([][]string{stop}, steps...)
		finally = [][]string{start}
	}

	// Snapshots newer than the target are destroyed by 'zfs rollback -r'.
	var lost []snaphist.Lost
	ds, _ := s.envDataset(r.Context(), e.Name)
	if ds != "" {
		zs, _ := hoststat.ZFSSnapshots(r.Context(), ds)
		found := false
		for _, z := range zs {
			if found {
				lost = append(lost, snaphist.Lost{Name: z.Name, Created: time.Unix(z.Created, 0).Format("2006-01-02 15:04"), Written: z.Written})
			}
			if z.Name == snap {
				found = true
			}
		}
	}
	user := sessionFrom(r).sess.User
	title := "Откат " + e.Name + " к " + snap
	if saveAs != "" {
		title += " (текущее → " + saveAs + ")"
	}
	s.submitSteps(w, r, title, e.Name, steps, finally, func(err error) {
		if err == nil {
			s.hist.Add(e.Name, snaphist.Event{Type: "rollback", At: time.Now(), User: user, To: snap, Lost: lost, Branch: saveAs})
		}
	})
}

// trySnapshot creates a new jail from an older snapshot via 'jcreate
// zfs_snapsrc=' (a ZFS clone: instant, no copy). Unlike a rollback the source
// jail keeps its current data and every snapshot, so returning to the current
// state means simply using the source jail again.
func (s *Server) trySnapshot(w http.ResponseWriter, r *http.Request, e *cbsd.Env, req snapReq) {
	if !cbsd.ValidSnapName(req.SnapName) {
		writeFieldErr(w, &cbsd.FieldError{Field: "snapname", Msg: "некорректное имя снимка"})
		return
	}
	if ex, _ := s.db.Env(r.Context(), req.New); ex != nil {
		writeFieldErr(w, &cbsd.FieldError{Field: "new", Msg: "имя уже занято"})
		return
	}
	ds, _ := s.envDataset(r.Context(), e.Name)
	if ds == "" {
		writeFieldErr(w, &cbsd.FieldError{Field: "snapname", Msg: "не найден набор данных ZFS клетки"})
		return
	}
	create, err := cbsd.FromSnapshotArgs(e, req.New, ds+"@"+req.SnapName, req.Start)
	if err != nil {
		writeFieldErr(w, err)
		return
	}
	steps := [][]string{}
	if req.Keep != "" {
		keep, err := cbsd.SnapshotArgs(e.Emulator, "create", e.Name, req.Keep)
		if err != nil {
			writeFieldErr(w, &cbsd.FieldError{Field: "keep", Msg: "латиница, цифры, _.-"})
			return
		}
		steps = append(steps, keep)
	}
	steps = append(steps, create)
	user := sessionFrom(r).sess.User
	title := "Снимок " + e.Name + "@" + req.SnapName + " → клетка " + req.New
	s.submitSteps(w, r, title, e.Name, steps, nil, func(err error) {
		if err == nil {
			s.hist.Add(e.Name, snaphist.Event{Type: "try", At: time.Now(), User: user, To: req.SnapName, Branch: req.New, Kept: req.Keep})
		}
	})
}

// handleSnapshotHistoryDelete hides recorded rollbacks from the graph: one
// event (?at=<its time>) or, without at, the whole history of the
// environment. Only the web UI's records change; ZFS is not touched.
func (s *Server) handleSnapshotHistoryDelete(w http.ResponseWriter, r *http.Request) {
	e := s.loadEnv(w, r)
	if e == nil {
		return
	}
	var at time.Time
	if v := r.URL.Query().Get("at"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "некорректное время события")
			return
		}
		at = t
	}
	n, err := s.hist.Remove(e.Name, at)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n > 0 {
		rc := sessionFrom(r)
		s.audit.Log(audit.Entry{User: rc.sess.User, IP: rc.ip, Event: "snapshot.history.delete", Target: e.Name, Result: fmt.Sprint(n)})
	}
	if n == 0 && !at.IsZero() {
		writeErr(w, http.StatusNotFound, "событие не найдено")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": n})
}
