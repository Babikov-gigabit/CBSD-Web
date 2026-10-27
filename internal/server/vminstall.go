package server

import (
	"net/http"

	"github.com/cbsd-web/cbsd-web/internal/cbsd"
)

// Installing an OS into a VM from the browser: attach an ISO, boot from it,
// and switch back to the disk afterwards. CBSD itself asks "boot from CD?"
// on the terminal when the disk is empty; jobs run non-interactively, so the
// boot device is set explicitly here instead.

type vmMediaInfo struct {
	Boot      string    `json:"boot"`
	VNCWait   bool      `json:"cd_vnc_wait"`
	Attached  []isoInfo `json:"attached"`
	Available []isoInfo `json:"available"`
	Running   bool      `json:"running"`
}

func (s *Server) loadVM(w http.ResponseWriter, r *http.Request) *cbsd.Env {
	e := s.loadEnv(w, r)
	if e != nil && e.Emulator != "bhyve" && e.Emulator != "xen" {
		writeErr(w, http.StatusBadRequest, "доступно только для ВМ")
		return nil
	}
	return e
}

func (s *Server) handleVMMedia(w http.ResponseWriter, r *http.Request) {
	e := s.loadVM(w, r)
	if e == nil {
		return
	}
	vals, _, err := s.db.VMConfig(r.Context(), e.Emulator, e.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, dbErrorMessage(err))
		return
	}
	list, err := s.listISOs(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	info := vmMediaInfo{Boot: vals["vm_boot"], VNCWait: vals["cd_vnc_wait"] == "1", Attached: []isoInfo{}, Available: []isoInfo{}, Running: e.Status == 1}
	for _, it := range list {
		if contains(it.AttachedTo, e.Name) {
			info.Attached = append(info.Attached, it)
		} else if it.Usable {
			info.Available = append(info.Available, it)
		}
	}
	writeJSON(w, http.StatusOK, info)
}

type vmMediaReq struct {
	// attach: connect ISO; eject: disconnect all ISOs;
	// install: boot from the ISO now; finish: boot from disk, eject, start.
	Action string `json:"action"`
	ISO    string `json:"iso"`
}

func (s *Server) handleVMMediaAction(w http.ResponseWriter, r *http.Request) {
	e := s.loadVM(w, r)
	if e == nil {
		return
	}
	var req vmMediaReq
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	set, stop, start := "bset", "bstop", "bstart"
	if e.Emulator == "xen" {
		set, stop, start = "xset", "xstop", "xstart"
	}
	jname := "jname=" + e.Name
	eject := []string{"media", "mode=eject", jname}
	var steps [][]string
	var title string

	switch req.Action {
	case "attach":
		if !cbsd.ValidMediaName(req.ISO) {
			writeFieldErr(w, &cbsd.FieldError{Field: "iso", Msg: "выберите образ"})
			return
		}
		list, err := s.listISOs(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		var it *isoInfo
		for i := range list {
			if list[i].Media == req.ISO && list[i].Usable {
				it = &list[i]
			}
		}
		if it == nil {
			writeFieldErr(w, &cbsd.FieldError{Field: "iso", Msg: "образ не найден"})
			return
		}
		media := []string{"name=" + it.Media, "path=" + it.Path, "type=iso"}
		// One install ISO at a time: detach the previous one first.
		steps = append(steps, eject)
		if !it.Registered {
			steps = append(steps, append([]string{"media", "mode=register"}, media...))
		}
		steps = append(steps,
			append(append([]string{"media", "mode=attach"}, media...), jname),
			[]string{set, jname, "vm_iso_path=" + it.Media})
		title = "Подключение ISO к " + e.Name
	case "eject":
		steps = [][]string{eject, {set, jname, "vm_iso_path=0"}}
		title = "Извлечение ISO из " + e.Name
	case "install":
		list, err := s.listISOs(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		attached := false
		for _, it := range list {
			attached = attached || contains(it.AttachedTo, e.Name)
		}
		if !attached {
			writeFieldErr(w, &cbsd.FieldError{Field: "iso", Msg: "сначала подключите ISO"})
			return
		}
		if e.Status == 1 {
			steps = append(steps, []string{stop, jname})
		}
		steps = append(steps, []string{set, jname, "vm_boot=cd"}, []string{start, jname})
		title = "Установка ОС: запуск " + e.Name + " с ISO"
	case "finish":
		if e.Status == 1 {
			steps = append(steps, []string{stop, jname})
		}
		steps = append(steps, []string{set, jname, "vm_boot=hdd", "vm_iso_path=0"}, eject, []string{start, jname})
		title = "Установка ОС завершена: запуск " + e.Name + " с диска"
	default:
		writeErr(w, http.StatusBadRequest, "неизвестное действие")
		return
	}
	s.submitSteps(w, r, title, e.Name, steps, nil, nil)
}
