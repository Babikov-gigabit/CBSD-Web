package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/cbsd-web/cbsd-web/web"
)

type asset struct {
	body, gz []byte
	ctype    string
	etag     string
}

// staticFS serves the embedded UI from memory with precomputed gzip and ETags.
type staticFS struct{ files map[string]*asset }

func newStaticFS() (*staticFS, error) {
	sub, err := fs.Sub(web.Files, "static")
	if err != nil {
		return nil, err
	}
	st := &staticFS{files: map[string]*asset{}}
	err = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(sub, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		a := &asset{body: b, etag: `"` + hex.EncodeToString(sum[:8]) + `"`}
		a.ctype = mime.TypeByExtension(path.Ext(p))
		if a.ctype == "" {
			a.ctype = "application/octet-stream"
		}
		if strings.HasPrefix(a.ctype, "text/") || strings.Contains(a.ctype, "javascript") || strings.Contains(a.ctype, "svg") || strings.Contains(a.ctype, "json") {
			var buf bytes.Buffer
			zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
			zw.Write(b)
			zw.Close()
			if buf.Len() < len(b) {
				a.gz = buf.Bytes()
			}
		}
		st.files["/"+p] = a
		return nil
	})
	return st, err
}

func (s *staticFS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := path.Clean(r.URL.Path)
	a, ok := s.files[p]
	if !ok {
		// Single-page app: unknown paths without an extension get index.html.
		if path.Ext(p) != "" {
			http.NotFound(w, r)
			return
		}
		a = s.files["/index.html"]
	}
	h := w.Header()
	h.Set("Content-Type", a.ctype)
	h.Set("ETag", a.etag)
	h.Set("Cache-Control", "no-cache")
	h.Set("Vary", "Accept-Encoding")
	if r.Header.Get("If-None-Match") == a.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body := a.body
	if a.gz != nil && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		h.Set("Content-Encoding", "gzip")
		body = a.gz
	}
	w.Write(body)
}
