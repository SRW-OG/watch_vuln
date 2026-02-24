package web

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/pkg/errors"

	"github.com/zema1/watchvuln/ent/vulninformation"
)

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("/api/me", s.requireAuth(s.handleMe))
	mux.HandleFunc("/api/v1/config", s.requireAuth(s.handleConfig))
	mux.HandleFunc("/api/v1/vulns", s.requireAuth(s.handleVulnList))
	mux.HandleFunc("/api/v1/vulns/", s.requireAuth(s.handleVulnDetail))

	mux.Handle("/static/", s.handleStatic())
	mux.HandleFunc("/", s.handleIndex)
	return mux
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		p, err := s.currentAuth().parseSession(cookie.Value)
		if err != nil {
			s.currentAuth().clearSessionCookie(w)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserKey{}, p.U)
		next(w, r.WithContext(ctx))
	}
}

type ctxUserKey struct{}

func userFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(ctxUserKey{}).(string)
	return v
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	if !s.currentAuth().checkCredentials(req.Username, req.Password) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	ttl := time.Hour * 24
	token, err := s.currentAuth().issueSession(req.Username, ttl)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	s.currentAuth().setSessionCookie(w, token, time.Now().Add(ttl))
	writeJSON(w, http.StatusOK, map[string]any{"username": req.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	s.currentAuth().clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": userFromCtx(r.Context())})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfig(w, r)
	case http.MethodPut:
		s.handleUpdateConfig(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	meta := defaultConfigMeta()
	if strings.TrimSpace(s.cfg.ConfigPath) == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"editable": false,
			"file":     "",
			"config":   nil,
			"meta":     meta,
			"error":    "config file is not set, start with -c config.yaml or -c config.json",
		})
		return
	}
	cfg, format, err := readConfigFile(s.cfg.ConfigPath)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"editable": false,
			"file":     filepath.Base(s.cfg.ConfigPath),
			"config":   nil,
			"meta":     meta,
			"error":    "failed to read config file",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"editable": true,
		"format":   format,
		"file":     filepath.Base(s.cfg.ConfigPath),
		"config":   cfg.redacted(),
		"meta":     meta,
	})
}

func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.cfg.ConfigPath) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "config file is not set"})
		return
	}

	oldCfg, format, err := readConfigFile(s.cfg.ConfigPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "failed to read config file"})
		return
	}

	var req struct {
		Config FileConfig `json:"config"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}

	merged := mergeSecrets(&req.Config, oldCfg)
	data, err := merged.marshal(format)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if err := writeFileAtomic(s.cfg.ConfigPath, data); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to write config file"})
		return
	}

	applyRes, applyErr := s.applyRuntimeConfig(r.Context(), merged)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"format":      format,
		"file":        filepath.Base(s.cfg.ConfigPath),
		"config":      merged.redacted(),
		"apply":       applyRes,
		"apply_error": errString(applyErr),
	})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Server) handleVulnList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	from := strings.TrimSpace(r.URL.Query().Get("from"))
	pushedStr := strings.TrimSpace(r.URL.Query().Get("pushed"))
	limit := parseInt(r.URL.Query().Get("limit"), 20, 1, 100)
	offset := parseInt(r.URL.Query().Get("offset"), 0, 0, 1_000_000)

	query := s.currentDB().VulnInformation.Query()
	if q != "" {
		query = query.Where(vulninformation.Or(
			vulninformation.KeyContains(q),
			vulninformation.TitleContains(q),
			vulninformation.DescriptionContains(q),
			vulninformation.CveContains(q),
		))
	}
	if severity != "" {
		query = query.Where(vulninformation.Severity(severity))
	}
	if from != "" {
		query = query.Where(vulninformation.From(from))
	}
	if pushedStr != "" {
		if pushed, err := strconv.ParseBool(pushedStr); err == nil {
			query = query.Where(vulninformation.Pushed(pushed))
		}
	}

	total, err := query.Count(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	items, err := query.
		Order(vulninformation.ByCreateTime(sql.OrderDesc())).
		Limit(limit).
		Offset(offset).
		All(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}

	type item struct {
		ID          int       `json:"id"`
		Key         string    `json:"key"`
		Title       string    `json:"title"`
		Severity    string    `json:"severity"`
		CVE         string    `json:"cve"`
		From        string    `json:"from"`
		Pushed      bool      `json:"pushed"`
		CreateTime  time.Time `json:"create_time"`
		UpdateTime  time.Time `json:"update_time"`
		Disclosure  string    `json:"disclosure"`
		Tags        []string  `json:"tags"`
		References  []string  `json:"references"`
		GithubSearch []string `json:"github_search"`
	}
	res := make([]item, 0, len(items))
	for _, v := range items {
		res = append(res, item{
			ID:          v.ID,
			Key:         v.Key,
			Title:       v.Title,
			Severity:    v.Severity,
			CVE:         v.Cve,
			From:        v.From,
			Pushed:      v.Pushed,
			CreateTime:  v.CreateTime,
			UpdateTime:  v.UpdateTime,
			Disclosure:  v.Disclosure,
			Tags:        v.Tags,
			References:  v.References,
			GithubSearch: v.GithubSearch,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":  total,
		"items":  res,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) handleVulnDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/v1/vulns/")
	idStr = strings.TrimSpace(idStr)
	if idStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	v, err := s.currentDB().VulnInformation.Get(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":            v.ID,
		"key":           v.Key,
		"title":         v.Title,
		"description":   v.Description,
		"severity":      v.Severity,
		"cve":           v.Cve,
		"disclosure":    v.Disclosure,
		"solutions":     v.Solutions,
		"references":    v.References,
		"tags":          v.Tags,
		"github_search": v.GithubSearch,
		"from":          v.From,
		"pushed":        v.Pushed,
		"create_time":   v.CreateTime,
		"update_time":   v.UpdateTime,
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	uidir := s.currentUIDir()
	if uidir != "" {
		p := filepath.Join(uidir, "index.html")
		f, err := os.Open(p)
		if err == nil {
			defer f.Close()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.Copy(w, f)
			return
		}
	}
	efs := s.currentEmbeddedUI()
	if efs == nil {
		http.Error(w, "ui not found", http.StatusInternalServerError)
		return
	}
	f, err := efs.Open("index.html")
	if err != nil {
		http.Error(w, "ui not found", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.Copy(w, f)
}

func (s *Server) handleStatic() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(r.URL.Path, "/static/")
		if rel == "" || strings.Contains(rel, "..") {
			http.NotFound(w, r)
			return
		}
		uidir := s.currentUIDir()
		if uidir != "" {
			p := filepath.Join(uidir, "static", filepath.FromSlash(rel))
			if _, err := os.Stat(p); err == nil {
				ext := filepath.Ext(p)
				if ctype := mime.TypeByExtension(ext); ctype != "" {
					w.Header().Set("Content-Type", ctype)
				}
				http.ServeFile(w, r, p)
				return
			}
		}

		efs := s.currentEmbeddedUI()
		if efs == nil {
			http.NotFound(w, r)
			return
		}
		sub, err := fs.Sub(efs, "static")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		ext := filepath.Ext(rel)
		if ctype := mime.TypeByExtension(ext); ctype != "" {
			w.Header().Set("Content-Type", ctype)
		}
		http.ServeFileFS(w, r, sub, filepath.FromSlash(rel))
	})
}

func parseInt(s string, def, min, max int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func readJSON(r *http.Request, dst any) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return errors.New("empty body")
	}
	return json.Unmarshal(data, dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

