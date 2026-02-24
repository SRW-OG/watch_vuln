package web

import (
	"context"
	"io/fs"
	"net/http"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/zema1/watchvuln/ent"
)

type Config struct {
	Listen              string
	UIDir               string
	EmbeddedUI          fs.FS
	DBConn              string
	AdminUsername       string
	AdminPassword       string
	AdminPasswordBcrypt string
	SessionSecret       string
	ConfigPath          string
}

type Server struct {
	cfg    Config
	mu     sync.RWMutex
	db     *ent.Client
	auth   *auth
	server *http.Server
}

func NewServer(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Listen == "" {
		return nil, errors.New("listen is required")
	}
	if cfg.UIDir == "" && cfg.EmbeddedUI == nil {
		return nil, errors.New("ui dir is required")
	}
	if cfg.DBConn == "" {
		return nil, errors.New("db_conn is required")
	}
	if cfg.AdminUsername == "" {
		return nil, errors.New("admin_username is required")
	}
	if cfg.SessionSecret == "" {
		return nil, errors.New("session_secret is required")
	}
	if cfg.AdminPassword == "" && cfg.AdminPasswordBcrypt == "" {
		return nil, errors.New("admin_password or admin_password_bcrypt is required")
	}

	dbClient, err := openEntClient(ctx, cfg.DBConn)
	if err != nil {
		return nil, err
	}

	a, err := newAuth(cfg)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:  cfg,
		db:   dbClient,
		auth: a,
	}
	s.server = &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.routes(),
		ReadTimeout:       time.Second * 10,
		ReadHeaderTimeout: time.Second * 5,
		WriteTimeout:      time.Second * 30,
		IdleTimeout:       time.Second * 60,
	}
	return s, nil
}

func (s *Server) Close(ctx context.Context) error {
	if s.server != nil {
		_ = s.server.Shutdown(ctx)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Server) ListenAndServe() error {
	return s.server.ListenAndServe()
}

func (s *Server) currentDB() *ent.Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db
}

func (s *Server) currentAuth() *auth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auth
}

func (s *Server) currentUIDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.UIDir
}

func (s *Server) currentEmbeddedUI() fs.FS {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.EmbeddedUI
}

