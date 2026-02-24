package web

import (
	"context"
	"strings"
	"time"

	entSql "entgo.io/ent/dialect/sql"
	"github.com/pkg/errors"

	"github.com/zema1/watchvuln/ctrl"
	"github.com/zema1/watchvuln/ent"
)

type ApplyResult struct {
	Applied           bool `json:"applied"`
	DBReconnected     bool `json:"db_reconnected"`
	AuthUpdated       bool `json:"auth_updated"`
	UIDirUpdated      bool `json:"ui_dir_updated"`
	RequiresRestart   bool `json:"requires_restart"`
	RequiresRelogin   bool `json:"requires_relogin"`
	WebListenIgnored  bool `json:"web_listen_ignored"`
}

func (s *Server) applyRuntimeConfig(ctx context.Context, fc *FileConfig) (*ApplyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := &ApplyResult{}

	if strings.TrimSpace(fc.WebListen) != "" && strings.TrimSpace(fc.WebListen) != strings.TrimSpace(s.cfg.Listen) {
		res.RequiresRestart = true
		res.WebListenIgnored = true
	}

	if strings.TrimSpace(fc.WebUIDir) != "" && strings.TrimSpace(fc.WebUIDir) != strings.TrimSpace(s.cfg.UIDir) {
		s.cfg.UIDir = strings.TrimSpace(fc.WebUIDir)
		res.UIDirUpdated = true
		res.Applied = true
	}

	newDBConn := strings.TrimSpace(fc.DBConn)
	if keepSecret(newDBConn) || newDBConn == "" {
		newDBConn = s.cfg.DBConn
	}
	if strings.TrimSpace(newDBConn) != "" && strings.TrimSpace(newDBConn) != strings.TrimSpace(s.cfg.DBConn) {
		dbClient, err := openEntClient(ctx, newDBConn)
		if err != nil {
			return nil, err
		}
		old := s.db
		s.db = dbClient
		s.cfg.DBConn = newDBConn
		res.DBReconnected = true
		res.Applied = true
		if old != nil {
			_ = old.Close()
		}
	}

	newAdminUsername := strings.TrimSpace(fc.AdminUsername)
	if newAdminUsername == "" {
		newAdminUsername = s.cfg.AdminUsername
	}

	newSessionSecret := strings.TrimSpace(fc.SessionSecret)
	if keepSecret(newSessionSecret) || newSessionSecret == "" {
		newSessionSecret = s.cfg.SessionSecret
	}

	newAdminPassword := strings.TrimSpace(fc.AdminPassword)
	if keepSecret(newAdminPassword) || newAdminPassword == "" {
		newAdminPassword = s.cfg.AdminPassword
	}
	newAdminBcrypt := strings.TrimSpace(fc.AdminPasswordBcrypt)
	if keepSecret(newAdminBcrypt) || newAdminBcrypt == "" {
		newAdminBcrypt = s.cfg.AdminPasswordBcrypt
	}

	authChanged := false
	if newAdminUsername != s.cfg.AdminUsername {
		authChanged = true
	}
	if newSessionSecret != s.cfg.SessionSecret {
		authChanged = true
		res.RequiresRelogin = true
	}
	if newAdminPassword != s.cfg.AdminPassword {
		authChanged = true
	}
	if newAdminBcrypt != s.cfg.AdminPasswordBcrypt {
		authChanged = true
	}

	if authChanged {
		nextCfg := s.cfg
		nextCfg.AdminUsername = newAdminUsername
		nextCfg.SessionSecret = newSessionSecret
		nextCfg.AdminPassword = newAdminPassword
		nextCfg.AdminPasswordBcrypt = newAdminBcrypt
		if strings.TrimSpace(nextCfg.AdminPassword) == "" && strings.TrimSpace(nextCfg.AdminPasswordBcrypt) == "" {
			return nil, errors.New("refuse to apply empty admin password")
		}
		a, err := newAuth(nextCfg)
		if err != nil {
			return nil, err
		}
		s.auth = a
		s.cfg.AdminUsername = newAdminUsername
		s.cfg.SessionSecret = newSessionSecret
		s.cfg.AdminPassword = newAdminPassword
		s.cfg.AdminPasswordBcrypt = newAdminBcrypt
		res.AuthUpdated = true
		res.Applied = true
	}

	return res, nil
}

func openEntClient(ctx context.Context, dbConn string) (*ent.Client, error) {
	appCfg := &ctrl.WatchVulnAppConfig{DBConn: dbConn}
	drvName, connStr, err := appCfg.DBConnForEnt()
	if err != nil {
		return nil, err
	}
	drv, err := entSql.Open(drvName, connStr)
	if err != nil {
		return nil, errors.Wrap(err, "failed opening connection to db")
	}
	db := drv.DB()
	db.SetMaxOpenConns(5)
	db.SetConnMaxLifetime(time.Minute)
	db.SetMaxIdleConns(5)

	dbClient := ent.NewClient(ent.Driver(drv))
	migrateCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	if err := dbClient.Schema.Create(migrateCtx); err != nil {
		_ = dbClient.Close()
		return nil, errors.Wrap(err, "failed creating schema resources")
	}
	return dbClient, nil
}

