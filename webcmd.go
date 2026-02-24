package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"github.com/zema1/watchvuln/web"
)

type webFileConfig struct {
	DBConn              string `yaml:"db_conn" json:"db_conn"`
	WebListen           string `yaml:"web_listen" json:"web_listen"`
	UIDir               string `yaml:"web_ui_dir" json:"web_ui_dir"`
	AdminUsername       string `yaml:"admin_username" json:"admin_username"`
	AdminPassword       string `yaml:"admin_password" json:"admin_password"`
	AdminPasswordBcrypt string `yaml:"admin_password_bcrypt" json:"admin_password_bcrypt"`
	SessionSecret       string `yaml:"session_secret" json:"session_secret"`
}

func webCommand() *cli.Command {
	return &cli.Command{
		Name:  "web",
		Usage: "start web ui and api",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "listen",
				Usage: "listen address, ex: 127.0.0.1:8080",
			},
			&cli.StringFlag{
				Name:  "ui-dir",
				Usage: "ui directory path",
			},
			&cli.StringFlag{
				Name:  "db-conn",
				Usage: "database connection string",
			},
			&cli.StringFlag{
				Name:  "admin-username",
				Usage: "admin username",
			},
			&cli.StringFlag{
				Name:  "admin-password",
				Usage: "admin password",
			},
			&cli.StringFlag{
				Name:  "admin-password-bcrypt",
				Usage: "admin password bcrypt hash",
			},
			&cli.StringFlag{
				Name:  "session-secret",
				Usage: "session signing secret",
			},
		},
		Action: func(c *cli.Context) error {
			ctx, cancel := signalCtx()
			defer cancel()

			cfg := webFileConfig{}
			if c.String("config") != "" {
				fc, err := initWebConfigFromFile(c.String("config"))
				if err != nil {
					return err
				}
				cfg = *fc
			}

			if v := getenvNonEmpty("WEB_LISTEN"); v != "" {
				cfg.WebListen = v
			}
			if v := getenvNonEmpty("WEB_UI_DIR"); v != "" {
				cfg.UIDir = v
			}
			if v := getenvNonEmpty("DB_CONN"); v != "" {
				cfg.DBConn = v
			}
			if v := getenvNonEmpty("ADMIN_USERNAME"); v != "" {
				cfg.AdminUsername = v
			}
			if v := getenvNonEmpty("ADMIN_PASSWORD"); v != "" {
				cfg.AdminPassword = v
			}
			if v := getenvNonEmpty("ADMIN_PASSWORD_BCRYPT"); v != "" {
				cfg.AdminPasswordBcrypt = v
			}
			if v := getenvNonEmpty("SESSION_SECRET"); v != "" {
				cfg.SessionSecret = v
			}

			if c.String("listen") != "" {
				cfg.WebListen = c.String("listen")
			}
			if c.String("ui-dir") != "" {
				cfg.UIDir = c.String("ui-dir")
			}
			if c.String("db-conn") != "" {
				cfg.DBConn = c.String("db-conn")
			}
			if c.String("admin-username") != "" {
				cfg.AdminUsername = c.String("admin-username")
			}
			if c.String("admin-password") != "" {
				cfg.AdminPassword = c.String("admin-password")
			}
			if c.String("admin-password-bcrypt") != "" {
				cfg.AdminPasswordBcrypt = c.String("admin-password-bcrypt")
			}
			if c.String("session-secret") != "" {
				cfg.SessionSecret = c.String("session-secret")
			}

			if cfg.WebListen == "" {
				cfg.WebListen = "127.0.0.1:8080"
			}
			if cfg.UIDir == "" {
				cfg.UIDir = "webui"
			}
			if cfg.DBConn == "" {
				cfg.DBConn = "sqlite3://vuln_v3.sqlite3"
			}

			srv, err := web.NewServer(ctx, web.Config{
				Listen:              cfg.WebListen,
				UIDir:               cfg.UIDir,
				EmbeddedUI:          embeddedWebUIFS(),
				DBConn:              cfg.DBConn,
				AdminUsername:       cfg.AdminUsername,
				AdminPassword:       cfg.AdminPassword,
				AdminPasswordBcrypt: cfg.AdminPasswordBcrypt,
				SessionSecret:       cfg.SessionSecret,
				ConfigPath:          c.String("config"),
			})
			if err != nil {
				return err
			}
			defer func() {
				closeCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()
				_ = srv.Close(closeCtx)
			}()

			errCh := make(chan error, 1)
			go func() {
				errCh <- srv.ListenAndServe()
			}()

			select {
			case <-ctx.Done():
				return ctx.Err()
			case err := <-errCh:
				if errors.Is(err, context.Canceled) {
					return nil
				}
				if errors.Is(err, http.ErrServerClosed) {
					return nil
				}
				return err
			}
		},
	}
}

func initWebConfigFromFile(path string) (*webFileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg webFileConfig
	if strings.HasSuffix(path, ".json") {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
		return &cfg, nil
	}
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
		return &cfg, nil
	}
	return nil, fmt.Errorf("unsupported config file extension: %s", path)
}

func getenvNonEmpty(key string) string {
	v := os.Getenv(key)
	return strings.TrimSpace(v)
}

