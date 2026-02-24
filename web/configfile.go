package web

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

const secretPlaceholder = "********"

type FileConfig struct {
	DBConn          string              `yaml:"db_conn" json:"db_conn"`
	Sources         []string            `yaml:"sources" json:"sources"`
	Interval        string              `yaml:"interval" json:"interval"`
	EnableCVEFilter *bool               `yaml:"enable_cve_filter" json:"enable_cve_filter"`
	NoGithubSearch  *bool               `yaml:"no_github_search" json:"no_github_search"`
	NoStartMessage  *bool               `yaml:"no_start_message" json:"no_start_message"`
	NoSleep         *bool               `yaml:"no_sleep" json:"no_sleep"`
	DiffMode        *bool               `yaml:"diff_mode" json:"diff_mode"`
	WhiteKeywords   []string            `yaml:"white_keywords" json:"white_keywords"`
	BlackKeywords   []string            `yaml:"black_keywords" json:"black_keywords"`
	Pusher          []map[string]string `yaml:"pusher" json:"pusher"`
	Proxy           string              `yaml:"proxy" json:"proxy"`
	SkipTLSVerify   bool                `yaml:"skip_tls_verify" json:"skip_tls_verify"`
	Test            bool                `yaml:"test" json:"test"`

	WebListen           string `yaml:"web_listen" json:"web_listen"`
	WebUIDir            string `yaml:"web_ui_dir" json:"web_ui_dir"`
	AdminUsername       string `yaml:"admin_username" json:"admin_username"`
	AdminPassword       string `yaml:"admin_password" json:"admin_password"`
	AdminPasswordBcrypt string `yaml:"admin_password_bcrypt" json:"admin_password_bcrypt"`
	SessionSecret       string `yaml:"session_secret" json:"session_secret"`
}

func readConfigFile(path string) (*FileConfig, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var cfg FileConfig
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, "", err
		}
		return &cfg, "json", nil
	case ".yaml", ".yml", "":
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, "", err
		}
		return &cfg, "yaml", nil
	default:
		return nil, "", errors.Errorf("unsupported config file extension: %s", ext)
	}
}

func (c *FileConfig) marshal(format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(c, "", "  ")
	case "yaml":
		return yaml.Marshal(c)
	default:
		return nil, errors.Errorf("unsupported format: %s", format)
	}
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp := filepath.Join(dir, "."+base+".tmp")
	bak := filepath.Join(dir, "."+base+".bak")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	_ = os.Remove(bak)
	if err := os.Rename(path, bak); err != nil {
		if !os.IsNotExist(err) {
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		_ = os.Rename(bak, path)
		return err
	}
	_ = os.Remove(bak)
	return nil
}

func (c *FileConfig) redacted() *FileConfig {
	cp := *c
	cp.DBConn = redactDBConn(cp.DBConn)
	if cp.AdminPassword != "" {
		cp.AdminPassword = secretPlaceholder
	}
	if cp.AdminPasswordBcrypt != "" {
		cp.AdminPasswordBcrypt = secretPlaceholder
	}
	if cp.SessionSecret != "" {
		cp.SessionSecret = secretPlaceholder
	}

	if len(cp.Pusher) != 0 {
		secretKeys := map[string]struct{}{
			"access_token": {},
			"sign_secret":  {},
			"key":          {},
			"url":          {},
			"token":        {},
			"bot_token":    {},
			"chat_ids":     {},
			"webhook_url":  {},
			"domain":       {},
			"group_chat":   {},
		}
		for i := range cp.Pusher {
			if cp.Pusher[i] == nil {
				continue
			}
			for k := range cp.Pusher[i] {
				if _, ok := secretKeys[k]; !ok {
					continue
				}
				if strings.TrimSpace(cp.Pusher[i][k]) != "" {
					cp.Pusher[i][k] = secretPlaceholder
				}
			}
		}
	}
	return &cp
}

func mergeSecrets(newCfg, oldCfg *FileConfig) *FileConfig {
	if oldCfg == nil {
		return newCfg
	}
	cp := *newCfg
	if keepSecret(cp.AdminPassword) {
		cp.AdminPassword = oldCfg.AdminPassword
	}
	if keepSecret(cp.AdminPasswordBcrypt) {
		cp.AdminPasswordBcrypt = oldCfg.AdminPasswordBcrypt
	}
	if keepSecret(cp.SessionSecret) {
		cp.SessionSecret = oldCfg.SessionSecret
	}
	if keepSecret(cp.DBConn) {
		cp.DBConn = oldCfg.DBConn
	}

	if len(cp.Pusher) != 0 && len(oldCfg.Pusher) != 0 {
		secretKeys := map[string]struct{}{
			"access_token": {},
			"sign_secret":  {},
			"key":          {},
			"url":          {},
			"token":        {},
			"bot_token":    {},
			"chat_ids":     {},
			"webhook_url":  {},
			"domain":       {},
			"group_chat":   {},
		}
		n := len(cp.Pusher)
		if len(oldCfg.Pusher) < n {
			n = len(oldCfg.Pusher)
		}
		for i := 0; i < n; i++ {
			if cp.Pusher[i] == nil || oldCfg.Pusher[i] == nil {
				continue
			}
			if strings.TrimSpace(cp.Pusher[i]["type"]) != strings.TrimSpace(oldCfg.Pusher[i]["type"]) {
				continue
			}
			for k := range oldCfg.Pusher[i] {
				if _, ok := secretKeys[k]; !ok {
					continue
				}
				if keepSecret(cp.Pusher[i][k]) {
					cp.Pusher[i][k] = oldCfg.Pusher[i][k]
				}
			}
		}
	}
	return &cp
}

func keepSecret(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" || v == secretPlaceholder || strings.Contains(v, secretPlaceholder)
}

func redactDBConn(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	u, err := url.Parse(v)
	if err != nil {
		return v
	}
	if u.User == nil {
		return v
	}
	if _, has := u.User.Password(); !has {
		return v
	}
	u.User = url.UserPassword(u.User.Username(), secretPlaceholder)
	return u.String()
}

