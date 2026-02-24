package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookieName = "watchvuln_session"

type auth struct {
	adminUsername string
	adminPassword string
	adminBcrypt   string
	secret        []byte
}

type sessionPayload struct {
	U   string `json:"u"`
	Exp int64  `json:"exp"`
}

func newAuth(cfg Config) (*auth, error) {
	return &auth{
		adminUsername: cfg.AdminUsername,
		adminPassword: cfg.AdminPassword,
		adminBcrypt:   cfg.AdminPasswordBcrypt,
		secret:        []byte(cfg.SessionSecret),
	}, nil
}

func (a *auth) checkCredentials(username, password string) bool {
	if username != a.adminUsername {
		return false
	}
	if a.adminBcrypt != "" {
		return bcrypt.CompareHashAndPassword([]byte(a.adminBcrypt), []byte(password)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(a.adminPassword), []byte(password)) == 1
}

func (a *auth) issueSession(username string, ttl time.Duration) (string, error) {
	p := sessionPayload{
		U:   username,
		Exp: time.Now().Add(ttl).Unix(),
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sig := a.sign(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (a *auth) parseSession(token string) (*sessionPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid session token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid session token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid session token")
	}
	want := a.sign(payload)
	if !hmac.Equal(sig, want) {
		return nil, errors.New("invalid session token")
	}
	var p sessionPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, errors.New("invalid session token")
	}
	if p.Exp <= time.Now().Unix() {
		return nil, errors.New("session expired")
	}
	if p.U == "" {
		return nil, errors.New("invalid session token")
	}
	return &p, nil
}

func (a *auth) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func (a *auth) setSessionCookie(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
	})
}

func (a *auth) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

