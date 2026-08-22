package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Yoshiofthewire/ky_server_base/internal/api"
	"github.com/Yoshiofthewire/ky_server_base/internal/auth"
	"github.com/Yoshiofthewire/ky_server_base/internal/config"
	"github.com/Yoshiofthewire/ky_server_base/internal/crypto"
	"github.com/Yoshiofthewire/ky_server_base/internal/store"
	"github.com/Yoshiofthewire/ky_server_base/internal/testdb"
)

func setupTestServer(t *testing.T) (*api.Server, store.Store, *config.Config) {
	t.Helper()
	cfg, _ := config.LoadFromEnv()
	cfg.Database = testdb.Config(t)
	cfg.Captcha.Provider = "none" // disable captcha for unit test speed

	st, err := store.Open(context.Background(), cfg.Database)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := api.NewServer(cfg, st)
	return srv, st, cfg
}

func TestAuthAndSessionEndpoints(t *testing.T) {
	srv, st, _ := setupTestServer(t)

	// Create test user
	passHash, _ := crypto.HashPassword("SuperSecretPass123!")
	user := &store.User{
		ID:           "usr_alice",
		Username:     "alice",
		Email:        "alice@busnes.app",
		DisplayName:  "Alice Admin",
		PasswordHash: passHash,
		Role:         "admin",
		Status:       "active",
		SSOProvider:  "local",
	}
	_ = st.Users().CreateUser(context.Background(), user)

	// 1. Login with correct password
	loginBody, _ := json.Marshal(map[string]string{
		"username": "alice",
		"password": "SuperSecretPass123!",
	})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == auth.SessionCookieName {
			sessionCookie = c
		} else if c.Name == auth.CSRFCookieName {
			csrfCookie = c
			break
		}
	}
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatal("expected session and CSRF cookies in login response")
	}

	// 2. /api/auth/me
	meReq := httptest.NewRequest("GET", "/api/auth/me", nil)
	meReq.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, meReq)

	if w.Code != http.StatusOK {
		t.Fatalf("me expected 200 OK, got %d", w.Code)
	}

	var meResp struct {
		Authenticated bool        `json:"authenticated"`
		User          *store.User `json:"user"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &meResp)
	if !meResp.Authenticated || meResp.User.Username != "alice" {
		t.Errorf("unexpected me response: %+v", meResp)
	}

	// 3. /api/settings
	setReq := httptest.NewRequest("GET", "/api/settings", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, setReq)
	if w.Code != http.StatusOK {
		t.Fatalf("settings expected 200 OK, got %d", w.Code)
	}

	// 4. /api/devices/pair/init
	pairReq := httptest.NewRequest("POST", "/api/devices/pair/init", nil)
	pairReq.AddCookie(sessionCookie)
	pairReq.AddCookie(csrfCookie)
	pairReq.Header.Set(auth.HeaderCSRF, csrfCookie.Value)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, pairReq)
	if w.Code != http.StatusOK {
		t.Fatalf("pair init expected 200 OK, got %d", w.Code)
	}

	// 5. /api/backup/drill
	drillReq := httptest.NewRequest("POST", "/api/backup/drill", nil)
	drillReq.AddCookie(sessionCookie)
	drillReq.AddCookie(csrfCookie)
	drillReq.Header.Set(auth.HeaderCSRF, csrfCookie.Value)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, drillReq)
	if w.Code != http.StatusOK {
		t.Fatalf("backup drill expected 200 OK, got %d", w.Code)
	}
}

func TestInactiveAccountInvalidatesSession(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	hash, _ := crypto.HashPassword("SuperSecretPass123!")
	user := &store.User{ID: "usr_inactive", Username: "inactive", PasswordHash: hash, Role: "admin", Status: "active", SSOProvider: "local"}
	if err := st.Users().CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"username": user.Username, "password": "SuperSecretPass123!"})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body)))
	var session *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == auth.SessionCookieName {
			session = cookie
		}
	}
	user.Status = "inactive"
	if err := st.Users().UpdateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(session)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if !bytes.Contains(w.Body.Bytes(), []byte(`"authenticated":false`)) {
		t.Fatalf("inactive account retained session: %s", w.Body.String())
	}
}

func TestCookieAuthenticatedWriteRequiresCSRF(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	session := loginAs(t, srv, st, "csrf-admin", "admin")
	req := httptest.NewRequest(http.MethodPost, "/api/settings/theme", bytes.NewBufferString(`{"theme":"oled"}`))
	req.AddCookie(session)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("write without CSRF got %d, want 403", w.Code)
	}
}
