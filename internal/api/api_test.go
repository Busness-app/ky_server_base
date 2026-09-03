package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/password"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky-primitives/totp"
	"github.com/Busness-app/ky_server_base/internal/api"
	"github.com/Busness-app/ky_server_base/internal/auth"
	"github.com/Busness-app/ky_server_base/internal/backup"
	"github.com/Busness-app/ky_server_base/internal/config"
	"github.com/Busness-app/ky_server_base/internal/crypto"
	"github.com/Busness-app/ky_server_base/internal/store"
	"github.com/Busness-app/ky_server_base/internal/testdb"
)

func setupTestServer(t *testing.T) (*api.Server, store.Store, *config.Config) {
	t.Helper()
	t.Setenv("KY_DATA_DIR", t.TempDir())
	cfg, _ := config.LoadFromEnv()
	db := testdb.Config(t)
	db.DataDir = cfg.Database.DataDir // testdb only picks the backend; keep the temp data dir
	cfg.Database = db
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
	passHash, _ := password.Hash("SuperSecretPass123!")
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

func TestLoginRejectsUnparseableStoredHash(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	_ = st.Users().CreateUser(context.Background(), &store.User{
		ID: "usr_bad", Username: "bad", PasswordHash: "not-a-phc-string",
		Role: "user", Status: "active", SSOProvider: "local",
	})
	body, _ := json.Marshal(map[string]string{"username": "bad", "password": "whatever-long-enough"})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", w.Code)
	}
}

func TestInactiveAccountInvalidatesSession(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	hash, _ := password.Hash("SuperSecretPass123!")
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

func TestMFATOTPRefusesReplay(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	ctx := context.Background()
	secret, _ := totp.GenerateSecret()
	enc, _ := crypto.EncryptAESGCM([]byte(secret), cfg.Security.EncryptionKey)
	_ = st.Users().CreateUser(ctx, &store.User{
		ID: "usr_mfa", Username: "mfa", Role: "user", Status: "active", SSOProvider: "local",
		TOTPEnabled: true, TOTPSecretEnc: enc,
	})
	code, _ := totp.Code(secret, time.Now())

	post := func() int {
		raw := crypto.RandomHex(32)
		_ = st.Sessions().CreateMFAChallenge(ctx, &store.MFAChallenge{
			TokenHash: crypto.SHA256Hex([]byte(raw)), UserID: "usr_mfa", ExpiresAt: time.Now().Add(time.Minute),
		})
		body, _ := json.Marshal(map[string]string{"mfa_token": raw, "code": code})
		req := httptest.NewRequest("POST", "/api/auth/mfa/totp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w.Code
	}
	if got := post(); got != http.StatusOK {
		t.Fatalf("first use: %d", got)
	}
	if got := post(); got != http.StatusUnauthorized {
		t.Fatalf("replay: got %d, want 401", got)
	}
}

// fakePairer stands in for KyRecovery: the real client refuses non-HTTPS and private hosts,
// so there is no way to exercise the pairing handler against a test server.
type fakePairer struct {
	result backup.PairingResult
}

func (f fakePairer) ClaimPairing(ctx context.Context, serverURL, pairingCode, appName string) (backup.PairingResult, error) {
	return f.result, nil
}

func TestPairRemoteStoresTheRecoveryKey(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	api.SetRecoveryClientForTest(srv, fakePairer{result: backup.PairingResult{
		APIToken: "tok_pair",
		Key:      backup.RecoveryKey{Public: pub, Threshold: 2, TotalShares: 3},
	}})

	body, _ := json.Marshal(map[string]string{
		"recovery_url": "https://recovery.busnes.app",
		"pairing_code": "123456",
	})
	req := httptest.NewRequest("POST", "/api/backup/pair-remote", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	cookie := loginAs(t, srv, st, "alice", "admin")
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "test-csrf"})
	req.Header.Set(auth.HeaderCSRF, "test-csrf")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("pair: got %d: %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["recovery_key_id"] != pub.ID() {
		t.Errorf("recovery_key_id: got %v, want %s", out["recovery_key_id"], pub.ID())
	}

	got, err := backup.LoadRecoveryKey(context.Background(), cfg.Database.DataDir, st.Settings())
	if err != nil {
		t.Fatalf("load pinned key: %v", err)
	}
	if got.Public.ID() != pub.ID() || got.Threshold != 2 || got.TotalShares != 3 {
		t.Errorf("pinned key: got %+v", got)
	}

	// Pairing again to a different key must not silently re-point the product.
	other, _ := recoverykey.Generate()
	api.SetRecoveryClientForTest(srv, fakePairer{result: backup.PairingResult{
		APIToken: "tok_pair2",
		Key:      backup.RecoveryKey{Public: other.Public(), Threshold: 2, TotalShares: 3},
	}})
	req2 := httptest.NewRequest("POST", "/api/backup/pair-remote", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(cookie)
	req2.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "test-csrf"})
	req2.Header.Set(auth.HeaderCSRF, "test-csrf")
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("re-pair to a different key: got %d, want 409: %s", w2.Code, w2.Body.String())
	}
}

// A recovery.pub swapped under a live instance must stop the export, not produce a capsule
// sealed to a key the suite's custodians cannot open.
func TestExportCapsuleRefusesAMismatchedRecoveryKey(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	ctx := context.Background()

	pinned, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.StoreRecoveryKey(ctx, cfg.Database.DataDir, st.Settings(),
		backup.RecoveryKey{Public: pinned.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}

	// Swap the file for a different key, leaving the settings pin on the first one.
	other, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := backup.RecoveryKeyPath(cfg.Database.DataDir)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Store(path, other.Public().Bytes(), keyfile.Raw); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/backup/export-capsule", nil)
	req.AddCookie(loginAs(t, srv, st, "alice", "admin"))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("export with a swapped recovery.pub: got %d, want 409: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "pinned key ID") {
		t.Errorf("body does not name the condition: %s", w.Body.String())
	}
}
