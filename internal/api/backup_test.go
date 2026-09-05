package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky_server_base/internal/api"
	"github.com/Busness-app/ky_server_base/internal/auth"
	"github.com/Busness-app/ky_server_base/internal/store"
)

// adminDo is adminPost with a method and a JSON body.
func adminDo(t *testing.T, srv *api.Server, session *http.Cookie, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(session)
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "test-csrf"})
	req.Header.Set(auth.HeaderCSRF, "test-csrf")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func pinBody(pub recoverykey.PublicKey, k, n int) map[string]any {
	return map[string]any{"public_key": base64.StdEncoding.EncodeToString(pub.Bytes()), "threshold": k, "total_shares": n}
}

func statusOf(t *testing.T, srv *api.Server, session *http.Cookie) map[string]any {
	t.Helper()
	w := adminDo(t, srv, session, "GET", "/api/backup/status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d: %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func auditRows(t *testing.T, st store.Store, action string) []*store.AuditRecord {
	t.Helper()
	records, _, err := st.Audit().ListAuditRecords(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []*store.AuditRecord
	for _, rec := range records {
		if rec.Action == action {
			out = append(out, rec)
		}
	}
	return out
}

func TestPinKeyIsWriteOnce(t *testing.T) {
	srv, st, _ := setupSQLiteServer(t)
	session := loginAs(t, srv, st, "alice", "admin")
	first, _ := recoverykey.Generate()
	if w := adminDo(t, srv, session, "POST", "/api/backup/pin-key", pinBody(first.Public(), 2, 3)); w.Code != http.StatusOK {
		t.Fatalf("pin: got %d: %s", w.Code, w.Body.String())
	}
	if w := adminDo(t, srv, session, "POST", "/api/backup/pin-key", pinBody(first.Public(), 2, 3)); w.Code != http.StatusOK {
		t.Fatalf("same key again: got %d: %s", w.Code, w.Body.String())
	}
	other, _ := recoverykey.Generate()
	if w := adminDo(t, srv, session, "POST", "/api/backup/pin-key", pinBody(other.Public(), 2, 3)); w.Code != http.StatusConflict {
		t.Fatalf("different key: got %d, want 409: %s", w.Code, w.Body.String())
	}
	var pinned, refused bool
	for _, rec := range auditRows(t, st, "admin.backup_key_pin") {
		switch {
		case rec.Resource == first.Public().ID() && strings.HasPrefix(rec.Details, "threshold=2"):
			pinned = true
		case rec.Resource == other.Public().ID() && strings.HasPrefix(rec.Details, "error="):
			refused = true
		}
	}
	if !pinned || !refused {
		t.Fatalf("pin audit rows: pinned=%v refused=%v", pinned, refused)
	}
	status := statusOf(t, srv, session)
	if status["key_pinned"] != true || status["recovery_key_id"] != first.Public().ID() {
		t.Errorf("status after pin: %v", status)
	}
}

func TestPinKeyBadTopology(t *testing.T) {
	srv, st, _ := setupSQLiteServer(t)
	session := loginAs(t, srv, st, "alice", "admin")
	priv, _ := recoverykey.Generate()
	if w := adminDo(t, srv, session, "POST", "/api/backup/pin-key", pinBody(priv.Public(), 1, 3)); w.Code != http.StatusBadRequest {
		t.Fatalf("1-of-3: got %d, want 400: %s", w.Code, w.Body.String())
	}
	if w := adminDo(t, srv, session, "POST", "/api/backup/pin-key", map[string]any{"public_key": "AAAA", "threshold": 2, "total_shares": 3}); w.Code != http.StatusBadRequest {
		t.Fatalf("garbage key: got %d, want 400: %s", w.Code, w.Body.String())
	}
	if statusOf(t, srv, session)["key_pinned"] != false {
		t.Error("a refused pin left a key behind")
	}
}

func TestRunWithPinnedKeyAndNoDestination(t *testing.T) {
	srv, st, cfg := setupSQLiteServer(t)
	cfg.Backup.Dir = ""
	fake := &fakeDepositor{}
	api.SetRecoveryClientForTest(srv, fake)
	session := loginAs(t, srv, st, "alice", "admin")
	priv, _ := recoverykey.Generate()
	if w := adminDo(t, srv, session, "POST", "/api/backup/pin-key", pinBody(priv.Public(), 2, 3)); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	w := adminPost(t, srv, session, "/api/backup/deposit")
	if w.Code != http.StatusPreconditionFailed || !strings.Contains(w.Body.String(), "pair with KyRecovery or set KY_BACKUP_DIR") {
		t.Fatalf("no destination: got %d: %s", w.Code, w.Body.String())
	}
	if fake.got != nil {
		t.Error("an unpaired instance sent bytes to the store")
	}
}

func TestRunWritesLocalCopy0600(t *testing.T) {
	srv, st, cfg := setupSQLiteServer(t)
	cfg.Backup.Dir = filepath.Join(t.TempDir(), "capsules")
	cfg.Backup.Keep = 3
	fake := &fakeDepositor{}
	api.SetRecoveryClientForTest(srv, fake)
	session := loginAs(t, srv, st, "alice", "admin")
	priv, _ := recoverykey.Generate()
	if w := adminDo(t, srv, session, "POST", "/api/backup/pin-key", pinBody(priv.Public(), 2, 3)); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	w := adminPost(t, srv, session, "/api/backup/deposit")
	if w.Code != http.StatusOK {
		t.Fatalf("run: got %d: %s", w.Code, w.Body.String())
	}
	var res recoveryclient.Result
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Receipt != nil || res.LocalPath == "" || fake.got != nil {
		t.Fatalf("unpaired run %+v sent=%v", res, fake.got != nil)
	}
	info, err := os.Stat(res.LocalPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("local copy mode %o, want 0600", info.Mode().Perm())
	}
	if filepath.Dir(res.LocalPath) != cfg.Backup.Dir || !strings.HasSuffix(res.LocalPath, "."+res.Manifest.CapsuleID+".kycap") {
		t.Errorf("local copy path %q", res.LocalPath)
	}
	raw, _ := os.ReadFile(res.LocalPath)
	if _, files, err := capsule.Open(raw, priv, t.TempDir()); err != nil || len(files) < 2 {
		t.Fatalf("local copy does not open with the suite key: %v (%d files)", err, len(files))
	}
	var ok bool
	for _, rec := range auditRows(t, st, "admin.backup_run") {
		if rec.UserID == "usr_alice" && rec.Resource == res.Manifest.CapsuleID && strings.Contains(rec.Details, "outcome=success") && strings.Contains(rec.Details, "local_path=") {
			ok = true
		}
	}
	if !ok {
		t.Error("no successful admin.backup_run row naming the local copy")
	}
	status := statusOf(t, srv, session)
	copies, _ := status["local_copies"].([]any)
	if status["paired"] != false || status["key_pinned"] != true || len(copies) != 1 || status["local_dir"] != cfg.Backup.Dir {
		t.Errorf("status %v", status)
	}
}

func TestUnpairKeepsPin(t *testing.T) {
	srv, st, _ := setupSQLiteServer(t)
	priv, _ := recoverykey.Generate()
	api.SetRecoveryClientForTest(srv, fakePairer{result: recoveryclient.PairingResult{
		APIToken: "kyrec_live_t",
		Key:      recoveryclient.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3},
	}})
	session := loginAs(t, srv, st, "alice", "admin")
	pair := map[string]string{"recovery_url": "https://recovery.busnes.app", "pairing_code": "123456"}
	if w := adminDo(t, srv, session, "POST", "/api/backup/pair-remote", pair); w.Code != http.StatusOK {
		t.Fatalf("pair: got %d: %s", w.Code, w.Body.String())
	}
	if status := statusOf(t, srv, session); status["paired"] != true || status["recovery_url"] != pair["recovery_url"] {
		t.Fatalf("status after pair: %v", status)
	}
	w := adminDo(t, srv, session, "DELETE", "/api/backup/pairing", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("unpair: got %d: %s", w.Code, w.Body.String())
	}
	status := statusOf(t, srv, session)
	if status["paired"] != false || status["key_pinned"] != true || status["recovery_key_id"] != priv.Public().ID() {
		t.Errorf("unpair changed the pin: %v", status)
	}
	if _, has := status["recovery_url"]; has {
		t.Errorf("unpair left the URL row: %v", status)
	}
	rows := auditRows(t, st, "admin.backup_unpair")
	if len(rows) != 1 || rows[0].Resource != pair["recovery_url"] || rows[0].Details != "success" {
		t.Errorf("unpair audit: %+v", rows)
	}
	if w := adminDo(t, srv, session, "DELETE", "/api/backup/pairing", nil); w.Code != http.StatusPreconditionFailed {
		t.Fatalf("second unpair: got %d, want 412: %s", w.Code, w.Body.String())
	}
}

func TestScheduleBounds(t *testing.T) {
	srv, st, _ := setupSQLiteServer(t)
	session := loginAs(t, srv, st, "alice", "admin")
	for _, tc := range []struct {
		sec  int64
		want int
	}{{0, 200}, {899, 400}, {1 << 55, 400}, {900, 200}} {
		w := adminDo(t, srv, session, "PUT", "/api/backup/schedule", map[string]int64{"interval_sec": tc.sec})
		if w.Code != tc.want {
			t.Errorf("interval %d: got %d, want %d: %s", tc.sec, w.Code, tc.want, w.Body.String())
		}
	}
	if status := statusOf(t, srv, session); status["interval_sec"] != float64(900) || status["min_interval_sec"] != float64(900) {
		t.Errorf("status schedule: %v", status)
	}
	rows := auditRows(t, st, "admin.backup_schedule")
	if len(rows) != 2 || rows[0].Details != "interval_sec=900" || rows[1].Details != "interval_sec=0" {
		t.Errorf("schedule audit: %+v", rows)
	}
}

func TestStatusNeverCarriesToken(t *testing.T) {
	srv, st, cfg := setupSQLiteServer(t)
	priv, _ := recoverykey.Generate()
	ctx := context.Background()
	if err := recoveryclient.StoreRecoveryKey(cfg.Database.DataDir, backupSettings(ctx, st), recoveryclient.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	if err := storePairing(t, cfg, st, "https://recovery.busnes.app", "kyrec_live_secret"); err != nil {
		t.Fatal(err)
	}
	session := loginAs(t, srv, st, "alice", "admin")
	w := adminDo(t, srv, session, "GET", "/api/backup/status", nil)
	body := strings.ToLower(w.Body.String())
	if w.Code != http.StatusOK || strings.Contains(body, "kyrec_live_secret") || strings.Contains(body, "token") {
		t.Fatalf("status carries the credential: %d %s", w.Code, w.Body.String())
	}
	var status map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &status)
	if status["paired"] != true || status["key_pinned"] != true {
		t.Errorf("status %v", status)
	}
}

// A session without the CSRF header stops at the middleware. With no key pinned, the handler
// itself would answer 412, so 403 proves it never ran.
func TestExportCapsuleRequiresCSRF(t *testing.T) {
	srv, st, _ := setupSQLiteServer(t)
	req := httptest.NewRequest("POST", "/api/backup/export-capsule", nil)
	req.AddCookie(loginAs(t, srv, st, "alice", "admin"))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || w.Header().Get("Content-Disposition") != "" {
		t.Fatalf("export without CSRF: got %d %q", w.Code, w.Header().Get("Content-Disposition"))
	}
}

// The SPA catch-all may answer a wrong-method request, so the property pinned is that no
// method but POST produces a capsule attachment.
func TestExportCapsuleOnlyPOST(t *testing.T) {
	srv, st, cfg := setupSQLiteServer(t)
	priv, _ := recoverykey.Generate()
	if err := recoveryclient.StoreRecoveryKey(cfg.Database.DataDir, backupSettings(context.Background(), st), recoveryclient.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	session := loginAs(t, srv, st, "alice", "admin")
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		w := adminDo(t, srv, session, method, "/api/backup/export-capsule", nil)
		if w.Header().Get("Content-Disposition") != "" || w.Header().Get("X-Recovery-Key-ID") != "" || w.Header().Get("Content-Type") == "application/octet-stream" {
			t.Errorf("%s produced a capsule: %d %v", method, w.Code, w.Header())
		}
	}
	w := adminPost(t, srv, session, "/api/backup/export-capsule")
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment;") {
		t.Fatalf("POST export: got %d %v", w.Code, w.Header())
	}
}
