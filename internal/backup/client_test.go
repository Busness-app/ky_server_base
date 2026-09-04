package backup_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky_server_base/internal/backup"
)

// recorder answers every request with one canned response and keeps the last request seen.
type recorder struct {
	status int
	body   func(req []byte) string
	last   *http.Request
	sent   []byte
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.last = req
	r.sent, _ = io.ReadAll(req.Body)
	return &http.Response{
		StatusCode: r.status,
		Body:       io.NopCloser(strings.NewReader(r.body(r.sent))),
		Header:     http.Header{},
	}, nil
}

// kyrecovery pins the service name the claim sends and refuses every later deposit whose
// manifest names another, so the claim must carry the same value Seal is given. A claim
// without it pins "generic" and breaks every deposit that follows.
func TestClaimPairingSendsTheServiceName(t *testing.T) {
	priv, _ := recoverykey.Generate()
	pub := base64.StdEncoding.EncodeToString(priv.Public().Bytes())
	rec := &recorder{status: http.StatusOK, body: func([]byte) string {
		return fmt.Sprintf(`{"api_token":"tok","recovery_public_key":%q,"threshold":2,"total_shares":3}`, pub)
	}}
	client := backup.NewClientWithTransportForTest(rec)
	if _, err := client.ClaimPairing(context.Background(), "https://recovery.busnes.app", " 123456 ", "kynotes", "KyNotes US-East"); err != nil {
		t.Fatal(err)
	}
	var sent map[string]string
	if err := json.Unmarshal(rec.sent, &sent); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"pairing_code": "123456", "service_name": "kynotes", "app_name": "KyNotes US-East"}
	for k, v := range want {
		if sent[k] != v {
			t.Errorf("%s: got %q, want %q", k, sent[k], v)
		}
	}
	if rec.last.URL.Path != "/api/pairing/claim" {
		t.Errorf("path: got %s", rec.last.URL.Path)
	}
}

func receiptFor(container []byte, id string) string {
	sum := sha256.Sum256(container)
	return fmt.Sprintf(`{"capsule_id":%q,"digest":%q,"size_bytes":%d,"deposited_at":"2026-09-04T10:00:00Z"}`,
		id, hex.EncodeToString(sum[:]), len(container))
}

func TestDepositSendsTheContainerAsAnOctetStream(t *testing.T) {
	container := []byte("kycap/3 bytes")
	for _, status := range []int{http.StatusCreated, http.StatusOK} {
		rec := &recorder{status: status, body: func(sent []byte) string { return receiptFor(sent, "cap-1") }}
		client := backup.NewClientWithTransportForTest(rec)
		rcpt, err := client.Deposit(context.Background(), "https://recovery.busnes.app/", "kyrec_live_x", container)
		if err != nil {
			t.Fatalf("%d: %v", status, err)
		}
		if rcpt.CapsuleID != "cap-1" || rcpt.SizeBytes != int64(len(container)) {
			t.Errorf("%d: receipt %+v", status, rcpt)
		}
		if got := rec.last.Header.Get("Authorization"); got != "Bearer kyrec_live_x" {
			t.Errorf("authorization: got %q", got)
		}
		if got := rec.last.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("content-type: got %q", got)
		}
		if rec.last.URL.Path != "/api/backup/deposit" {
			t.Errorf("path: got %s", rec.last.URL.Path)
		}
		if string(rec.sent) != string(container) {
			t.Error("body is not the container byte for byte")
		}
	}
}

// A receipt is only proof of a deposit when it describes the bytes that were sent.
func TestDepositRefusesAReceiptForOtherBytes(t *testing.T) {
	container := []byte("kycap/3 bytes")
	for name, body := range map[string]func([]byte) string{
		"wrong digest": func([]byte) string { return receiptFor([]byte("other"), "cap-1") },
		"wrong size": func(sent []byte) string {
			return strings.Replace(receiptFor(sent, "cap-1"), fmt.Sprintf(`"size_bytes":%d`, len(sent)), `"size_bytes":1`, 1)
		},
		"no capsule id": func(sent []byte) string { return receiptFor(sent, "") },
	} {
		client := backup.NewClientWithTransportForTest(&recorder{status: http.StatusCreated, body: body})
		if _, err := client.Deposit(context.Background(), "https://recovery.busnes.app", "tok", container); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDepositReportsARefusal(t *testing.T) {
	client := backup.NewClientWithTransportForTest(&recorder{status: http.StatusForbidden, body: func([]byte) string { return `{"error":"service mismatch"}` }})
	_, err := client.Deposit(context.Background(), "https://recovery.busnes.app", "tok", []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "service mismatch") {
		t.Fatalf("got %v, want the status and the server's message", err)
	}
}

func TestDepositRefusesAnUnsafeURL(t *testing.T) {
	client := backup.NewClientWithTransportForTest(&recorder{status: http.StatusCreated, body: func(sent []byte) string { return receiptFor(sent, "c") }})
	for _, u := range []string{"http://recovery.busnes.app", "https://127.0.0.1:8095", "https://10.0.0.5", "https://user:pw@recovery.busnes.app"} {
		if _, err := client.Deposit(context.Background(), u, "tok", []byte("x")); err == nil {
			t.Errorf("%s: accepted", u)
		}
	}
}
