package backup_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky_server_base/internal/backup"
	"github.com/Busness-app/ky_server_base/internal/config"
	"github.com/Busness-app/ky_server_base/internal/store"
)

// sqliteInstance is a fresh SQLite store in a temp data dir, the way every backup adapter
// test needs one.
func sqliteInstance(t *testing.T) (*config.Config, store.Store) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Server.AppName = "busnes_app"
	cfg.Server.Port = 8080
	cfg.Database.Driver = "sqlite"
	cfg.Database.DataDir = dir
	cfg.Database.DSN = filepath.Join(dir, "ky_server.db") + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
	cfg.Security.EncryptionKey = bytes.Repeat([]byte{1}, 32)
	st, err := store.Open(context.Background(), cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return cfg, st
}

func TestSettingsAdapterMapsNotFound(t *testing.T) {
	_, st := sqliteInstance(t)
	s := backup.Settings(context.Background(), st.Settings())
	if _, err := s.Get("nope"); !errors.Is(err, recoveryclient.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	_ = s.Set("a", "1")
	if v, _ := s.Get("a"); v != "1" {
		t.Fatal("set/get")
	}
	if err := s.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("a"); !errors.Is(err, recoveryclient.ErrNotFound) {
		t.Fatal("delete")
	}
}

func TestSealerRoundTripUnderDeploymentKey(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.EncryptionKey = bytes.Repeat([]byte{1}, 32)
	s, err := backup.NewSealer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := s.Seal([]byte("tok"))
	p, err := s.Open(c)
	if err != nil || string(p) != "tok" {
		t.Fatal(err)
	}
}
