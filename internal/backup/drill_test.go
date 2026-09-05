package backup_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky_server_base/internal/backup"
)

func TestChecksFailsOnAScratchDirMissingTheDatabase(t *testing.T) {
	cfg, _ := payloadConfig(t)
	payload, err := backup.Collect(context.Background(), cfg, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	scratch := t.TempDir()
	// Recreate every required file except the database, so the missing member is the only
	// difference from a real drill's scratch directory.
	for _, f := range payload.Files {
		if f.Path == "data/ky_server.db" {
			continue
		}
		full := filepath.Join(scratch, f.Path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, f.Data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	checks := backup.Checks(cfg, payload)(scratch)
	var sawMissing bool
	for _, c := range checks {
		if c.Name == "Required File: data/ky_server.db" {
			sawMissing = true
			if c.Passed {
				t.Error("missing database reported as passed")
			}
		}
		if c.Passed && c.Name == "Required Files" {
			t.Error("Required Files reported all-present with the database missing")
		}
	}
	if !sawMissing {
		t.Fatal("no check reported the missing database member")
	}
}

func TestChecksPassesOnACompleteScratchDir(t *testing.T) {
	t.Setenv("KY_PORT", "8080")
	t.Setenv("KY_DB_DRIVER", "sqlite")
	cfg, _ := payloadConfig(t)
	payload, err := backup.Collect(context.Background(), cfg, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	for _, f := range payload.Files {
		full := filepath.Join(scratch, f.Path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, f.Data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	checks := backup.Checks(cfg, payload)(scratch)
	if len(checks) == 0 {
		t.Fatal("no checks ran")
	}
	for _, c := range checks {
		if !c.Passed {
			t.Errorf("check %q failed: %s", c.Name, c.Message)
		}
	}
}

func TestDrillRootIsUnderTheDataDir(t *testing.T) {
	cfg, _ := payloadConfig(t)
	root := backup.DrillRoot(cfg)
	rel, err := filepath.Rel(cfg.Database.DataDir, root)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("drill root %q is not under data dir %q", root, cfg.Database.DataDir)
	}
}
