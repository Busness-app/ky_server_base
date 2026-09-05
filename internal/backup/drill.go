package backup

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky_server_base/internal/config"
	_ "modernc.org/sqlite"
)

// Checks are the scaffold's assertions on an opened capsule: every required member is
// present, each SQLite member passes integrity_check, and the recipe's environment names
// are set. They see only the scratch directory the lib opened the capsule into.
func Checks(cfg *config.Config, payload recoveryclient.Payload) func(dir string) []recoveryclient.Check {
	return func(dir string) []recoveryclient.Check {
		var checks []recoveryclient.Check
		recipe := payload.VerificationRecipe
		if recipe == nil {
			recipe = map[string]any{}
		}

		// 1. Required files
		if reqFiles, ok := recipe["required_files"].([]string); ok {
			allFound := true
			for _, pathStr := range reqFiles {
				fullPath, safe := drillPath(dir, pathStr)
				if !safe {
					allFound = false
					checks = append(checks, recoveryclient.Check{Name: "Required File: " + pathStr, Passed: false, Message: "Unsafe path"})
					continue
				}
				fi, err := os.Stat(fullPath)
				if err != nil || fi.Size() == 0 {
					allFound = false
					checks = append(checks, recoveryclient.Check{Name: "Required File: " + pathStr, Passed: false, Message: "File missing or empty"})
				}
			}
			if allFound && len(reqFiles) > 0 {
				checks = append(checks, recoveryclient.Check{Name: "Required Files", Passed: true,
					Message: fmt.Sprintf("All %d required files verified", len(reqFiles))})
			}
		}

		// 2. SQLite integrity
		if checkSQLite, _ := recipe["check_sqlite_integrity"].(bool); checkSQLite {
			if sqlitePaths, ok := recipe["sqlite_paths"].([]string); ok {
				for _, dbPathRel := range sqlitePaths {
					dbPathFull, safe := drillPath(dir, dbPathRel)
					if !safe {
						checks = append(checks, recoveryclient.Check{Name: "SQLite Integrity: " + dbPathRel, Passed: false, Message: "Unsafe path"})
						continue
					}
					checks = append(checks, sqliteIntegrityCheck(dbPathRel, dbPathFull))
				}
			}
		}

		// 3. Environment variables
		if expEnv, ok := recipe["expected_env"].([]string); ok {
			for _, envName := range expEnv {
				_, found := os.LookupEnv(envName)
				message := "Missing"
				if found {
					message = "Configured"
				}
				checks = append(checks, recoveryclient.Check{Name: "Environment: " + envName, Passed: found, Message: message})
			}
		}

		return checks
	}
}

func sqliteIntegrityCheck(name, path string) recoveryclient.Check {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return recoveryclient.Check{Name: "SQLite Integrity: " + name, Passed: false, Message: fmt.Sprintf("Failed to open db: %v", err)}
	}
	defer db.Close()
	var result string
	err = db.QueryRow("PRAGMA integrity_check;").Scan(&result)
	if err != nil || result != "ok" {
		return recoveryclient.Check{Name: "SQLite Integrity: " + name, Passed: false,
			Message: fmt.Sprintf("PRAGMA integrity_check failed: %s (err: %v)", result, err)}
	}
	return recoveryclient.Check{Name: "SQLite Integrity: " + name, Passed: true, Message: "PRAGMA integrity_check passed ok"}
}

func drillPath(root, name string) (string, bool) {
	clean := filepath.Clean(name)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.Join(root, clean), true
}

// DrillRoot is where Drill opens capsules: under the data directory, never the system temp
// dir, because the opened payload is the whole instance in the clear. The lib creates and
// wipes a 0700 subdirectory per drill and sweeps stale ones.
func DrillRoot(cfg *config.Config) string {
	return filepath.Join(cfg.Database.DataDir, "drill")
}
