package backup

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	_ "modernc.org/sqlite"
)

// CheckItem represents a discrete verification result in a restore drill.
type CheckItem struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

// DrillResult contains the structured outcome of a restore drill.
type DrillResult struct {
	Passed       bool        `json:"passed"`
	DurationMS   int64       `json:"duration_ms"`
	Checks       []CheckItem `json:"checks"`
	ErrorMessage string      `json:"error_message,omitempty"`
}

// RunRestoreDrill proves the backup pipeline: it seals files exactly as a real backup would,
// but to a throwaway keypair it then opens with, extracts into a 0700 scratch directory, and
// runs the verification recipe. The product has no recovery private key, so this is the only
// end-to-end check it can run alone. A separate check reports whether the suite key is pinned.
func RunRestoreDrill(ctx context.Context, serviceName, appVersion string, files []BackupFile, deps, recipe map[string]any, pinned RecoveryKey) (*DrillResult, error) {
	start := time.Now()
	result := &DrillResult{Passed: true, Checks: make([]CheckItem, 0)}

	// 0. Is this instance paired to the suite recovery key?
	if pinned.Public.IsZero() {
		result.Passed = false
		result.Checks = append(result.Checks, CheckItem{Name: "Recovery Key", Passed: false, Message: ErrNotPaired.Error()})
	} else {
		result.Checks = append(result.Checks, CheckItem{Name: "Recovery Key", Passed: true,
			Message: fmt.Sprintf("Sealing to recovery key %s (%d-of-%d custodians)", pinned.Public.ID()[:16], pinned.Threshold, pinned.TotalShares)})
	}

	// 1. Seal to a throwaway key and open with it. Topology is fixed here: it is display
	// metadata, and the drill key has no custodians.
	drillKey, err := recoverykey.Generate()
	if err != nil {
		return nil, fmt.Errorf("drill key: %w", err)
	}
	raw, _, err := capsule.Seal(serviceName, appVersion, toCapsuleFiles(files), deps, recipe, 2, 3, drillKey.Public())
	if err != nil {
		return nil, fmt.Errorf("drill seal: %w", err)
	}

	scratchDir, err := os.MkdirTemp("", "kyrec-drill-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create drill sandbox: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratchDir) }()
	_ = os.Chmod(scratchDir, 0700)

	m, extracted, err := capsule.Open(raw, drillKey, scratchDir)
	if err != nil {
		result.Passed = false
		result.ErrorMessage = fmt.Sprintf("Open failed: %v", err)
		result.Checks = append(result.Checks, CheckItem{Name: "Directory Unpack", Passed: false, Message: result.ErrorMessage})
		result.DurationMS = time.Since(start).Milliseconds()
		return result, nil
	}

	var totalBytes int64
	for _, f := range extracted {
		totalBytes += int64(len(f.Content))
	}
	result.Checks = append(result.Checks, CheckItem{Name: "Directory Unpack", Passed: true,
		Message: fmt.Sprintf("Extracted %d files (%d bytes)", len(extracted), totalBytes)})

	recipeMap, _ := m.VerificationRecipe.(map[string]any)
	if recipeMap == nil {
		recipeMap = map[string]any{}
	}

	// 2. Verify Required Files
	if reqFiles, ok := recipeMap["required_files"].([]interface{}); ok {
		allFound := true
		for _, rf := range reqFiles {
			pathStr := fmt.Sprintf("%v", rf)
			fullPath, safe := drillPath(scratchDir, pathStr)
			if !safe {
				result.Passed = false
				result.Checks = append(result.Checks, CheckItem{Name: "Required File: " + pathStr, Passed: false, Message: "Unsafe path"})
				continue
			}
			fi, err := os.Stat(fullPath)
			if err != nil || fi.Size() == 0 {
				allFound = false
				result.Passed = false
				result.Checks = append(result.Checks, CheckItem{
					Name:    fmt.Sprintf("Required File: %s", pathStr),
					Passed:  false,
					Message: "File missing or empty",
				})
			}
		}
		if allFound && len(reqFiles) > 0 {
			result.Checks = append(result.Checks, CheckItem{
				Name:    "Required Files",
				Passed:  true,
				Message: fmt.Sprintf("All %d required files verified", len(reqFiles)),
			})
		}
	}

	// 3. SQLite Integrity Checks
	if checkSQLite, _ := recipeMap["check_sqlite_integrity"].(bool); checkSQLite {
		if sqlitePaths, ok := recipeMap["sqlite_paths"].([]interface{}); ok {
			for _, sp := range sqlitePaths {
				dbPathRel := fmt.Sprintf("%v", sp)
				dbPathFull, safe := drillPath(scratchDir, dbPathRel)
				if !safe {
					result.Passed = false
					result.Checks = append(result.Checks, CheckItem{Name: "SQLite Integrity: " + dbPathRel, Passed: false, Message: "Unsafe path"})
					continue
				}

				db, err := sql.Open("sqlite", dbPathFull)
				if err != nil {
					result.Passed = false
					result.Checks = append(result.Checks, CheckItem{
						Name:    fmt.Sprintf("SQLite Integrity: %s", dbPathRel),
						Passed:  false,
						Message: fmt.Sprintf("Failed to open db: %v", err),
					})
					continue
				}

				var checkResult string
				err = db.QueryRowContext(ctx, "PRAGMA integrity_check;").Scan(&checkResult)
				_ = db.Close()

				if err != nil || checkResult != "ok" {
					result.Passed = false
					result.Checks = append(result.Checks, CheckItem{
						Name:    fmt.Sprintf("SQLite Integrity: %s", dbPathRel),
						Passed:  false,
						Message: fmt.Sprintf("PRAGMA integrity_check failed: %s (err: %v)", checkResult, err),
					})
				} else {
					result.Checks = append(result.Checks, CheckItem{
						Name:    fmt.Sprintf("SQLite Integrity: %s", dbPathRel),
						Passed:  true,
						Message: "PRAGMA integrity_check passed ok",
					})
				}
			}
		}
	}

	// 4. Check Environment Variables
	if expEnv, ok := recipeMap["expected_env"].([]interface{}); ok && len(expEnv) > 0 {
		for _, name := range expEnv {
			envName := fmt.Sprint(name)
			_, found := os.LookupEnv(envName)
			if !found {
				result.Passed = false
			}
			message := "Missing"
			if found {
				message = "Configured"
			}
			result.Checks = append(result.Checks, CheckItem{Name: "Environment: " + envName, Passed: found, Message: message})
		}
	}

	result.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

func drillPath(root, name string) (string, bool) {
	clean := filepath.Clean(name)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.Join(root, clean), true
}
