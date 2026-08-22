package backup

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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

// RunRestoreDrill decapsulates the container into an ephemeral 0700 scratch directory, executes the recipe, and scrubs the directory.
func RunRestoreDrill(ctx context.Context, capsule *Capsule, key []byte) (*DrillResult, error) {
	start := time.Now()

	scratchDir, err := os.MkdirTemp("", "kyrec-drill-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create drill sandbox: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(scratchDir)
	}()

	_ = os.Chmod(scratchDir, 0700)

	result := &DrillResult{
		Passed: true,
		Checks: make([]CheckItem, 0),
	}

	// 1. Decapsulate and extract
	files, err := ExtractCapsule(capsule, key, scratchDir)
	if err != nil {
		result.Passed = false
		result.ErrorMessage = fmt.Sprintf("Decapsulation failed: %v", err)
		result.Checks = append(result.Checks, CheckItem{
			Name:    "Directory Unpack",
			Passed:  false,
			Message: result.ErrorMessage,
		})
		result.DurationMS = time.Since(start).Milliseconds()
		return result, nil
	}

	var totalBytes int64
	for _, f := range files {
		totalBytes += int64(len(f.Data))
	}

	result.Checks = append(result.Checks, CheckItem{
		Name:    "Directory Unpack",
		Passed:  true,
		Message: fmt.Sprintf("Extracted %d files (%d bytes)", len(files), totalBytes),
	})

	recipe := capsule.Manifest.VerificationRecipe
	if recipe == nil {
		recipe = make(map[string]interface{})
	}

	// 2. Verify Required Files
	if reqFiles, ok := recipe["required_files"].([]interface{}); ok {
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
	if checkSQLite, _ := recipe["check_sqlite_integrity"].(bool); checkSQLite {
		if sqlitePaths, ok := recipe["sqlite_paths"].([]interface{}); ok {
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
	if expEnv, ok := recipe["expected_env"].([]interface{}); ok && len(expEnv) > 0 {
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
