package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/password"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky-primitives/shamir"
	"github.com/Busness-app/ky_server_base/internal/api"
	"github.com/Busness-app/ky_server_base/internal/backup"
	"github.com/Busness-app/ky_server_base/internal/config"
	"github.com/Busness-app/ky_server_base/internal/crypto"
	"github.com/Busness-app/ky_server_base/internal/store"
)

// appVersion is what the capsule manifest records for this build.
const appVersion = "1.0.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init-admin":
			runInitAdmin(os.Args[2:])
			return
		case "backup-drill":
			runBackupDrill(os.Args[2:])
			return
		case "export-capsule":
			runExportCapsule(os.Args[2:])
			return
		case "deposit":
			runDeposit()
			return
		case "restore":
			runRestore(os.Args[2:])
			return
		case "version":
			fmt.Println("ky_server_base v1.0.0 (Busnes.app base platform)")
			return
		}
	}

	runServer()
}

func runServer() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	if cfg.Backup.AllowPrivateRecovery {
		log.Printf("[BACKUP] KY_BACKUP_ALLOW_PRIVATE_RECOVERY is on: private and CGNAT KyRecovery destinations admitted (HTTPS still required)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database (%s): %v", cfg.Database.Driver, err)
	}
	defer st.Close()

	// Ensure default admin user exists if database is empty
	count, _ := st.Users().CountUsers(ctx)
	if count == 0 {
		adminPass := os.Getenv("KY_ADMIN_PASSWORD")
		if adminPass == "" {
			adminPass = crypto.RandomHex(12)
			log.Printf("[SECURITY] Initial bootstrap: Created admin account. Username: admin | Password: %s", adminPass)
		}
		hash, err := password.Hash(adminPass)
		if err != nil {
			log.Fatalf("Failed to hash bootstrap admin password: %v", err)
		}
		if err := st.Users().CreateUser(ctx, &store.User{
			ID:           fmt.Sprintf("usr_%s", crypto.RandomHex(12)),
			Username:     "admin",
			DisplayName:  "Administrator",
			PasswordHash: hash,
			Role:         "admin",
			Status:       "active",
			SSOProvider:  "local",
		}); err != nil {
			log.Fatalf("Failed to create bootstrap admin: %v", err)
		}
	}

	srv := api.NewServer(cfg, st)
	if cfg.Backup.DepositInterval > 0 {
		go depositLoop(ctx, cfg, st)
	}

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      srv,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Graceful shutdown channel
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[KY-BASE] %s listening on http://%s (DB: %s)", cfg.Server.AppName, addr, cfg.Database.Driver)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-stop
	log.Println("[KY-BASE] Shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	log.Println("[KY-BASE] Server stopped")
}

// depositLoop seals and deposits a capsule every DepositInterval while the instance is paired.
// Unpaired instances stay quiet; every attempt after pairing is audited under the system user.
func depositLoop(ctx context.Context, cfg *config.Config, st store.Store) {
	client := backup.NewKyRecoveryClient()
	ticker := time.NewTicker(cfg.Backup.DepositInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		rcpt, m, err := backup.DepositBackup(ctx, cfg, st.Settings(), client, appVersion)
		if errors.Is(err, backup.ErrNotPaired) {
			continue
		}
		action, resource, details := backup.Outcome(rcpt, m, err)
		_ = st.Audit().LogAudit(ctx, &store.AuditRecord{UserID: "system", Action: action, Resource: resource, Details: details})
		if err != nil {
			log.Printf("[BACKUP] scheduled deposit: %s", backup.AuditSafe(err.Error()))
			continue
		}
		log.Printf("[BACKUP] deposited capsule %s (%d bytes) with KyRecovery", rcpt.CapsuleID, rcpt.SizeBytes)
	}
}

// runDeposit seals and deposits one capsule now, for cron or an operator at a shell.
func runDeposit() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("DB error: %v", err)
	}
	defer st.Close()

	rcpt, m, err := backup.DepositBackup(ctx, cfg, st.Settings(), backup.NewKyRecoveryClient(), appVersion)
	action, resource, details := backup.Outcome(rcpt, m, err)
	_ = st.Audit().LogAudit(ctx, &store.AuditRecord{UserID: "cli", Action: action, Resource: resource, Details: details})
	if err != nil {
		log.Fatalf("Deposit: %v", err)
	}
	log.Printf("✓ Capsule %s (%d bytes, sealed to recovery key %s) deposited at %s; digest %s",
		rcpt.CapsuleID, rcpt.SizeBytes, m.RecoveryKeyID, rcpt.DepositedAt.Format(time.RFC3339), rcpt.Digest)
}

func runInitAdmin(args []string) {
	fs := flag.NewFlagSet("init-admin", flag.ExitOnError)
	username := fs.String("username", "admin", "Admin username")
	passwordFlag := fs.String("password", "", "Admin password (minimum 12 characters)")
	_ = fs.Parse(args)

	if *passwordFlag == "" || len(*passwordFlag) < 12 {
		log.Fatal("Error: -password is required and must be at least 12 characters")
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("DB error: %v", err)
	}
	defer st.Close()

	hash, err := password.Hash(*passwordFlag)
	if err != nil {
		log.Fatalf("Password hashing error: %v", err)
	}

	existing, err := st.Users().GetUserByUsername(ctx, *username)
	if err == nil && existing != nil {
		existing.PasswordHash = hash
		existing.Status = "active"
		existing.Role = "admin"
		if err := st.Users().UpdateUser(ctx, existing); err != nil {
			log.Fatalf("Failed to update admin: %v", err)
		}
		log.Printf("✓ Admin user %q password successfully reset", *username)
		return
	}

	user := &store.User{
		ID:           fmt.Sprintf("usr_%s", crypto.RandomHex(12)),
		Username:     *username,
		DisplayName:  "Administrator",
		PasswordHash: hash,
		Role:         "admin",
		Status:       "active",
		SSOProvider:  "local",
	}

	if err := st.Users().CreateUser(ctx, user); err != nil {
		log.Fatalf("Failed to create admin: %v", err)
	}
	log.Printf("✓ Admin user %q created successfully", *username)
}

func loadRecoveryKey(ctx context.Context, cfg *config.Config, st store.Store) (backup.RecoveryKey, error) {
	return backup.LoadRecoveryKey(ctx, cfg.Database.DataDir, st.Settings())
}

// collectFiles is what every CLI seal uses; the sealed-only members are safe here and nowhere else.
func collectFiles(cfg *config.Config) *backup.Payload {
	payload, err := backup.CollectSealable(cfg, appVersion)
	if err != nil {
		log.Fatalf("Failed to collect backup files: %v", err)
	}
	return payload
}

func runBackupDrill(args []string) {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("DB error: %v", err)
	}
	defer st.Close()

	payload := collectFiles(cfg)
	pinned, err := loadRecoveryKey(ctx, cfg, st)
	if err != nil && !errors.Is(err, backup.ErrNotPaired) {
		log.Fatalf("Recovery key: %v", err)
	}
	result, err := backup.RunRestoreDrill(ctx, payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, pinned)
	if err != nil {
		log.Fatalf("Drill execution error: %v", err)
	}

	fmt.Printf("\n=== Feature 0: KyBackup Restore Drill Summary ===\n")
	fmt.Printf("Status:   %s\n", map[bool]string{true: "PASSED (OK)", false: "FAILED"}[result.Passed])
	fmt.Printf("Duration: %d ms\n", result.DurationMS)
	for _, check := range result.Checks {
		status := "✓"
		if !check.Passed {
			status = "✗"
		}
		fmt.Printf("  [%s] %s: %s\n", status, check.Name, check.Message)
	}
	fmt.Println("==================================================")
}

func runExportCapsule(args []string) {
	fs := flag.NewFlagSet("export-capsule", flag.ExitOnError)
	out := fs.String("out", "", "output path (default <capsule-id>.kycap in the current directory)")
	_ = fs.Parse(args)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("DB error: %v", err)
	}
	defer st.Close()

	key, err := loadRecoveryKey(ctx, cfg, st)
	if err != nil {
		log.Fatalf("Recovery key: %v", err)
	}
	payload := collectFiles(cfg)
	raw, m, err := backup.Seal(payload.ServiceName, payload.AppVersion, payload.Files, payload.Dependencies, payload.VerificationRecipe, key)
	if err != nil {
		log.Fatalf("Seal: %v", err)
	}
	path := *out
	if path == "" {
		path = backup.FilenameSafe(m.CapsuleID) + ".kycap"
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		log.Fatalf("Write: %v", err)
	}
	log.Printf("✓ Capsule %s sealed to recovery key %s, written to %s (%d bytes)", m.CapsuleID, m.RecoveryKeyID, path, len(raw))
}

// restore is the product-side half of the ceremony: k custodian shares typed from their cards,
// combined here, used once, and dropped. It refuses a capsule from another service before
// touching the key, and prints the authenticated manifest so the operator can compare
// CapsuleID and CreatedAt against kyrecovery's deposit record — Open proves integrity and
// binding to this key, not which backup this is.
func restore(capsulePath, targetDir, expectService string, shareStrings []string, stdout io.Writer) error {
	raw, err := os.ReadFile(capsulePath)
	if err != nil {
		return err
	}
	peek, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		return err
	}
	if peek.ServiceName != expectService {
		return fmt.Errorf("capsule is for service %q, this instance is %q; pass -service to override", peek.ServiceName, expectService)
	}

	shares := make([]shamir.Share, 0, len(shareStrings))
	for i, s := range shareStrings {
		sh, err := shamir.ParseShare(s)
		if err != nil {
			return fmt.Errorf("share %d: %w", i+1, err)
		}
		shares = append(shares, sh)
	}
	priv, err := recoverykey.Combine(shares)
	if err != nil {
		return err
	}

	m, files, err := capsule.Open(raw, priv, targetDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Restored %d files from capsule %s\n  service:      %s (v%s)\n  created:      %s\n  recovery key: %s\n  payload hash: %s\n",
		len(files), m.CapsuleID, m.ServiceName, m.AppVersion, m.CreatedAt.Format(time.RFC3339), m.RecoveryKeyID, m.PayloadHash)
	return nil
}

// readShares takes custodian shares off a reader, one per non-empty line. They never travel
// in argv: /proc/<pid>/cmdline is world-readable, argv is kept in shell history and copied by
// every process monitor, and k of these lines rebuild the suite private key.
func readShares(r io.Reader) ([]string, error) {
	var shares []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			shares = append(shares, line)
		}
	}
	return shares, sc.Err()
}

// stdinIsTerminal reports whether a human is typing, so a pipeline gets no stray prompt.
func stdinIsTerminal() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func runRestore(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	capsulePath := fs.String("capsule", "", "path to the .kycap file")
	target := fs.String("to", "", "empty directory to restore into")
	service := fs.String("service", "", "expected service name (default: $KY_APP_NAME)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: ky_server_base restore -capsule <file.kycap> -to <dir> [-service <name>]\n\n"+
			"Custodian shares are read from stdin, one ky2-... share per line, and never from\n"+
			"the command line: argv is world-readable and lands in shell history.\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if *capsulePath == "" || *target == "" {
		fs.Usage()
		os.Exit(2)
	}
	if *service == "" {
		// Not config.LoadFromEnv: it mints <DataDir>/encryption.key as a side effect, and a
		// recovery host has no business growing a key of its own mid-ceremony.
		*service = os.Getenv("KY_APP_NAME")
	}
	if *service == "" {
		*service = config.DefaultAppName
	}
	if *service == "" {
		log.Fatal("Error: -service is required when KY_APP_NAME is not set")
	}

	if stdinIsTerminal() {
		fmt.Fprintln(os.Stderr, "Paste custodian shares, one per line, then Ctrl-D:")
	}
	shares, err := readShares(os.Stdin)
	if err != nil {
		log.Fatalf("Reading shares: %v", err)
	}
	if len(shares) == 0 {
		log.Fatal("Error: no custodian shares on stdin")
	}
	if err := restore(*capsulePath, *target, *service, shares, os.Stdout); err != nil {
		log.Fatalf("Restore failed: %v", err)
	}
}
