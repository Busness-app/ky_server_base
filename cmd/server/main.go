package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Busness-app/ky_server_base/internal/api"
	"github.com/Busness-app/ky_server_base/internal/backup"
	"github.com/Busness-app/ky_server_base/internal/config"
	"github.com/Busness-app/ky_server_base/internal/crypto"
	"github.com/Busness-app/ky_server_base/internal/store"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init-admin":
			runInitAdmin(os.Args[2:])
			return
		case "backup-drill":
			runBackupDrill(os.Args[2:])
			return
		case "export-recovery-kit":
			runExportRecoveryKit(os.Args[2:])
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
		hash, err := crypto.HashPassword(adminPass)
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

func runInitAdmin(args []string) {
	fs := flag.NewFlagSet("init-admin", flag.ExitOnError)
	username := fs.String("username", "admin", "Admin username")
	password := fs.String("password", "", "Admin password (minimum 12 characters)")
	_ = fs.Parse(args)

	if *password == "" || len(*password) < 12 {
		log.Fatal("Error: -password is required and must be at least 12 characters")
	}

	cfg, _ := config.LoadFromEnv()
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("DB error: %v", err)
	}
	defer st.Close()

	hash, err := crypto.HashPassword(*password)
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

func runBackupDrill(args []string) {
	cfg, _ := config.LoadFromEnv()
	ctx := context.Background()

	payload, err := backup.BuildLocalPayload(cfg, "1.0.0")
	if err != nil {
		log.Fatalf("Failed to build local payload: %v", err)
	}

	var files []backup.BackupFile
	for _, f := range payload.Files {
		files = append(files, backup.BackupFile{
			Path: f.Path,
			Data: []byte(f.DataBase64),
			Mode: f.Mode,
		})
	}

	capsule, key, err := backup.CreateCapsule(cfg.Server.AppName, "1.0.0", files, payload.Dependencies, payload.VerificationRecipe, 2, 3)
	if err != nil {
		log.Fatalf("Failed to create capsule: %v", err)
	}

	result, err := backup.RunRestoreDrill(ctx, capsule, key)
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

func runExportRecoveryKit(args []string) {
	cfg, _ := config.LoadFromEnv()
	payload, _ := backup.BuildLocalPayload(cfg, "1.0.0")
	var files []backup.BackupFile
	for _, f := range payload.Files {
		files = append(files, backup.BackupFile{
			Path: f.Path,
			Data: []byte(f.DataBase64),
			Mode: f.Mode,
		})
	}

	capsule, _, err := backup.CreateCapsule(cfg.Server.AppName, "1.0.0", files, payload.Dependencies, payload.VerificationRecipe, 2, 3)
	if err != nil {
		log.Fatalf("Failed to generate capsule: %v", err)
	}

	html := backup.GenerateRecoveryKitHTML(capsule, cfg.Server.AppName, cfg.Server.AppURL)
	outPath := "recovery_kit.html"
	if err := os.WriteFile(outPath, []byte(html), 0600); err != nil {
		log.Fatalf("Failed to write recovery kit: %v", err)
	}
	log.Printf("✓ Emergency Disaster Recovery Kit written to %s", outPath)
}
