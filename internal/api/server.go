package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Yoshiofthewire/ky_server_base/internal/auth"
	"github.com/Yoshiofthewire/ky_server_base/internal/backup"
	"github.com/Yoshiofthewire/ky_server_base/internal/config"
	"github.com/Yoshiofthewire/ky_server_base/internal/devices"
	"github.com/Yoshiofthewire/ky_server_base/internal/scim"
	"github.com/Yoshiofthewire/ky_server_base/internal/sso"
	"github.com/Yoshiofthewire/ky_server_base/internal/store"
	"github.com/Yoshiofthewire/ky_server_base/web"
)

type Server struct {
	config   *config.Config
	store    store.Store
	sessions *auth.SessionManager
	pairing  *devices.PairingService
	kysignon *sso.KySignOnClient
	oidc     *sso.GenericOIDCClient
	saml     *sso.SAMLServiceProvider
	scim     *scim.Server
	recovery *backup.KyRecoveryClient
	mux      *http.ServeMux
}

func NewServer(cfg *config.Config, st store.Store) *Server {
	sessions := auth.NewSessionManager(st, cfg.Security)
	pairing := devices.NewPairingService(st, cfg.Server.AppName, cfg.Server.AppURL)
	kysignon := sso.NewKySignOnClient(cfg.SSO, st)
	oidc := sso.NewGenericOIDCClient(cfg.SSO, st)
	saml := sso.NewSAMLServiceProvider(cfg.SSO.SAMLEntityID, cfg.Server.AppURL+"/saml/acs")
	scimSrv := scim.NewServer(st, cfg.SCIM, cfg.Server.AppURL)
	recovery := backup.NewKyRecoveryClient()

	s := &Server{
		config:   cfg,
		store:    st,
		sessions: sessions,
		pairing:  pairing,
		kysignon: kysignon,
		oidc:     oidc,
		saml:     saml,
		scim:     scimSrv,
		recovery: recovery,
		mux:      http.NewServeMux(),
	}

	s.routes()
	return s
}

func (s *Server) routes() {
	// Auth
	s.mux.HandleFunc("/api/auth/pow-challenge", s.handlePoWChallenge)
	s.mux.HandleFunc("/api/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/auth/mfa/totp", s.handleMFATOTP)
	s.mux.HandleFunc("/api/auth/mfa/recovery-code", s.handleMFARecovery)
	s.mux.HandleFunc("/api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("/api/auth/me", s.handleMe)

	// SSO
	s.mux.HandleFunc("/api/sso/kysignon/login", s.handleKySignOnLogin)
	s.mux.HandleFunc("/api/sso/kysignon/callback", s.handleKySignOnCallback)
	s.mux.HandleFunc("/api/sso/kysignon/sync", s.handleKySignOnSyncWebhook)
	s.mux.HandleFunc("/saml/metadata", s.handleSAMLMetadata)

	// Devices & Ephemeral QR Pairing
	s.mux.HandleFunc("/api/devices/pair/init", s.handlePairInit)
	s.mux.HandleFunc("/api/devices/pair/verify", s.handlePairVerify)
	s.mux.HandleFunc("/api/devices/pair/poll", s.handlePairPoll)

	// Feature 0 KyBackup & Restore Drills
	s.mux.HandleFunc("/api/backup/drill", s.handleBackupDrill)
	s.mux.HandleFunc("/api/backup/export-kit", s.handleExportRecoveryKit)
	s.mux.HandleFunc("/api/backup/pair-remote", s.handlePairRemoteRecovery)

	// Settings & Theme
	s.mux.HandleFunc("/api/settings", s.handleGetSettings)
	s.mux.HandleFunc("/api/settings/theme", s.handleSetTheme)

	// SCIM 2.0 routes
	s.scim.RegisterRoutes(s.mux)

	// Embedded React PWA Frontend
	s.mux.Handle("/", web.Handler())
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Enable CORS for local Vite dev / wrappers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, X-KySignOn-Signature")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// SCIM middleware
	if strings.HasPrefix(r.URL.Path, "/scim/v2") {
		s.scim.AuthMiddleware(s.mux).ServeHTTP(w, r)
		return
	}

	s.mux.ServeHTTP(w, r)
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}
