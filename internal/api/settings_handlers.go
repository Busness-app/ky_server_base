package api

import (
	"encoding/json"
	"net/http"
)

type ThemeUpdateRequest struct {
	Theme string `json:"theme"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.Settings().GetAllSettings(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load settings")
		return
	}

	theme, _ := s.store.Settings().GetSetting(r.Context(), "site_theme")
	if theme == "" {
		theme = "patina"
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"app_name":       s.config.Server.AppName,
		"app_url":        s.config.Server.AppURL,
		"sso_enabled":    s.config.SSO.Enabled,
		"scim_enabled":   s.config.SCIM.Enabled,
		"theme":          theme,
		"db_driver":      s.config.Database.Driver,
		"captcha_provider": s.config.Captcha.Provider,
		"extra_settings": settings,
	})
}

func (s *Server) handleSetTheme(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req ThemeUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Theme == "" {
		s.writeError(w, http.StatusBadRequest, "Invalid theme")
		return
	}

	if err := s.store.Settings().SetSetting(r.Context(), "site_theme", req.Theme); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to save theme")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{"theme": req.Theme})
}
