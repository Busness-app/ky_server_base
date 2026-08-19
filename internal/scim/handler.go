package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Yoshiofthewire/ky_server_base/internal/config"
	"github.com/Yoshiofthewire/ky_server_base/internal/crypto"
	"github.com/Yoshiofthewire/ky_server_base/internal/store"
)

// Server handles all RFC 7643 and RFC 7644 SCIM 2.0 endpoints.
type Server struct {
	store  store.Store
	config config.SCIMConfig
	appURL string
}

func NewServer(st store.Store, cfg config.SCIMConfig, appURL string) *Server {
	return &Server{
		store:  st,
		config: cfg,
		appURL: strings.TrimRight(appURL, "/"),
	}
}

// RegisterRoutes attaches standard /scim/v2 routes to an http.ServeMux.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/scim/v2/ServiceProviderConfig", s.handleServiceProviderConfig)
	mux.HandleFunc("/scim/v2/Schemas", s.handleSchemas)
	mux.HandleFunc("/scim/v2/ResourceTypes", s.handleResourceTypes)

	mux.HandleFunc("/scim/v2/Users", s.handleUsers)
	mux.HandleFunc("/scim/v2/Users/", s.handleUserByID)

	mux.HandleFunc("/scim/v2/Groups", s.handleGroups)
	mux.HandleFunc("/scim/v2/Groups/", s.handleGroupByID)
}

// AuthMiddleware enforces bearer token verification for SCIM requests.
func (s *Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/scim/v2") {
			next.ServeHTTP(w, r)
			return
		}

		if !s.config.Enabled {
			s.writeError(w, http.StatusForbidden, "SCIM provisioning is disabled", "")
			return
		}

		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")

		if token == "" || token != s.config.BearerToken {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			s.writeError(w, http.StatusUnauthorized, "Invalid or missing bearer token", "")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}

	cfg := map[string]any{
		"schemas":          []string{SchemaServiceProviderConfig},
		"documentationUri": "https://busnes.app/docs/scim",
		"patch":            map[string]bool{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": 200},
		"changePassword":   map[string]bool{"supported": false},
		"sort":             map[string]bool{"supported": false},
		"etag":             map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{
			{
				"name":        "OAuth Bearer Token",
				"description": "Authentication scheme using the OAuth Bearer Token Standard",
				"specUri":     "http://www.rfc-editor.org/info/rfc6750",
				"type":        "oauthbearertoken",
				"primary":     true,
			},
		},
		"meta": SCIMMeta{
			ResourceType: "ServiceProviderConfig",
			Created:      time.Now().UTC(),
			LastModified: time.Now().UTC(),
			Location:     fmt.Sprintf("%s/scim/v2/ServiceProviderConfig", s.appURL),
		},
	}

	s.writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleSchemas(w http.ResponseWriter, r *http.Request) {
	resp := ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: 2,
		StartIndex:   1,
		ItemsPerPage: 2,
		Resources: []any{
			map[string]any{"id": SchemaUser, "name": "User", "description": "User Account"},
			map[string]any{"id": SchemaGroup, "name": "Group", "description": "Group Resource"},
		},
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleResourceTypes(w http.ResponseWriter, r *http.Request) {
	resp := ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: 2,
		StartIndex:   1,
		ItemsPerPage: 2,
		Resources: []any{
			map[string]any{
				"schemas":          []string{SchemaResourceType},
				"id":               "User",
				"name":             "User",
				"endpoint":         "/Users",
				"schema":           SchemaUser,
				"schemaExtensions": []any{},
			},
			map[string]any{
				"schemas":          []string{SchemaResourceType},
				"id":               "Group",
				"name":             "Group",
				"endpoint":         "/Groups",
				"schema":           SchemaGroup,
				"schemaExtensions": []any{},
			},
		},
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------
// Users Collection & Operations
// ---------------------------------------------------------------------

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listUsers(w, r)
	case http.MethodPost:
		s.createUser(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
	}
}

func (s *Server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/scim/v2/Users/")
	if id == "" {
		s.handleUsers(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getUser(w, r, id)
	case http.MethodPut:
		s.replaceUser(w, r, id)
	case http.MethodPatch:
		s.patchUser(w, r, id)
	case http.MethodDelete:
		s.deleteUser(w, r, id)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
	}
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	startIndex := getQueryInt(r, "startIndex", 1)
	count := getQueryInt(r, "count", 50)
	filter := r.URL.Query().Get("filter")

	offset := startIndex - 1
	if offset < 0 {
		offset = 0
	}

	search := ""
	if filter != "" {
		// Basic filter parsing: userName eq "value" or email eq "value"
		if strings.Contains(filter, "eq") {
			parts := strings.Split(filter, "eq")
			if len(parts) == 2 {
				val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				search = val
			}
		} else {
			search = filter
		}
	}

	users, total, err := s.store.Users().ListUsers(r.Context(), offset, count, search)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error(), "")
		return
	}

	var resources []any
	for _, u := range users {
		resources = append(resources, s.userToSCIM(u))
	}

	resp := ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}

	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var input SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body", "invalidSyntax")
		return
	}

	if input.UserName == "" {
		s.writeError(w, http.StatusBadRequest, "userName is required", "invalidValue")
		return
	}

	email := ""
	if len(input.Emails) > 0 {
		email = input.Emails[0].Value
	}

	displayName := input.DisplayName
	if displayName == "" && input.Name != nil {
		displayName = input.Name.Formatted
	}
	if displayName == "" {
		displayName = input.UserName
	}

	role := "user"
	if len(input.Roles) > 0 && input.Roles[0].Value != "" {
		role = input.Roles[0].Value
	}

	status := "active"
	if !input.Active {
		status = "inactive"
	}

	userID := fmt.Sprintf("usr_%s", crypto.RandomHex(12))
	user := &store.User{
		ID:          userID,
		Username:    input.UserName,
		Email:       email,
		DisplayName: displayName,
		Role:        role,
		Status:      status,
		SSOProvider: "scim",
		SSOSubject:  input.ExternalID,
	}

	if err := s.store.Users().CreateUser(r.Context(), user); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			s.writeError(w, http.StatusConflict, "User already exists", "uniqueness")
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error(), "")
		return
	}

	_ = s.store.Audit().LogAudit(r.Context(), &store.AuditRecord{
		UserID:   user.ID,
		Action:   "scim.user.create",
		Resource: user.Username,
	})

	w.Header().Set("Location", fmt.Sprintf("%s/scim/v2/Users/%s", s.appURL, user.ID))
	s.writeJSON(w, http.StatusCreated, s.userToSCIM(user))
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request, id string) {
	user, err := s.store.Users().GetUserByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "User not found", "")
		return
	}
	s.writeJSON(w, http.StatusOK, s.userToSCIM(user))
}

func (s *Server) replaceUser(w http.ResponseWriter, r *http.Request, id string) {
	existing, err := s.store.Users().GetUserByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "User not found", "")
		return
	}

	var input SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON", "invalidSyntax")
		return
	}

	if input.UserName != "" {
		existing.Username = input.UserName
	}
	if len(input.Emails) > 0 {
		existing.Email = input.Emails[0].Value
	}
	if input.DisplayName != "" {
		existing.DisplayName = input.DisplayName
	}
	if len(input.Roles) > 0 {
		existing.Role = input.Roles[0].Value
	}
	if input.Active {
		existing.Status = "active"
	} else {
		existing.Status = "inactive"
	}

	if err := s.store.Users().UpdateUser(r.Context(), existing); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error(), "")
		return
	}

	s.writeJSON(w, http.StatusOK, s.userToSCIM(existing))
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request, id string) {
	user, err := s.store.Users().GetUserByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "User not found", "")
		return
	}

	var patch PatchRequest
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid patch JSON", "invalidSyntax")
		return
	}

	for _, op := range patch.Operations {
		path := strings.ToLower(op.Path)
		switch path {
		case "active":
			if b, ok := op.Value.(bool); ok {
				if b {
					user.Status = "active"
				} else {
					user.Status = "inactive"
				}
			}
		case "displayname":
			if str, ok := op.Value.(string); ok {
				user.DisplayName = str
			}
		case "role", "roles":
			if str, ok := op.Value.(string); ok {
				user.Role = str
			}
		}
	}

	if err := s.store.Users().UpdateUser(r.Context(), user); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error(), "")
		return
	}

	s.writeJSON(w, http.StatusOK, s.userToSCIM(user))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.store.Users().DeleteUser(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "User not found", "")
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error(), "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------
// Groups Collection & Operations
// ---------------------------------------------------------------------

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listGroups(w, r)
	case http.MethodPost:
		s.createGroup(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
	}
}

func (s *Server) handleGroupByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/scim/v2/Groups/")
	if id == "" {
		s.handleGroups(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getGroup(w, r, id)
	case http.MethodDelete:
		s.deleteGroup(w, r, id)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
	}
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	startIndex := getQueryInt(r, "startIndex", 1)
	count := getQueryInt(r, "count", 50)
	offset := startIndex - 1
	if offset < 0 {
		offset = 0
	}

	groups, total, err := s.store.Groups().ListGroups(r.Context(), offset, count)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error(), "")
		return
	}

	var resources []any
	for _, g := range groups {
		resources = append(resources, s.groupToSCIM(g))
	}

	resp := ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}

	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var input SCIMGroup
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON", "invalidSyntax")
		return
	}

	if input.DisplayName == "" {
		s.writeError(w, http.StatusBadRequest, "displayName is required", "invalidValue")
		return
	}

	grpID := fmt.Sprintf("grp_%s", crypto.RandomHex(12))
	grp := &store.Group{
		ID:          grpID,
		DisplayName: input.DisplayName,
		ExternalID:  input.ExternalID,
	}

	if err := s.store.Groups().CreateGroup(r.Context(), grp); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			s.writeError(w, http.StatusConflict, "Group already exists", "uniqueness")
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error(), "")
		return
	}

	for _, m := range input.Members {
		if m.Value != "" {
			_ = s.store.Groups().AddGroupMember(r.Context(), grp.ID, m.Value)
		}
	}

	w.Header().Set("Location", fmt.Sprintf("%s/scim/v2/Groups/%s", s.appURL, grp.ID))
	s.writeJSON(w, http.StatusCreated, s.groupToSCIM(grp))
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request, id string) {
	grp, err := s.store.Groups().GetGroupByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Group not found", "")
		return
	}
	s.writeJSON(w, http.StatusOK, s.groupToSCIM(grp))
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.store.Groups().DeleteGroup(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Group not found", "")
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error(), "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------
// Mappers & Helpers
// ---------------------------------------------------------------------

func (s *Server) userToSCIM(u *store.User) SCIMUser {
	var emails []SCIMMultiValued
	if u.Email != "" {
		emails = append(emails, SCIMMultiValued{
			Value:   u.Email,
			Primary: true,
			Type:    "work",
		})
	}

	var roles []SCIMMultiValued
	if u.Role != "" {
		roles = append(roles, SCIMMultiValued{
			Value:   u.Role,
			Primary: true,
		})
	}

	return SCIMUser{
		Schemas:     []string{SchemaUser},
		ID:          u.ID,
		ExternalID:  u.SSOSubject,
		UserName:    u.Username,
		DisplayName: u.DisplayName,
		Active:      u.Status == "active",
		Emails:      emails,
		Roles:       roles,
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      u.CreatedAt,
			LastModified: u.UpdatedAt,
			Location:     fmt.Sprintf("%s/scim/v2/Users/%s", s.appURL, u.ID),
		},
	}
}

func (s *Server) groupToSCIM(g *store.Group) SCIMGroup {
	var members []SCIMMultiValued
	for _, m := range g.Members {
		members = append(members, SCIMMultiValued{
			Value: m,
		})
	}

	return SCIMGroup{
		Schemas:     []string{SchemaGroup},
		ID:          g.ID,
		ExternalID:  g.ExternalID,
		DisplayName: g.DisplayName,
		Members:     members,
		Meta: SCIMMeta{
			ResourceType: "Group",
			Created:      g.CreatedAt,
			LastModified: g.UpdatedAt,
			Location:     fmt.Sprintf("%s/scim/v2/Groups/%s", s.appURL, g.ID),
		},
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) writeError(w http.ResponseWriter, status int, detail, scimType string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	resp := ErrorResponse{
		Schemas:  []string{SchemaError},
		Status:   strconv.Itoa(status),
		ScimType: scimType,
		Detail:   detail,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func getQueryInt(r *http.Request, key string, defaultVal int) int {
	if val := r.URL.Query().Get(key); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil && intVal > 0 {
			return intVal
		}
	}
	return defaultVal
}
