package sso

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidState     = errors.New("invalid or expired SSO state")
	ErrInvalidIDToken   = errors.New("invalid ID token")
	ErrProviderDisabled = errors.New("SSO provider is not enabled")
)

// IdentityClaims holds the unified identity extracted from any SSO provider.
type IdentityClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Role              string `json:"role,omitempty"`
	Provider          string `json:"provider"` // "kysignon", "oidc", "saml"
}

// ParseJWTClaims decodes unverified JWT claims for basic identification and profile inspection.
func ParseJWTClaims(rawJWT string) (*IdentityClaims, error) {
	parts := strings.Split(rawJWT, ".")
	if len(parts) < 2 {
		return nil, ErrInvalidIDToken
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payloadBytes, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, ErrInvalidIDToken
		}
	}

	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Role              string `json:"role"`
	}

	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}

	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = claims.Sub
	}

	return &IdentityClaims{
		Subject:           claims.Sub,
		Email:             claims.Email,
		Name:              claims.Name,
		PreferredUsername: username,
		Role:              claims.Role,
	}, nil
}

// SSOState represents ephemeral state held during OAuth/OIDC authorization flow.
type SSOState struct {
	State        string    `json:"state"`
	Verifier     string    `json:"verifier"`
	Provider     string    `json:"provider"`
	RedirectBack string    `json:"redirect_back"`
	CreatedAt    time.Time `json:"created_at"`
}
