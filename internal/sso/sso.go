package sso

import (
	"context"
	"errors"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
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

func verifyIDToken(ctx context.Context, issuer, clientID, rawJWT, expectedNonce string) (*IdentityClaims, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, rawJWT)
	if err != nil || expectedNonce == "" || idToken.Nonce != expectedNonce {
		return nil, ErrInvalidIDToken
	}
	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Role              string `json:"role"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.Sub == "" {
		return nil, ErrInvalidIDToken
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
