package sso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Yoshiofthewire/ky_server_base/internal/config"
	"github.com/Yoshiofthewire/ky_server_base/internal/store"
)

// GenericOIDCClient provides standard OpenID Connect discovery and auth flows for Google, Entra, Okta, etc.
type GenericOIDCClient struct {
	config config.SSOConfig
	store  store.Store
	client *http.Client

	mu          sync.RWMutex
	discoveryDoc *OIDCDiscovery
	lastFetch   time.Time
}

type OIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func NewGenericOIDCClient(cfg config.SSOConfig, st store.Store) *GenericOIDCClient {
	return &GenericOIDCClient{
		config: cfg,
		store:  st,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (g *GenericOIDCClient) discover(ctx context.Context) (*OIDCDiscovery, error) {
	g.mu.RLock()
	if g.discoveryDoc != nil && time.Since(g.lastFetch) < 1*time.Hour {
		defer g.mu.RUnlock()
		return g.discoveryDoc, nil
	}
	g.mu.RUnlock()

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.discoveryDoc != nil && time.Since(g.lastFetch) < 1*time.Hour {
		return g.discoveryDoc, nil
	}

	issuer := strings.TrimRight(g.config.GenericOIDCIssuer, "/")
	discoveryURL := fmt.Sprintf("%s/.well-known/openid-configuration", issuer)

	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}

	var doc OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}

	g.discoveryDoc = &doc
	g.lastFetch = time.Now()
	return &doc, nil
}

// BuildAuthURL creates the standard authorization URL with PKCE.
func (g *GenericOIDCClient) BuildAuthURL(ctx context.Context, redirectURI, state, challenge string) (string, error) {
	if g.config.GenericOIDCIssuer == "" || g.config.GenericOIDCClientID == "" {
		return "", ErrProviderDisabled
	}

	doc, err := g.discover(ctx)
	if err != nil {
		// Fallback to convention endpoints if discovery fails
		authEndpoint := fmt.Sprintf("%s/oauth/authorize", strings.TrimRight(g.config.GenericOIDCIssuer, "/"))
		doc = &OIDCDiscovery{AuthorizationEndpoint: authEndpoint}
	}

	v := url.Values{}
	v.Set("client_id", g.config.GenericOIDCClientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("response_type", "code")
	v.Set("scope", "openid profile email")
	v.Set("state", state)
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")

	return fmt.Sprintf("%s?%s", doc.AuthorizationEndpoint, v.Encode()), nil
}

// ExchangeCode completes the code exchange for identity tokens.
func (g *GenericOIDCClient) ExchangeCode(ctx context.Context, code, verifier, redirectURI string) (*IdentityClaims, error) {
	doc, err := g.discover(ctx)
	if err != nil {
		tokenEndpoint := fmt.Sprintf("%s/oauth/token", strings.TrimRight(g.config.GenericOIDCIssuer, "/"))
		doc = &OIDCDiscovery{TokenEndpoint: tokenEndpoint}
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("code_verifier", verifier)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", g.config.GenericOIDCClientID)
	if g.config.GenericOIDCSecret != "" {
		data.Set("client_secret", g.config.GenericOIDCSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", doc.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.IDToken == "" {
		return nil, errors.New("missing id_token in response")
	}

	claims, err := ParseJWTClaims(tokenResp.IDToken)
	if err != nil {
		return nil, err
	}
	claims.Provider = "oidc"
	return claims, nil
}
