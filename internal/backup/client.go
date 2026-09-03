package backup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky_server_base/internal/config"
)

// KyRecoveryClient implements the Zero-Code Pairing & Push client contract.
type KyRecoveryClient struct {
	client *http.Client
}

func NewKyRecoveryClient() *KyRecoveryClient {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if isPublicIP(ip) {
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
		}
		return nil, errors.New("recovery host resolves only to private or reserved addresses")
	}}
	client := &http.Client{Timeout: 30 * time.Second, Transport: transport}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		return validateRecoveryURL(req.URL)
	}
	return &KyRecoveryClient{
		client: client,
	}
}

func validateRecoveryURL(u *url.URL) error {
	if u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("recovery URL must be an HTTPS URL without credentials")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !isPublicIP(ip) {
		return errors.New("recovery URL cannot target a private or reserved address")
	}
	return nil
}

func isPublicIP(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

// PairingResult is what a completed pairing yields: the bearer token for deposits and the
// suite recovery public key with its custodian topology. A claim that returns no key is not a
// completed pairing.
type PairingResult struct {
	APIToken string
	Key      RecoveryKey
}

// ClaimPairing exchanges a 6-digit ephemeral pairing PIN with KyRecovery server for a permanent
// API bearer token and the suite recovery public key to seal backups to.
func (c *KyRecoveryClient) ClaimPairing(ctx context.Context, serverURL, pairingCode, appName string) (PairingResult, error) {
	serverURL = strings.TrimRight(serverURL, "/")
	endpoint := fmt.Sprintf("%s/api/pairing/claim", serverURL)
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil || validateRecoveryURL(parsedEndpoint) != nil {
		return PairingResult{}, errors.New("invalid recovery URL")
	}

	reqBody := map[string]string{
		"pairing_code": strings.TrimSpace(pairingCode),
		"app_name":     appName,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return PairingResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return PairingResult{}, fmt.Errorf("pairing claim request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return PairingResult{}, fmt.Errorf("pairing claim rejected (%d): %s", resp.StatusCode, string(b))
	}

	var claimResp struct {
		APIToken          string `json:"api_token"`
		Status            string `json:"status"`
		RecoveryPublicKey string `json:"recovery_public_key"` // std base64 of 1216 bytes
		Threshold         int    `json:"threshold"`
		TotalShares       int    `json:"total_shares"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&claimResp); err != nil {
		return PairingResult{}, err
	}
	if claimResp.APIToken == "" {
		return PairingResult{}, errors.New("empty api_token in claim response")
	}
	pkBytes, err := base64.StdEncoding.DecodeString(claimResp.RecoveryPublicKey)
	if err != nil {
		return PairingResult{}, fmt.Errorf("recovery_public_key: %w", err)
	}
	pk, err := recoverykey.ParsePublicKey(pkBytes)
	if err != nil {
		return PairingResult{}, fmt.Errorf("recovery_public_key: %w", err)
	}
	return PairingResult{
		APIToken: claimResp.APIToken,
		Key:      RecoveryKey{Public: pk, Threshold: claimResp.Threshold, TotalShares: claimResp.TotalShares},
	}, nil
}

// PushBackupPayload defines the self-declaring backup ingest schema.
type PushBackupPayload struct {
	ServiceName        string                 `json:"service_name"`
	AppVersion         string                 `json:"app_version"`
	Threshold          int                    `json:"threshold"`
	TotalShares        int                    `json:"total_shares"`
	Files              []PushBackupFile       `json:"files"`
	Dependencies       map[string]interface{} `json:"dependencies"`
	VerificationRecipe map[string]interface{} `json:"verification_recipe"`
}

type PushBackupFile struct {
	Path       string `json:"path"`
	DataBase64 string `json:"data_base64"`
	Mode       int64  `json:"mode"`
}

type PushResponse struct {
	Status       string      `json:"status"`
	CapsuleID    string      `json:"capsule_id"`
	ServiceName  string      `json:"service_name"`
	SizeBytes    int64       `json:"size_bytes"`
	PayloadHash  string      `json:"payload_hash"`
	DrillSummary DrillResult `json:"drill_summary"`
}

// PushBackup pushes a self-declaring backup payload to the remote KyRecovery instance.
func (c *KyRecoveryClient) PushBackup(ctx context.Context, serverURL, apiToken string, payload PushBackupPayload) (*PushResponse, error) {
	serverURL = strings.TrimRight(serverURL, "/")
	endpoint := fmt.Sprintf("%s/api/backup/push", serverURL)
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil || validateRecoveryURL(parsedEndpoint) != nil {
		return nil, errors.New("invalid recovery URL")
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("backup push failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("backup push rejected (%d): %s", resp.StatusCode, string(b))
	}

	var pushResp PushResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&pushResp); err != nil {
		return nil, err
	}

	return &pushResp, nil
}

// BuildLocalPayload collects local application files (SQLite database, configuration) into a self-declaring backup package.
func BuildLocalPayload(cfg *config.Config, appVersion string) (*PushBackupPayload, error) {
	var files []PushBackupFile
	var sqlitePaths []string

	// If SQLite is used, read the database file
	if strings.ToLower(cfg.Database.Driver) == "sqlite" {
		dbPath := cfg.Database.DSN
		if idx := strings.Index(dbPath, "?"); idx != -1 {
			dbPath = dbPath[:idx]
		}
		if dbBytes, err := os.ReadFile(dbPath); err == nil {
			relPath := "data/ky_server.db"
			files = append(files, PushBackupFile{
				Path:       relPath,
				DataBase64: base64.StdEncoding.EncodeToString(dbBytes),
				Mode:       0600,
			})
			sqlitePaths = append(sqlitePaths, relPath)
		}
	}

	// Include config manifest snapshot
	cfgJSON, _ := json.MarshalIndent(map[string]any{
		"server":   cfg.Server,
		"database": map[string]any{"driver": cfg.Database.Driver},
	}, "", "  ")

	files = append(files, PushBackupFile{
		Path:       "config/settings.json",
		DataBase64: base64.StdEncoding.EncodeToString(cfgJSON),
		Mode:       0600,
	})

	var reqFiles []string
	for _, f := range files {
		reqFiles = append(reqFiles, f.Path)
	}

	payload := &PushBackupPayload{
		ServiceName: cfg.Server.AppName,
		AppVersion:  appVersion,
		Threshold:   2,
		TotalShares: 3,
		Files:       files,
		Dependencies: map[string]interface{}{
			"ports": []int{cfg.Server.Port},
			"env":   []string{"KY_PORT", "KY_DB_DRIVER"},
		},
		VerificationRecipe: map[string]interface{}{
			"check_sqlite_integrity": len(sqlitePaths) > 0,
			"sqlite_paths":           sqlitePaths,
			"required_files":         reqFiles,
			"expected_env":           []string{"KY_PORT", "KY_DB_DRIVER"},
			"expected_ports":         []int{cfg.Server.Port},
		},
	}

	return payload, nil
}
