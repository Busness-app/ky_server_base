package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky_server_base/internal/config"
)

// encryptionKeyPath is where a restore drops the key that decrypts users.totp_secret_enc,
// relative to the restore target: the same <DataDir>/encryption.key config.LoadFromEnv reads.
const encryptionKeyPath = "data/encryption.key"

// recoveryPubPath is where a restore drops the suite recovery public key, matching the
// <DataDir>/recovery.pub that RecoveryKeyPath reads.
const recoveryPubPath = "data/recovery.pub"

// uploadTimeout bounds one deposit. A container is at most 384 MiB and kyrecovery gives the
// read fifteen minutes; the claim keeps the short timeout because it carries a few hundred bytes.
const uploadTimeout = 15 * time.Minute

// KyRecoveryClient is the product half of the pairing and deposit contract.
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

// endpoint joins the server URL and an API path after checking the URL is one the client is
// willing to talk to.
func endpoint(serverURL, path string) (string, error) {
	u := strings.TrimRight(serverURL, "/") + path
	parsed, err := url.Parse(u)
	if err != nil || validateRecoveryURL(parsed) != nil {
		return "", errors.New("invalid recovery URL")
	}
	return u, nil
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
//
// serviceName is sent explicitly: kyrecovery pins whatever the claimer sends and refuses every
// later deposit whose manifest names a different service, so it must be the same value Seal
// is given.
func (c *KyRecoveryClient) ClaimPairing(ctx context.Context, serverURL, pairingCode, serviceName, appName string) (PairingResult, error) {
	u, err := endpoint(serverURL, "/api/pairing/claim")
	if err != nil {
		return PairingResult{}, err
	}

	reqBody := map[string]string{
		"pairing_code": strings.TrimSpace(pairingCode),
		"service_name": serviceName,
		"app_name":     appName,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(bodyBytes))
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
		return PairingResult{}, fmt.Errorf("pairing claim rejected (%d): %s", resp.StatusCode, remoteMessage(resp.Body))
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
	if !validTopology(claimResp.Threshold, claimResp.TotalShares) {
		return PairingResult{}, fmt.Errorf("claim response: %d-of-%d is not a custodian topology", claimResp.Threshold, claimResp.TotalShares)
	}
	return PairingResult{
		APIToken: claimResp.APIToken,
		Key:      RecoveryKey{Public: pk, Threshold: claimResp.Threshold, TotalShares: claimResp.TotalShares},
	}, nil
}

// ErrRemote marks an error that came from the wire or from KyRecovery itself, as opposed to
// one raised here before any byte was sent. Handlers answer the two differently.
var ErrRemote = errors.New("backup: KyRecovery")

// Receipt is kyrecovery's record of one deposit. Digest and SizeBytes are the only values
// the store computed itself; a restore compares CapsuleID against the capsule in hand.
type Receipt struct {
	CapsuleID   string    `json:"capsule_id"`
	Digest      string    `json:"digest"`
	SizeBytes   int64     `json:"size_bytes"`
	DepositedAt time.Time `json:"deposited_at"`
}

// Deposit hands a sealed container to kyrecovery and returns its receipt. The container is
// opaque to the store; the receipt's digest is checked against the bytes sent so a deposit
// counts only when kyrecovery stored exactly what left here. 200 is kyrecovery re-sending the
// receipt for bytes it already holds, which is a success.
func (c *KyRecoveryClient) Deposit(ctx context.Context, serverURL, apiToken string, container []byte) (Receipt, error) {
	u, err := endpoint(serverURL, "/api/backup/deposit")
	if err != nil {
		return Receipt{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(container))
	if err != nil {
		return Receipt{}, err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/octet-stream")

	// The client's own timeout is sized for a claim; the upload budget is the context above.
	upload := *c.client
	upload.Timeout = 0
	resp, err := upload.Do(req)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: deposit request failed: %w", ErrRemote, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return Receipt{}, fmt.Errorf("%w: deposit rejected (%d): %s", ErrRemote, resp.StatusCode, remoteMessage(resp.Body))
	}
	var rcpt Receipt
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&rcpt); err != nil {
		return Receipt{}, fmt.Errorf("%w: deposit receipt: %w", ErrRemote, err)
	}
	sum := sha256.Sum256(container)
	if want := hex.EncodeToString(sum[:]); rcpt.Digest != want {
		return Receipt{}, fmt.Errorf("%w: deposit receipt digest %s does not match the container sent (%s)", ErrRemote, rcpt.Digest, want)
	}
	if rcpt.SizeBytes != int64(len(container)) {
		return Receipt{}, fmt.Errorf("%w: deposit receipt size %d does not match the %d bytes sent", ErrRemote, rcpt.SizeBytes, len(container))
	}
	if rcpt.CapsuleID == "" {
		return Receipt{}, fmt.Errorf("%w: deposit receipt has no capsule_id", ErrRemote)
	}
	return rcpt, nil
}

// auditTextLimit bounds any text that reaches the audit log from outside the process. It sits
// under AuditColumnWidth with room for the "..." marker and a multi-byte rune at the cut.
const auditTextLimit = 200

// AuditColumnWidth is the widest value the Postgres audit columns accept (VARCHAR(255)).
// Anything longer makes the insert fail, and a failed insert is a missing audit row.
const AuditColumnWidth = 255

// AuditSafe makes a string fit for an audit record: printable characters only, cut at
// auditTextLimit. Remote bodies and operator input go through it before they are stored,
// because the audit table rides inside every capsule and grows with whatever lands in it.
func AuditSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= auditTextLimit {
			b.WriteString("...")
			break
		}
		switch {
		case r == '\n' || r == '\t':
			b.WriteByte(' ')
		case unicode.IsPrint(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// remoteMessage is what a KyRecovery error body contributes to an error: a bounded, printable
// excerpt, never the raw body.
func remoteMessage(body io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(body, 4<<10))
	return AuditSafe(string(b))
}

// ErrNoDatabaseSnapshot is returned when the payload cannot carry a consistent copy of the
// database, so a capsule without one is never sealed as if it were a backup.
var ErrNoDatabaseSnapshot = errors.New("backup: no consistent database snapshot for this driver")

// Payload is what a backup carries: the members and the metadata the manifest records.
type Payload struct {
	ServiceName        string
	AppVersion         string
	Files              []BackupFile
	Dependencies       map[string]any
	VerificationRecipe map[string]any
}

// BuildLocalPayload collects local application files (SQLite database, configuration). It
// carries nothing secret: sealing callers add the sealed-only members with AppendSealedOnlyFiles.
func BuildLocalPayload(cfg *config.Config, appVersion string) (*Payload, error) {
	if strings.ToLower(cfg.Database.Driver) != "sqlite" {
		return nil, fmt.Errorf("%w: %s", ErrNoDatabaseSnapshot, cfg.Database.Driver)
	}
	dbBytes, err := snapshotSQLite(cfg.Database.DSN, cfg.Database.DataDir)
	if err != nil {
		return nil, err
	}
	const dbPath = "data/ky_server.db"
	files := []BackupFile{{Path: dbPath, Data: dbBytes, Mode: 0600}}
	sqlitePaths := []string{dbPath}

	// Include config manifest snapshot
	cfgJSON, _ := json.MarshalIndent(map[string]any{
		"server":   cfg.Server,
		"database": map[string]any{"driver": cfg.Database.Driver},
	}, "", "  ")
	files = append(files, BackupFile{Path: "config/settings.json", Data: cfgJSON, Mode: 0600})

	payload := &Payload{
		ServiceName: cfg.Server.AppName,
		AppVersion:  appVersion,
		Files:       files,
		Dependencies: map[string]any{
			"ports": []int{cfg.Server.Port},
			"env":   []string{"KY_PORT", "KY_DB_DRIVER"},
		},
		VerificationRecipe: map[string]any{
			"check_sqlite_integrity": true,
			"sqlite_paths":           sqlitePaths,
			"required_files":         requiredFiles(files),
			"expected_env":           []string{"KY_PORT", "KY_DB_DRIVER"},
			"expected_ports":         []int{cfg.Server.Port},
		},
	}

	return payload, nil
}

// snapshotSQLite returns a consistent single-file copy of the live database. The store runs
// in WAL mode, so reading the main file misses every commit still in the -wal and can tear
// under a concurrent checkpoint; VACUUM INTO writes a transactionally consistent image.
func snapshotSQLite(dsn, dataDir string) ([]byte, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	dir, err := os.MkdirTemp(dataDir, "snapshot-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "ky_server.db")
	// VACUUM INTO takes a filename expression, not a bound parameter.
	if _, err := db.Exec("VACUUM INTO '" + strings.ReplaceAll(path, "'", "''") + "'"); err != nil {
		return nil, fmt.Errorf("backup: database snapshot: %w", err)
	}
	return os.ReadFile(path)
}

func requiredFiles(files []BackupFile) []string {
	req := make([]string, 0, len(files))
	for _, f := range files {
		req = append(req, f.Path)
	}
	return req
}

// AppendSealedOnlyFiles adds the payload members that may only ever travel inside a sealed
// capsule, and re-derives required_files so a restore drill still checks for them. Nothing
// that returns from here may leave the process except through Seal.
//
// The encryption key must ride along: users.totp_secret_enc is AES-GCM under it, so a capsule
// without it restores a database whose MFA secrets are unreadable forever. The capsule is
// sealed to the suite recovery public key, so only k custodians together open it, which is
// exactly what that key is for. Spelled the way keyfile.LoadOrCreate reads it back.
//
// The suite recovery public key rides along when this instance is paired. Without it a restore
// comes back with the settings pin but no file, which reads as "not paired" and steers the
// operator into a re-pair. Unpaired instances simply omit it, so a drill still runs.
func AppendSealedOnlyFiles(cfg *config.Config, payload *Payload) error {
	if len(cfg.Security.EncryptionKey) != 32 {
		return fmt.Errorf("backup: encryption key is %d bytes, want 32; refusing to seal a capsule that cannot decrypt what it restores", len(cfg.Security.EncryptionKey))
	}
	payload.Files = append(payload.Files, BackupFile{
		Path: encryptionKeyPath,
		Data: []byte(hex.EncodeToString(cfg.Security.EncryptionKey) + "\n"),
		Mode: 0600,
	})

	if pub, err := os.ReadFile(RecoveryKeyPath(cfg.Database.DataDir)); err == nil {
		payload.Files = append(payload.Files, BackupFile{Path: recoveryPubPath, Data: pub, Mode: 0600})
	}

	payload.VerificationRecipe["required_files"] = requiredFiles(payload.Files)
	return nil
}

// CollectSealable is the payload every sealing caller uses: the local files plus the
// sealed-only members. It never reaches the wire except inside a capsule.
func CollectSealable(cfg *config.Config, appVersion string) (*Payload, error) {
	payload, err := BuildLocalPayload(cfg, appVersion)
	if err != nil {
		return nil, err
	}
	if err := AppendSealedOnlyFiles(cfg, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
