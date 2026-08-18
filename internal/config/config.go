package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config encapsulates all runtime configuration for ky_server_base.
type Config struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Security SecurityConfig `json:"security"`
	SSO      SSOConfig      `json:"sso"`
	SCIM     SCIMConfig     `json:"scim"`
	Backup   BackupConfig   `json:"backup"`
	Captcha  CaptchaConfig  `json:"captcha"`
}

// ServerConfig defines HTTP and network settings.
type ServerConfig struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	AppURL       string        `json:"app_url"`
	AppName      string        `json:"app_name"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	Environment  string        `json:"environment"`
}

// DatabaseConfig holds connection settings for pluggable storage (SQLite, PostgreSQL, MySQL).
type DatabaseConfig struct {
	Driver          string        `json:"driver"` // "sqlite", "postgres", "mysql"
	DSN             string        `json:"dsn"`    // Connection string or file path
	DataDir         string        `json:"data_dir"`
	MaxOpenConns    int           `json:"max_open_conns"`
	MaxIdleConns    int           `json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`
}

// SecurityConfig holds encryption keys, cookie secrets, and session settings.
type SecurityConfig struct {
	SessionSecret string `json:"session_secret"`
	EncryptionKey string `json:"encryption_key"` // 32-byte hex for AES-256-GCM
	CookieSecure  bool   `json:"cookie_secure"`
	CookieDomain  string `json:"cookie_domain"`
	SessionTTL    time.Duration
}

// SSOConfig holds identity provider and federation parameters.
type SSOConfig struct {
	Enabled             bool   `json:"enabled"`
	KySignOnIssuer      string `json:"kysignon_issuer"`
	KySignOnClientID    string `json:"kysignon_client_id"`
	KySignOnSecret      string `json:"kysignon_secret"`
	KySignOnHMACSecret  string `json:"kysignon_hmac_secret"`
	GenericOIDCIssuer   string `json:"generic_oidc_issuer"`
	GenericOIDCClientID string `json:"generic_oidc_client_id"`
	GenericOIDCSecret   string `json:"generic_oidc_secret"`
	SAMLEntityID        string `json:"saml_entity_id"`
	SAMLMetadataURL     string `json:"saml_metadata_url"`
	AutoProvision       bool   `json:"auto_provision"`
}

// SCIMConfig holds settings for RFC 7643/7644 inbound user provisioning.
type SCIMConfig struct {
	Enabled     bool   `json:"enabled"`
	BearerToken string `json:"bearer_token"`
}

// BackupConfig holds parameters for KyBackup capsules & recovery drills.
type BackupConfig struct {
	StorageDir   string `json:"storage_dir"`
	MasterKey    string `json:"master_key"`
	AutoDrillDay int    `json:"auto_drill_day"` // day of week
}

// CaptchaConfig holds anti-abuse settings (PoW default, Turnstile, Friendly).
type CaptchaConfig struct {
	Provider     string `json:"provider"` // "pow", "turnstile", "friendly", "none"
	SiteKey      string `json:"site_key"`
	SecretKey    string `json:"secret_key"`
	DifficultyPoW int    `json:"difficulty_pow"`
}

// LoadFromEnv initializes a Config struct populated from environment variables with sensible defaults.
func LoadFromEnv() (*Config, error) {
	port := getEnvInt("KY_PORT", getEnvInt("PORT", 8080))
	host := getEnv("KY_HOST", "0.0.0.0")
	appURL := getEnv("KY_APP_URL", fmt.Sprintf("http://localhost:%d", port))
	appName := getEnv("KY_APP_NAME", "Busnes.app")
	env := getEnv("KY_ENV", "development")

	driver := strings.ToLower(getEnv("KY_DB_DRIVER", "sqlite"))
	dataDir := getEnv("KY_DATA_DIR", "./data")
	defaultDSN := fmt.Sprintf("%s/ky_server.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", dataDir)
	if driver == "postgres" || driver == "postgresql" {
		driver = "postgres"
		defaultDSN = "postgres://postgres:postgres@localhost:5432/ky_server?sslmode=disable"
	}
	dsn := getEnv("KY_DB_DSN", defaultDSN)

	sessionSecret := getEnv("KY_SESSION_SECRET", "")
	if sessionSecret == "" {
		sessionSecret = generateRandomHex(32)
	}

	encryptionKey := getEnv("KY_ENCRYPTION_KEY", "")
	if encryptionKey == "" {
		encryptionKey = generateRandomHex(32)
	}

	cfg := &Config{
		Server: ServerConfig{
			Host:         host,
			Port:         port,
			AppURL:       strings.TrimRight(appURL, "/"),
			AppName:      appName,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			Environment:  env,
		},
		Database: DatabaseConfig{
			Driver:          driver,
			DSN:             dsn,
			DataDir:         dataDir,
			MaxOpenConns:    getEnvInt("KY_DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvInt("KY_DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: 15 * time.Minute,
		},
		Security: SecurityConfig{
			SessionSecret: sessionSecret,
			EncryptionKey: encryptionKey,
			CookieSecure:  getEnvBool("KY_COOKIE_SECURE", env == "production"),
			CookieDomain:  getEnv("KY_COOKIE_DOMAIN", ""),
			SessionTTL:    7 * 24 * time.Hour,
		},
		SSO: SSOConfig{
			Enabled:             getEnvBool("KY_SSO_ENABLED", true),
			KySignOnIssuer:      getEnv("KY_KYSIGNON_ISSUER", ""),
			KySignOnClientID:    getEnv("KY_KYSIGNON_CLIENT_ID", ""),
			KySignOnSecret:      getEnv("KY_KYSIGNON_SECRET", ""),
			KySignOnHMACSecret:  getEnv("KY_KYSIGNON_HMAC_SECRET", ""),
			GenericOIDCIssuer:   getEnv("KY_OIDC_ISSUER", ""),
			GenericOIDCClientID: getEnv("KY_OIDC_CLIENT_ID", ""),
			GenericOIDCSecret:   getEnv("KY_OIDC_SECRET", ""),
			SAMLEntityID:        getEnv("KY_SAML_ENTITY_ID", ""),
			SAMLMetadataURL:     getEnv("KY_SAML_METADATA_URL", ""),
			AutoProvision:       getEnvBool("KY_SSO_AUTO_PROVISION", true),
		},
		SCIM: SCIMConfig{
			Enabled:     getEnvBool("KY_SCIM_ENABLED", true),
			BearerToken: getEnv("KY_SCIM_TOKEN", generateRandomHex(24)),
		},
		Backup: BackupConfig{
			StorageDir:   getEnv("KY_BACKUP_DIR", "./backups"),
			MasterKey:    getEnv("KY_BACKUP_KEY", encryptionKey),
			AutoDrillDay: getEnvInt("KY_BACKUP_DRILL_DAY", 0), // Sunday
		},
		Captcha: CaptchaConfig{
			Provider:      getEnv("KY_CAPTCHA_PROVIDER", "pow"),
			SiteKey:       getEnv("KY_CAPTCHA_SITE_KEY", ""),
			SecretKey:     getEnv("KY_CAPTCHA_SECRET_KEY", ""),
			DifficultyPoW: getEnvInt("KY_CAPTCHA_POW_DIFFICULTY", 4),
		},
	}

	return cfg, nil
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		if intVal, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
			return intVal
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		lower := strings.ToLower(strings.TrimSpace(val))
		return lower == "true" || lower == "1" || lower == "yes" || lower == "on"
	}
	return defaultVal
}

func generateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
