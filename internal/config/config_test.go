package config_test

import (
	"testing"

	"github.com/Busness-app/ky_server_base/internal/config"
)

func TestConfigLoadDefaults(t *testing.T) {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Server.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Server.Port)
	}
	if cfg.Database.Driver != "sqlite" {
		t.Errorf("expected default driver sqlite, got %s", cfg.Database.Driver)
	}
	if cfg.Captcha.Provider != "pow" {
		t.Errorf("expected default captcha provider pow, got %s", cfg.Captcha.Provider)
	}
}

func TestConfigLoadFromEnvOverrides(t *testing.T) {
	t.Setenv("KY_PORT", "9090")
	t.Setenv("KY_DB_DRIVER", "postgres")
	t.Setenv("KY_DB_DSN", "postgres://user:pass@localhost:5432/testdb")
	t.Setenv("KY_APP_NAME", "CustomBusnesApp")
	t.Setenv("KY_CAPTCHA_PROVIDER", "turnstile")

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Server.Port != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.Server.Port)
	}
	if cfg.Database.Driver != "postgres" {
		t.Errorf("expected driver postgres, got %s", cfg.Database.Driver)
	}
	if cfg.Database.DSN != "postgres://user:pass@localhost:5432/testdb" {
		t.Errorf("expected custom DSN, got %s", cfg.Database.DSN)
	}
	if cfg.Server.AppName != "CustomBusnesApp" {
		t.Errorf("expected custom app name, got %s", cfg.Server.AppName)
	}
	if cfg.Captcha.Provider != "turnstile" {
		t.Errorf("expected captcha provider turnstile, got %s", cfg.Captcha.Provider)
	}
}
