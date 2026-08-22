package sso_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/Yoshiofthewire/ky_server_base/internal/config"
	"github.com/Yoshiofthewire/ky_server_base/internal/crypto"
	"github.com/Yoshiofthewire/ky_server_base/internal/sso"
	"github.com/Yoshiofthewire/ky_server_base/internal/store"
	"github.com/Yoshiofthewire/ky_server_base/internal/testdb"
)

func TestKySignOnWebhookSync(t *testing.T) {
	st, err := store.Open(context.Background(), testdb.Config(t))
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer st.Close()

	hmacSecret := "webhook-secret-999"
	client := sso.NewKySignOnClient(config.SSOConfig{
		KySignOnHMACSecret: hmacSecret,
	}, st)

	payload := sso.KySignOnSyncPayload{
		Event:       "user.created",
		ID:          "ext-usr-456",
		Username:    "bob",
		Email:       "bob@busnes.app",
		DisplayName: "Bob Engineer",
		Role:        "user",
		Status:      "active",
		Timestamp:   time.Now().Unix(),
	}
	body, _ := json.Marshal(payload)
	sig := crypto.ComputeHMACSHA256(body, hmacSecret)

	// 1. Sync create user
	if err := client.HandleSyncWebhook(context.Background(), body, sig); err != nil {
		t.Fatalf("HandleSyncWebhook failed: %v", err)
	}

	created, err := st.Users().GetUserBySSO(context.Background(), "kysignon", "ext-usr-456")
	if err != nil {
		t.Fatalf("GetUserBySSO failed: %v", err)
	}
	if created.Username != "bob" || created.DisplayName != "Bob Engineer" {
		t.Errorf("unexpected created user: %+v", created)
	}

	// 2. Sync deactivation
	payload.Event = "user.deactivated"
	body, _ = json.Marshal(payload)
	sig = crypto.ComputeHMACSHA256(body, hmacSecret)

	if err := client.HandleSyncWebhook(context.Background(), body, sig); err != nil {
		t.Fatalf("HandleSyncWebhook deactivation failed: %v", err)
	}

	updated, _ := st.Users().GetUserBySSO(context.Background(), "kysignon", "ext-usr-456")
	if updated.Status != "inactive" {
		t.Errorf("expected inactive status, got %s", updated.Status)
	}
}

func TestSAMLServiceProvider(t *testing.T) {
	sp := sso.NewSAMLServiceProvider("https://app.busnes.app/saml/metadata", "https://app.busnes.app/saml/acs")

	metadata := sp.GenerateMetadata()
	if len(metadata) == 0 || !testing.Verbose() && len(metadata) < 50 {
		if len(metadata) == 0 {
			t.Errorf("expected non-empty metadata")
		}
	}

	rawSAML := `<?xml version="1.0"?>
<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
    <Subject>
      <NameID>charlie@busnes.app</NameID>
    </Subject>
    <AttributeStatement>
      <Attribute Name="email">
        <AttributeValue>charlie@busnes.app</AttributeValue>
      </Attribute>
      <Attribute Name="displayName">
        <AttributeValue>Charlie Manager</AttributeValue>
      </Attribute>
    </AttributeStatement>
  </Assertion>
</Response>`

	b64Response := base64.StdEncoding.EncodeToString([]byte(rawSAML))
	claims, err := sp.ParseSAMLResponse(b64Response)
	if err != nil {
		t.Fatalf("ParseSAMLResponse failed: %v", err)
	}

	if claims.Email != "charlie@busnes.app" || claims.Name != "Charlie Manager" {
		t.Errorf("unexpected SAML claims: %+v", claims)
	}
}
