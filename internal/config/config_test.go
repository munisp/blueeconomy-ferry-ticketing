package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func validEnv(t *testing.T) {
	t.Helper()
	t.Setenv("FERRY_LISTEN_ADDRESS", ":8080")
	t.Setenv("FERRY_DATABASE_URL", "postgres://localhost/ferries")
	t.Setenv("FERRY_MANIFEST_SALT", "0123456789abcdef")
	t.Setenv("FERRY_MANIFEST_COMPLETENESS_KPI", "0.95")
	t.Setenv("FERRY_AUTH_MODE", "jwt")
	t.Setenv("FERRY_OIDC_ISSUER", "https://keycloak.example/realms/blueeconomy")
	t.Setenv("FERRY_OIDC_AUDIENCE", "ferry-ticketing")
	t.Setenv("FERRY_OIDC_JWKS_URL", "https://keycloak.example/realms/blueeconomy/protocol/openid-connect/certs")
	t.Setenv("FERRY_TB_ADDRESS", "127.0.0.1:3000")
	t.Setenv("FERRY_TB_CLUSTER_ID", "0")
	t.Setenv("FERRY_TB_LEDGER", "7")
	t.Setenv("FERRY_TB_CODE", "9")
	t.Setenv("FERRY_TB_PASSENGER_CLEARING_ACCOUNT", "00000000000000000000000000000001")
	t.Setenv("FERRY_TB_OPERATOR_REVENUE_ACCOUNT", "00000000000000000000000000000002")
	t.Setenv("FERRY_TB_AGENT_FLOAT_ACCOUNT", "00000000000000000000000000000003")
	t.Setenv("FERRY_TB_MINISTRY_SUBSIDY_ACCOUNT", "00000000000000000000000000000004")
	t.Setenv("FERRY_TB_PLATFORM_FEE_ACCOUNT", "00000000000000000000000000000005")
	t.Setenv("FERRY_TB_PENDING_TIMEOUT_SECONDS", "900")
	t.Setenv("FERRY_PASS_SIGNING_KEY_FILE", "/run/secrets/pass-signing-key")
	t.Setenv("FERRY_TOPUP_WEBHOOK_HMAC_SECRET", "webhook-hmac-secret-0123456789")
	t.Setenv("FERRY_TICKET_SIGNING_KEY_FILE", "/run/secrets/ticket-signing-key")
	t.Setenv("FERRY_TICKET_WINDOW_SECRET", "window-secret-0123456789")
}

func TestLoadValidatesJWTMode(t *testing.T) {
	validEnv(t)
	config, err := Load()
	require.NoError(t, err)
	require.Equal(t, ":8080", config.ListenAddress)
	require.Equal(t, "jwt", config.AuthMode)
	require.InDelta(t, 0.95, config.CompletenessKPI, 0.0001)
	require.Equal(t, uint32(7), config.TigerBeetleLedger)
	require.Equal(t, uint16(9), config.TigerBeetleCode)
	require.Equal(t, uint32(900), config.PendingTransferTimeoutSeconds)
}

// TestVoidDualControlThresholdDefaultsFailClosed pins the money-path knob:
// unset means dual control on every sold-ticket void (threshold 0), an
// explicit value relaxes it, and a malformed value fails closed.
func TestVoidDualControlThresholdDefaultsFailClosed(t *testing.T) {
	validEnv(t)
	config, err := Load()
	require.NoError(t, err)
	require.Zero(t, config.VoidDualControlThresholdNGNMinor, "unset threshold fails closed to dual control on every sold void")

	validEnv(t)
	t.Setenv("FERRY_VOID_DUAL_CONTROL_THRESHOLD_NGN_MINOR", "5000000")
	config, err = Load()
	require.NoError(t, err)
	require.Equal(t, int64(5000000), config.VoidDualControlThresholdNGNMinor)

	validEnv(t)
	t.Setenv("FERRY_VOID_DUAL_CONTROL_THRESHOLD_NGN_MINOR", "-1")
	_, err = Load()
	require.Error(t, err, "negative threshold fails closed")

	validEnv(t)
	t.Setenv("FERRY_VOID_DUAL_CONTROL_THRESHOLD_NGN_MINOR", "not-a-number")
	_, err = Load()
	require.Error(t, err, "malformed threshold fails closed")
}

// TestLegacyUnsignedEmbarkOptIn pins the FE-8 knob: only an explicit "true"
// relaxes the signed-artifact-only posture; unset/false is off and anything
// malformed fails closed.
func TestLegacyUnsignedEmbarkOptIn(t *testing.T) {
	validEnv(t)
	config, err := Load()
	require.NoError(t, err)
	require.False(t, config.AllowLegacyUnsignedEmbark, "legacy embark is off by default")

	validEnv(t)
	t.Setenv("FERRY_ALLOW_LEGACY_UNSIGNED_EMBARK", "true")
	config, err = Load()
	require.NoError(t, err)
	require.True(t, config.AllowLegacyUnsignedEmbark)

	validEnv(t)
	t.Setenv("FERRY_ALLOW_LEGACY_UNSIGNED_EMBARK", "false")
	config, err = Load()
	require.NoError(t, err)
	require.False(t, config.AllowLegacyUnsignedEmbark)

	validEnv(t)
	t.Setenv("FERRY_ALLOW_LEGACY_UNSIGNED_EMBARK", "yes")
	_, err = Load()
	require.Error(t, err, "malformed opt-in fails closed")
}

func TestLoadFailsClosedOnMissingValues(t *testing.T) {
	validEnv(t)
	t.Setenv("FERRY_DATABASE_URL", "")
	_, err := Load()
	require.Error(t, err)

	validEnv(t)
	t.Setenv("FERRY_MANIFEST_SALT", "short")
	_, err = Load()
	require.Error(t, err, "short salt fails closed")

	validEnv(t)
	t.Setenv("FERRY_TB_ADDRESS", "")
	_, err = Load()
	require.Error(t, err, "unconfigured TigerBeetle fails closed")

	validEnv(t)
	t.Setenv("FERRY_MANIFEST_COMPLETENESS_KPI", "1.5")
	_, err = Load()
	require.Error(t, err)

	validEnv(t)
	t.Setenv("FERRY_AUTH_MODE", "none")
	_, err = Load()
	require.Error(t, err)

	validEnv(t)
	t.Setenv("FERRY_OIDC_JWKS_URL", "http://insecure.example/jwks")
	_, err = Load()
	require.Error(t, err, "JWKS must be HTTPS")
}

func TestLoadTicketProofValidation(t *testing.T) {
	validEnv(t)
	config, err := Load()
	require.NoError(t, err)
	require.Equal(t, "/run/secrets/ticket-signing-key", config.TicketSigningKeyFile)
	require.Equal(t, uint32(1), config.TicketRotationEpoch, "epoch defaults to 1 on first deployment")

	// No signing key file: fail closed.
	validEnv(t)
	t.Setenv("FERRY_TICKET_SIGNING_KEY_FILE", "")
	_, err = Load()
	require.Error(t, err)

	// Short window secret: fail closed.
	validEnv(t)
	t.Setenv("FERRY_TICKET_WINDOW_SECRET", "short")
	_, err = Load()
	require.Error(t, err)

	// Rotation grace requires the previous key file, and vice versa.
	validEnv(t)
	t.Setenv("FERRY_TICKET_PREVIOUS_KEY_GRACE_UNTIL", "2026-10-01T00:00:00Z")
	_, err = Load()
	require.Error(t, err)

	validEnv(t)
	t.Setenv("FERRY_TICKET_PREVIOUS_SIGNING_KEY_FILE", "/run/secrets/ticket-signing-key-prev")
	t.Setenv("FERRY_TICKET_PREVIOUS_KEY_GRACE_UNTIL", "")
	_, err = Load()
	require.Error(t, err, "previous key without grace deadline fails closed")

	validEnv(t)
	t.Setenv("FERRY_TICKET_PREVIOUS_SIGNING_KEY_FILE", "/run/secrets/ticket-signing-key-prev")
	t.Setenv("FERRY_TICKET_PREVIOUS_KEY_GRACE_UNTIL", "not-a-time")
	_, err = Load()
	require.Error(t, err)

	validEnv(t)
	t.Setenv("FERRY_TICKET_PREVIOUS_SIGNING_KEY_FILE", "/run/secrets/ticket-signing-key-prev")
	t.Setenv("FERRY_TICKET_PREVIOUS_KEY_GRACE_UNTIL", "2026-10-01T00:00:00Z")
	t.Setenv("FERRY_TICKET_ROTATION_EPOCH", "2")
	config, err = Load()
	require.NoError(t, err)
	require.Equal(t, uint32(2), config.TicketRotationEpoch)
	require.Equal(t, "2026-10-01T00:00:00Z", config.TicketPreviousKeyGraceUntil.Format(time.RFC3339))
}

func TestLoadTrustedProxyMode(t *testing.T) {
	validEnv(t)
	t.Setenv("FERRY_AUTH_MODE", "trusted_proxy")
	t.Setenv("FERRY_TRUSTED_PROXY_IDENTITY", "edge-1")
	t.Setenv("FERRY_TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 192.168.0.0/16")
	config, err := Load()
	require.NoError(t, err)
	require.Len(t, config.TrustedProxyCIDRs, 2)

	t.Setenv("FERRY_TRUSTED_PROXY_CIDRS", "")
	_, err = Load()
	require.Error(t, err)
}
