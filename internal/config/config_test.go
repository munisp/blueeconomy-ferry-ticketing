package config

import (
	"testing"

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
	t.Setenv("FERRY_TB_PENDING_TIMEOUT_SECONDS", "900")
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
