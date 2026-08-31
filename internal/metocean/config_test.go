package metocean

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// requiredEnv is the minimal valid bridge environment.
func requiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("MET_OCEAN_KAFKA_BROKERS", "kafka-1:9093,kafka-2:9093")
	t.Setenv("MET_OCEAN_KAFKA_TOPIC", AdvisoryTopic)
	t.Setenv("MET_OCEAN_KAFKA_GROUP_ID", "metocean-bridge")
	t.Setenv("MET_OCEAN_KAFKA_DLQ_TOPIC", "waterways.met_ocean.advisories.v1.dlq")
	t.Setenv("MET_OCEAN_KAFKA_SASL_MECHANISM", "scram-sha-512")
	t.Setenv("MET_OCEAN_KAFKA_SASL_USERNAME", "bridge")
	t.Setenv("MET_OCEAN_KAFKA_SASL_PASSWORD", "secret")
	t.Setenv("KEY_DIRECTORY_PATH", "/run/keys/directory.json")
	t.Setenv("TEMPORAL_ADDRESS", "temporal:7233")
	t.Setenv("TEMPORAL_NAMESPACE", "ferry")
	t.Setenv("MET_OCEAN_TEMPORAL_TASK_QUEUE", "ferry-task-queue")
	t.Setenv("MET_OCEAN_ZONE_ROUTE_MAP", `{"hz-lagos-approach":["lagos-ikoyi","lagos-apapa"]}`)
}

func TestLoadConfigValid(t *testing.T) {
	requiredEnv(t)
	config, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, []string{"kafka-1:9093", "kafka-2:9093"}, config.KafkaBrokers)
	require.Equal(t, AdvisoryTopic, config.KafkaTopic)
	require.Equal(t, "metocean-bridge", config.KafkaGroupID)
	routes, ok := config.RoutesForZone("hz-lagos-approach")
	require.True(t, ok)
	require.Equal(t, []string{"lagos-apapa", "lagos-ikoyi"}, routes)
	require.True(t, config.SuspendsOn("Severe"))
	require.True(t, config.SuspendsOn("Extreme"))
	require.False(t, config.SuspendsOn("Moderate"))
	_, ok = config.RoutesForZone("hz-unknown")
	require.False(t, ok)
}

func TestLoadConfigFailClosed(t *testing.T) {
	cases := map[string]func(){
		"no brokers":             func() { t.Setenv("MET_OCEAN_KAFKA_BROKERS", "") },
		"wrong topic":            func() { t.Setenv("MET_OCEAN_KAFKA_TOPIC", "waterways.other.v1") },
		"no group":               func() { t.Setenv("MET_OCEAN_KAFKA_GROUP_ID", "") },
		"no dlq":                 func() { t.Setenv("MET_OCEAN_KAFKA_DLQ_TOPIC", "") },
		"dlq equals topic":       func() { t.Setenv("MET_OCEAN_KAFKA_DLQ_TOPIC", AdvisoryTopic) },
		"sasl without password":  func() { t.Setenv("MET_OCEAN_KAFKA_SASL_PASSWORD", "") },
		"unknown sasl mechanism": func() { t.Setenv("MET_OCEAN_KAFKA_SASL_MECHANISM", "oauthbearer") },
		"plaintext transport": func() {
			t.Setenv("MET_OCEAN_KAFKA_SASL_MECHANISM", "")
			t.Setenv("MET_OCEAN_KAFKA_SASL_USERNAME", "")
			t.Setenv("MET_OCEAN_KAFKA_SASL_PASSWORD", "")
		},
		"no key directory":   func() { t.Setenv("KEY_DIRECTORY_PATH", "") },
		"no temporal":        func() { t.Setenv("TEMPORAL_ADDRESS", "") },
		"no zone map":        func() { t.Setenv("MET_OCEAN_ZONE_ROUTE_MAP", "") },
		"malformed zone map": func() { t.Setenv("MET_OCEAN_ZONE_ROUTE_MAP", `{"hz": []}`) },
		"duplicate route":    func() { t.Setenv("MET_OCEAN_ZONE_ROUTE_MAP", `{"hz": ["r1", "r1"]}`) },
		"unknown severity":   func() { t.Setenv("MET_OCEAN_SUSPEND_SEVERITIES", "Severe,Unknown") },
		"cert without key":   func() { t.Setenv("MET_OCEAN_KAFKA_TLS_CERT_FILE", "/run/tls/tls.crt") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			requiredEnv(t)
			mutate()
			_, err := LoadConfig()
			require.Error(t, err)
		})
	}
}

func TestLoadConfigTLSOnlyTransport(t *testing.T) {
	requiredEnv(t)
	t.Setenv("MET_OCEAN_KAFKA_SASL_MECHANISM", "")
	t.Setenv("MET_OCEAN_KAFKA_SASL_USERNAME", "")
	t.Setenv("MET_OCEAN_KAFKA_SASL_PASSWORD", "")
	t.Setenv("MET_OCEAN_KAFKA_TLS_CA_FILE", "/run/tls/ca.crt")
	config, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "/run/tls/ca.crt", config.TLSCAFile)
}

func TestLoadConfigCustomSeverities(t *testing.T) {
	requiredEnv(t)
	t.Setenv("MET_OCEAN_SUSPEND_SEVERITIES", "Moderate,Severe,Extreme")
	config, err := LoadConfig()
	require.NoError(t, err)
	require.True(t, config.SuspendsOn("Moderate"))
	require.False(t, config.SuspendsOn("Minor"))
}
