package metocean

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Kafka SASL mechanisms supported by the bridge.
const (
	SASLPlain       = "plain"
	SASLScramSHA256 = "scram-sha-256"
	SASLScramSHA512 = "scram-sha-512"
)

// Config is the validated met-ocean bridge configuration. Every value is
// operator-supplied through the environment; there are no defaults for
// security paths and the bridge fails closed on any gap.
type Config struct {
	// Kafka consumer (SASL/TLS, env-only).
	KafkaBrokers  []string
	KafkaTopic    string
	KafkaGroupID  string
	KafkaDLQTopic string
	SASLMechanism string
	SASLUsername  string
	SASLPassword  string
	TLSCAFile     string
	TLSCertFile   string
	TLSKeyFile    string

	// KeyDirectoryPath is the mounted fleet public-key directory JSON
	// (KEY_DIRECTORY_PATH); verification fails closed without it.
	KeyDirectoryPath string

	// Temporal wiring for the per-route advisory workflows.
	TemporalAddress   string
	TemporalNamespace string
	TemporalTaskQueue string

	// ZoneRoutes maps hazard zone ids to the ferry route references they
	// cover. An advisory for an unmapped zone is dead-lettered explicitly
	// (reason unmapped-zone), never silently dropped and never guessed.
	ZoneRoutes map[string][]string

	// SuspendSeverities are the CAP severities that suspend departures;
	// lower-severity advisories are recorded and metered but do not suspend.
	SuspendSeverities map[string]struct{}
}

// LoadConfig reads and validates the bridge environment, failing closed on
// any missing or malformed value.
func LoadConfig() (Config, error) {
	config := Config{}
	var err error

	brokers := strings.TrimSpace(os.Getenv("MET_OCEAN_KAFKA_BROKERS"))
	if brokers == "" {
		return Config{}, errors.New("MET_OCEAN_KAFKA_BROKERS is required")
	}
	for _, broker := range strings.Split(brokers, ",") {
		broker = strings.TrimSpace(broker)
		if broker == "" {
			return Config{}, errors.New("MET_OCEAN_KAFKA_BROKERS contains an empty address")
		}
		config.KafkaBrokers = append(config.KafkaBrokers, broker)
	}

	config.KafkaTopic = strings.TrimSpace(os.Getenv("MET_OCEAN_KAFKA_TOPIC"))
	if config.KafkaTopic == "" {
		return Config{}, errors.New("MET_OCEAN_KAFKA_TOPIC is required")
	}
	if config.KafkaTopic != AdvisoryTopic {
		return Config{}, fmt.Errorf("MET_OCEAN_KAFKA_TOPIC %q is not the approved advisory topic %q", config.KafkaTopic, AdvisoryTopic)
	}
	config.KafkaGroupID = strings.TrimSpace(os.Getenv("MET_OCEAN_KAFKA_GROUP_ID"))
	if config.KafkaGroupID == "" {
		return Config{}, errors.New("MET_OCEAN_KAFKA_GROUP_ID is required")
	}
	config.KafkaDLQTopic = strings.TrimSpace(os.Getenv("MET_OCEAN_KAFKA_DLQ_TOPIC"))
	if config.KafkaDLQTopic == "" {
		return Config{}, errors.New("MET_OCEAN_KAFKA_DLQ_TOPIC is required (fail-closed: rejections are dead-lettered, never dropped)")
	}
	if config.KafkaDLQTopic == config.KafkaTopic {
		return Config{}, errors.New("MET_OCEAN_KAFKA_DLQ_TOPIC must differ from MET_OCEAN_KAFKA_TOPIC")
	}

	config.SASLMechanism = strings.TrimSpace(os.Getenv("MET_OCEAN_KAFKA_SASL_MECHANISM"))
	config.SASLUsername = strings.TrimSpace(os.Getenv("MET_OCEAN_KAFKA_SASL_USERNAME"))
	config.SASLPassword = os.Getenv("MET_OCEAN_KAFKA_SASL_PASSWORD")
	switch config.SASLMechanism {
	case SASLPlain, SASLScramSHA256, SASLScramSHA512:
		if config.SASLUsername == "" || config.SASLPassword == "" {
			return Config{}, errors.New("MET_OCEAN_KAFKA_SASL_USERNAME and MET_OCEAN_KAFKA_SASL_PASSWORD are required when SASL is configured")
		}
	case "":
		if config.SASLUsername != "" || config.SASLPassword != "" {
			return Config{}, errors.New("SASL credentials require MET_OCEAN_KAFKA_SASL_MECHANISM")
		}
	default:
		return Config{}, fmt.Errorf("MET_OCEAN_KAFKA_SASL_MECHANISM %q is not plain, scram-sha-256 or scram-sha-512", config.SASLMechanism)
	}

	config.TLSCAFile = strings.TrimSpace(os.Getenv("MET_OCEAN_KAFKA_TLS_CA_FILE"))
	config.TLSCertFile = strings.TrimSpace(os.Getenv("MET_OCEAN_KAFKA_TLS_CERT_FILE"))
	config.TLSKeyFile = strings.TrimSpace(os.Getenv("MET_OCEAN_KAFKA_TLS_KEY_FILE"))
	if (config.TLSCertFile == "") != (config.TLSKeyFile == "") {
		return Config{}, errors.New("MET_OCEAN_KAFKA_TLS_CERT_FILE and MET_OCEAN_KAFKA_TLS_KEY_FILE must be set together")
	}
	if config.SASLMechanism == "" && config.TLSCAFile == "" && config.TLSCertFile == "" {
		return Config{}, errors.New("Kafka transport security is required: configure SASL and/or TLS (fail-closed: no plaintext admission)")
	}

	config.KeyDirectoryPath = strings.TrimSpace(os.Getenv("KEY_DIRECTORY_PATH"))
	if config.KeyDirectoryPath == "" {
		return Config{}, errors.New("KEY_DIRECTORY_PATH is required (fail-closed: provenance verification is mandatory)")
	}

	config.TemporalAddress = strings.TrimSpace(os.Getenv("TEMPORAL_ADDRESS"))
	config.TemporalNamespace = strings.TrimSpace(os.Getenv("TEMPORAL_NAMESPACE"))
	config.TemporalTaskQueue = strings.TrimSpace(os.Getenv("MET_OCEAN_TEMPORAL_TASK_QUEUE"))
	if config.TemporalAddress == "" || config.TemporalNamespace == "" || config.TemporalTaskQueue == "" {
		return Config{}, errors.New("TEMPORAL_ADDRESS, TEMPORAL_NAMESPACE and MET_OCEAN_TEMPORAL_TASK_QUEUE are required")
	}

	if config.ZoneRoutes, err = parseZoneRoutes(os.Getenv("MET_OCEAN_ZONE_ROUTE_MAP")); err != nil {
		return Config{}, err
	}
	if config.SuspendSeverities, err = parseSeverities(os.Getenv("MET_OCEAN_SUSPEND_SEVERITIES")); err != nil {
		return Config{}, err
	}
	return config, nil
}

// parseZoneRoutes parses the zone-to-routes JSON document
// ({"hz-zone": ["route-a", "route-b"]}). It fails closed on malformed JSON,
// empty identifiers, duplicate routes and an empty map.
func parseZoneRoutes(raw string) (map[string][]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("MET_OCEAN_ZONE_ROUTE_MAP is required (fail-closed: hazard zones never map to routes by guesswork)")
	}
	var document map[string][]string
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("MET_OCEAN_ZONE_ROUTE_MAP is not valid JSON: %w", err)
	}
	if len(document) == 0 {
		return nil, errors.New("MET_OCEAN_ZONE_ROUTE_MAP must map at least one hazard zone")
	}
	zoneRoutes := make(map[string][]string, len(document))
	for zone, routes := range document {
		if strings.TrimSpace(zone) == "" || zone != strings.TrimSpace(zone) {
			return nil, fmt.Errorf("MET_OCEAN_ZONE_ROUTE_MAP zone %q is not canonical non-empty text", zone)
		}
		if len(routes) == 0 {
			return nil, fmt.Errorf("MET_OCEAN_ZONE_ROUTE_MAP zone %q maps no routes", zone)
		}
		seen := make(map[string]struct{}, len(routes))
		canonical := make([]string, 0, len(routes))
		for _, route := range routes {
			if strings.TrimSpace(route) == "" || route != strings.TrimSpace(route) {
				return nil, fmt.Errorf("MET_OCEAN_ZONE_ROUTE_MAP zone %q route %q is not canonical non-empty text", zone, route)
			}
			if _, duplicate := seen[route]; duplicate {
				return nil, fmt.Errorf("MET_OCEAN_ZONE_ROUTE_MAP zone %q lists route %q twice", zone, route)
			}
			seen[route] = struct{}{}
			canonical = append(canonical, route)
		}
		sort.Strings(canonical)
		zoneRoutes[zone] = canonical
	}
	return zoneRoutes, nil
}

// parseSeverities parses the comma-separated CAP severities that suspend
// departures (default "Severe,Extreme": the bridge errs toward suspending on
// high-impact advisories only). Unknown severities fail closed.
func parseSeverities(raw string) (map[string]struct{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "Severe,Extreme"
	}
	parsed := make(map[string]struct{})
	for _, severity := range strings.Split(raw, ",") {
		severity = strings.TrimSpace(severity)
		if _, ok := severities[severity]; !ok || severity == "Unknown" {
			return nil, fmt.Errorf("MET_OCEAN_SUSPEND_SEVERITIES entry %q is not a CAP severity (Minor, Moderate, Severe, Extreme)", severity)
		}
		parsed[severity] = struct{}{}
	}
	return parsed, nil
}

// RoutesForZone resolves the ferry routes covered by one hazard zone.
func (config Config) RoutesForZone(zoneID string) ([]string, bool) {
	routes, ok := config.ZoneRoutes[zoneID]
	return routes, ok
}

// SuspendsOn reports whether advisories of this severity suspend departures.
func (config Config) SuspendsOn(severity string) bool {
	_, ok := config.SuspendSeverities[severity]
	return ok
}
