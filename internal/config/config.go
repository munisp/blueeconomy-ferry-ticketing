// Package config loads the ferry-api configuration from the environment.
// Every value is operator-supplied; there are no defaults for security or
// money paths and the service fails closed on any gap.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the validated ferry-api configuration.
type Config struct {
	ListenAddress   string
	DatabaseURL     string
	ManifestSalt    string
	CompletenessKPI float64

	AuthMode             string
	OIDCIssuer           string
	OIDCAudience         string
	OIDCJWKSURL          *url.URL
	OIDCCAFile           string
	TrustedProxyIdentity string
	TrustedProxyCIDRs    []*net.IPNet

	TigerBeetleAddress            string
	TigerBeetleClusterID          uint32
	TigerBeetleLedger             uint32
	TigerBeetleCode               uint16
	PassengerClearingAccount      string
	OperatorRevenueAccount        string
	AgentFloatAccount             string
	PendingTransferTimeoutSeconds uint32

	// VoidDualControlThresholdNGNMinor is the fare (kobo) at or above which
	// voiding a sold ticket requires a second officer (maker-checker).
	// Unset means 0: dual control for every PAID/ISSUED void (fail closed).
	VoidDualControlThresholdNGNMinor int64

	// AllowLegacyUnsignedEmbark opts the deployment into the deprecated
	// legacy raw-ticket-id embark path. Default off: gates must present
	// signed ticket artifacts. Sunset: the path is scheduled for removal
	// once all gates scan signed artifacts.
	AllowLegacyUnsignedEmbark bool

	TicketSigningKeyFile         string
	TicketPreviousSigningKeyFile string
	TicketPreviousKeyGraceUntil  time.Time
	TicketRotationEpoch          uint32
	TicketWindowSecret           string
}

// Load reads and validates the environment, failing closed on any missing or
// malformed value.
func Load() (Config, error) {
	config := Config{
		ListenAddress:        strings.TrimSpace(os.Getenv("FERRY_LISTEN_ADDRESS")),
		DatabaseURL:          strings.TrimSpace(os.Getenv("FERRY_DATABASE_URL")),
		ManifestSalt:         strings.TrimSpace(os.Getenv("FERRY_MANIFEST_SALT")),
		AuthMode:             strings.TrimSpace(os.Getenv("FERRY_AUTH_MODE")),
		OIDCIssuer:           strings.TrimSpace(os.Getenv("FERRY_OIDC_ISSUER")),
		OIDCAudience:         strings.TrimSpace(os.Getenv("FERRY_OIDC_AUDIENCE")),
		OIDCCAFile:           strings.TrimSpace(os.Getenv("FERRY_OIDC_CA_FILE")),
		TrustedProxyIdentity: strings.TrimSpace(os.Getenv("FERRY_TRUSTED_PROXY_IDENTITY")),
		TigerBeetleAddress:   strings.TrimSpace(os.Getenv("FERRY_TB_ADDRESS")),
	}
	if config.ListenAddress == "" {
		return Config{}, errors.New("FERRY_LISTEN_ADDRESS is required")
	}
	if config.DatabaseURL == "" {
		return Config{}, errors.New("FERRY_DATABASE_URL is required")
	}
	if len(config.ManifestSalt) < 16 {
		return Config{}, errors.New("FERRY_MANIFEST_SALT is required and must be at least 16 characters")
	}
	kpi, err := parseFraction("FERRY_MANIFEST_COMPLETENESS_KPI")
	if err != nil {
		return Config{}, err
	}
	config.CompletenessKPI = kpi

	switch config.AuthMode {
	case "jwt":
		if config.OIDCIssuer == "" || config.OIDCAudience == "" {
			return Config{}, errors.New("FERRY_OIDC_ISSUER and FERRY_OIDC_AUDIENCE are required in jwt mode")
		}
		if config.OIDCJWKSURL, err = parseHTTPSURL("FERRY_OIDC_JWKS_URL"); err != nil {
			return Config{}, err
		}
	case "trusted_proxy":
		if config.TrustedProxyIdentity == "" {
			return Config{}, errors.New("FERRY_TRUSTED_PROXY_IDENTITY is required in trusted_proxy mode")
		}
		if config.TrustedProxyCIDRs, err = parseCIDRs(os.Getenv("FERRY_TRUSTED_PROXY_CIDRS")); err != nil {
			return Config{}, err
		}
	default:
		return Config{}, errors.New("FERRY_AUTH_MODE must be jwt or trusted_proxy")
	}

	if config.TigerBeetleAddress == "" {
		return Config{}, errors.New("FERRY_TB_ADDRESS is required (fail-closed: the ledger must be configured)")
	}
	if config.TigerBeetleClusterID, err = parseUint32("FERRY_TB_CLUSTER_ID"); err != nil {
		return Config{}, err
	}
	if config.TigerBeetleLedger, err = parseNonZeroUint32("FERRY_TB_LEDGER"); err != nil {
		return Config{}, err
	}
	code, err := parseUint32("FERRY_TB_CODE")
	if err != nil || code == 0 || code > 65535 {
		return Config{}, errors.New("FERRY_TB_CODE must be a non-zero uint16")
	}
	config.TigerBeetleCode = uint16(code)
	for _, account := range []struct {
		name  string
		value *string
	}{
		{"FERRY_TB_PASSENGER_CLEARING_ACCOUNT", &config.PassengerClearingAccount},
		{"FERRY_TB_OPERATOR_REVENUE_ACCOUNT", &config.OperatorRevenueAccount},
		{"FERRY_TB_AGENT_FLOAT_ACCOUNT", &config.AgentFloatAccount},
	} {
		*account.value = strings.TrimSpace(os.Getenv(account.name))
		if *account.value == "" {
			return Config{}, fmt.Errorf("%s is required", account.name)
		}
	}
	if config.PendingTransferTimeoutSeconds, err = parseNonZeroUint32("FERRY_TB_PENDING_TIMEOUT_SECONDS"); err != nil {
		return Config{}, err
	}
	// Optional money-path knob; unset fails closed to dual control on every
	// sold-ticket void (threshold 0).
	if threshold := strings.TrimSpace(os.Getenv("FERRY_VOID_DUAL_CONTROL_THRESHOLD_NGN_MINOR")); threshold != "" {
		parsed, parseErr := strconv.ParseInt(threshold, 10, 64)
		if parseErr != nil || parsed < 0 {
			return Config{}, errors.New("FERRY_VOID_DUAL_CONTROL_THRESHOLD_NGN_MINOR must be a non-negative integer")
		}
		config.VoidDualControlThresholdNGNMinor = parsed
	}
	// Optional security knob; only an explicit "true" relaxes the default
	// signed-artifact-only posture, anything malformed fails closed.
	switch legacy := strings.ToLower(strings.TrimSpace(os.Getenv("FERRY_ALLOW_LEGACY_UNSIGNED_EMBARK"))); legacy {
	case "", "false":
		config.AllowLegacyUnsignedEmbark = false
	case "true":
		config.AllowLegacyUnsignedEmbark = true
	default:
		return Config{}, errors.New("FERRY_ALLOW_LEGACY_UNSIGNED_EMBARK must be \"true\" or \"false\"")
	}
	if err := config.loadTicketProof(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// loadTicketProof validates the signed-ticket-artifact configuration. The
// service fails closed without a signing key file and a window secret; the
// previous key (rotation grace) is optional but requires a grace deadline.
func (config *Config) loadTicketProof() error {
	config.TicketSigningKeyFile = strings.TrimSpace(os.Getenv("FERRY_TICKET_SIGNING_KEY_FILE"))
	if config.TicketSigningKeyFile == "" {
		return errors.New("FERRY_TICKET_SIGNING_KEY_FILE is required (fail-closed: no ticket signing without an injected key)")
	}
	config.TicketWindowSecret = strings.TrimSpace(os.Getenv("FERRY_TICKET_WINDOW_SECRET"))
	if len(config.TicketWindowSecret) < 16 {
		return errors.New("FERRY_TICKET_WINDOW_SECRET is required and must be at least 16 characters")
	}
	config.TicketPreviousSigningKeyFile = strings.TrimSpace(os.Getenv("FERRY_TICKET_PREVIOUS_SIGNING_KEY_FILE"))
	grace := strings.TrimSpace(os.Getenv("FERRY_TICKET_PREVIOUS_KEY_GRACE_UNTIL"))
	if config.TicketPreviousSigningKeyFile != "" {
		if grace == "" {
			return errors.New("FERRY_TICKET_PREVIOUS_KEY_GRACE_UNTIL is required when a previous signing key is configured")
		}
		deadline, err := time.Parse(time.RFC3339, grace)
		if err != nil {
			return fmt.Errorf("FERRY_TICKET_PREVIOUS_KEY_GRACE_UNTIL must be RFC3339: %w", err)
		}
		config.TicketPreviousKeyGraceUntil = deadline.UTC()
	} else if grace != "" {
		return errors.New("FERRY_TICKET_PREVIOUS_KEY_GRACE_UNTIL requires FERRY_TICKET_PREVIOUS_SIGNING_KEY_FILE")
	}
	epoch := strings.TrimSpace(os.Getenv("FERRY_TICKET_ROTATION_EPOCH"))
	if epoch == "" {
		// First deployment: epoch 1. Rotations set 2, 3, ... explicitly.
		config.TicketRotationEpoch = 1
		return nil
	}
	parsed, err := parseNonZeroUint32("FERRY_TICKET_ROTATION_EPOCH")
	if err != nil {
		return err
	}
	config.TicketRotationEpoch = parsed
	return nil
}

func parseFraction(name string) (float64, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return 0, fmt.Errorf("%s is required", name)
	}
	fraction, err := strconv.ParseFloat(value, 64)
	if err != nil || fraction <= 0 || fraction > 1 {
		return 0, fmt.Errorf("%s must be a fraction within (0, 1]", name)
	}
	return fraction, nil
}

func parseUint32(name string) (uint32, error) {
	value := strings.TrimSpace(os.Getenv(name))
	parsed, err := strconv.ParseUint(value, 10, 32)
	if value == "" || err != nil {
		return 0, fmt.Errorf("%s must be a uint32", name)
	}
	return uint32(parsed), nil
}

func parseNonZeroUint32(name string) (uint32, error) {
	parsed, err := parseUint32(name)
	if err != nil {
		return 0, err
	}
	if parsed == 0 {
		return 0, fmt.Errorf("%s must be non-zero", name)
	}
	return parsed, nil
}

func parseCIDRs(value string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, raw := range strings.Split(strings.TrimSpace(value), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("parse FERRY_TRUSTED_PROXY_CIDRS entry %q: %w", raw, err)
		}
		networks = append(networks, network)
	}
	if len(networks) == 0 {
		return nil, errors.New("FERRY_TRUSTED_PROXY_CIDRS must contain one or more networks")
	}
	return networks, nil
}

func parseHTTPSURL(name string) (*url.URL, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must be an HTTPS URL without credentials, query or fragment", name)
	}
	return parsed, nil
}
