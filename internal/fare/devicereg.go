package fare

// devicereg.go — PRA-135: device-plane wiring to the geo-service W-FEAT-3
// device registry. Conductor/validator devices are managed devices there
// (maker/checker provisioning, Ed25519 key epochs, lifecycle). This client
// is typed, trace-propagating, and cached with EXPLICIT staleness: a fresh
// registry verdict is authoritative for lifecycle (a SUSPENDED device is
// denied even when its local money caps exist); a STALE or unreachable
// registry falls back to BlueFare's local device plane (device_offline_caps)
// which stays fail-closed — never the other way around.

import (
	"os"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RegistryDevice mirrors the geo-service device record (typed).
type RegistryDevice struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Status   string `json:"status"`
	KeyEpoch int    `json:"keyEpoch"`
}

// DeviceRegistryClient is the typed HTTP client for the registry.
type DeviceRegistryClient struct {
	baseURL     string
	bearerToken string
	httpClient  *http.Client
}

// NewDeviceRegistryClient fails closed on missing config.
func NewDeviceRegistryClient(baseURL, bearerToken string, httpClient *http.Client) (*DeviceRegistryClient, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("device registry base URL is required")
	}
	if strings.TrimSpace(bearerToken) == "" {
		return nil, errors.New("device registry service token is required")
	}
	if httpClient == nil {
		return nil, errors.New("device registry http client is required")
	}
	return &DeviceRegistryClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		bearerToken: bearerToken, httpClient: httpClient,
	}, nil
}

// GetDevice loads one device record (service-level JWT, trace propagated).
func (client *DeviceRegistryClient) GetDevice(ctx context.Context, deviceID string) (RegistryDevice, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		client.baseURL+"/v1/devices/"+deviceID, nil)
	if err != nil {
		return RegistryDevice{}, err
	}
	request.Header.Set("Authorization", "Bearer "+client.bearerToken)
	injectTraceContext(ctx, request)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return RegistryDevice{}, fmt.Errorf("device registry lookup: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return RegistryDevice{}, ErrNotFound
	}
	if response.StatusCode != http.StatusOK {
		return RegistryDevice{}, fmt.Errorf("device registry returned %d", response.StatusCode)
	}
	var device RegistryDevice
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&device); err != nil {
		return RegistryDevice{}, fmt.Errorf("decode device record: %w", err)
	}
	if device.ID == "" || device.Status == "" {
		return RegistryDevice{}, errors.New("device registry record is incomplete (fail-closed)")
	}
	return device, nil
}

// DeviceVerdict is one directory answer with EXPLICIT staleness.
type DeviceVerdict struct {
	Device RegistryDevice
	Stale  bool // true = cached beyond TTL or registry unreachable fallback
}

// DeviceDirectory answers lifecycle lookups; the offline cache carries
// explicit staleness and the local store is the fail-closed fallback.
type DeviceDirectory struct {
	client *DeviceRegistryClient
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	entries map[string]cachedDevice
}

type cachedDevice struct {
	device    RegistryDevice
	fetchedAt time.Time
}

// NewDeviceDirectory builds the cached directory (ttl > 0, fail-closed).
func NewDeviceDirectory(client *DeviceRegistryClient, ttl time.Duration) (*DeviceDirectory, error) {
	if client == nil {
		return nil, errors.New("device registry client is required")
	}
	if ttl <= 0 {
		return nil, errors.New("device cache ttl must be positive")
	}
	return &DeviceDirectory{client: client, ttl: ttl, entries: map[string]cachedDevice{},
		now: func() time.Time { return time.Now().UTC() }}, nil
}

// Lookup resolves one device: fresh cache first, then the registry, then
// the stale cache entry marked Stale (explicit, never silent).
func (directory *DeviceDirectory) Lookup(ctx context.Context, deviceID string) (DeviceVerdict, error) {
	if strings.TrimSpace(deviceID) == "" {
		return DeviceVerdict{}, errors.New("device id is required")
	}
	directory.mu.Lock()
	entry, cached := directory.entries[deviceID]
	directory.mu.Unlock()
	if cached && directory.now().Sub(entry.fetchedAt) < directory.ttl {
		return DeviceVerdict{Device: entry.device}, nil
	}
	device, err := directory.client.GetDevice(ctx, deviceID)
	if err != nil {
		if cached {
			// Registry unreachable: the stale entry is served EXPLICITLY.
			return DeviceVerdict{Device: entry.device, Stale: true}, nil
		}
		return DeviceVerdict{}, err
	}
	directory.mu.Lock()
	directory.entries[deviceID] = cachedDevice{device: device, fetchedAt: directory.now()}
	directory.mu.Unlock()
	return DeviceVerdict{Device: device}, nil
}

// ---------------------------------------------------------------------------
// Env-gated factory (fail-closed on partial config).
// ---------------------------------------------------------------------------

// LoadDeviceDirectoryFromEnv wires the registry-backed directory. Empty env
// = no directory (conductor lifecycle stays local-only, fail-closed as
// before); partial env fails boot.
func LoadDeviceDirectoryFromEnv() (*DeviceDirectory, error) {
	baseURL := strings.TrimSpace(os.Getenv("FERRY_DEVICE_REGISTRY_BASE_URL"))
	tokenFile := strings.TrimSpace(os.Getenv("FERRY_DEVICE_REGISTRY_TOKEN_FILE"))
	ttlSeconds := strings.TrimSpace(os.Getenv("FERRY_DEVICE_REGISTRY_CACHE_TTL_SECONDS"))
	if baseURL == "" && tokenFile == "" && ttlSeconds == "" {
		return nil, nil
	}
	if baseURL == "" || tokenFile == "" {
		return nil, errors.New("FERRY_DEVICE_REGISTRY_BASE_URL and FERRY_DEVICE_REGISTRY_TOKEN_FILE are both required (fail-closed)")
	}
	token, err := readSecretFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("device registry: %w", err)
	}
	ttl := 300 * time.Second
	if ttlSeconds != "" {
		parsed, err := time.ParseDuration(ttlSeconds + "s")
		if err != nil || parsed <= 0 {
			return nil, errors.New("FERRY_DEVICE_REGISTRY_CACHE_TTL_SECONDS must be a positive integer")
		}
		ttl = parsed
	}
	client, err := NewDeviceRegistryClient(baseURL, token, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		return nil, err
	}
	return NewDeviceDirectory(client, ttl)
}
