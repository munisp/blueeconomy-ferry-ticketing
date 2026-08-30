package fare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// PRA-135 unit tests: typed registry client, explicit staleness, caching.

func TestDeviceRegistryClientAndCache(t *testing.T) {
	var hits atomic.Int64
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		hits.Add(1)
		authHeader = request.Header.Get("Authorization")
		if request.Header.Get("Traceparent") == "" {
			t.Error("traceparent must propagate to the registry")
		}
		_ = json.NewEncoder(writer).Encode(RegistryDevice{ID: "device-1", Kind: "CONDUCTOR", Status: "ACTIVE", KeyEpoch: 3})
	}))
	defer server.Close()
	client, err := NewDeviceRegistryClient(server.URL, "service-token-123", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := NewDeviceDirectory(client, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	verdict, err := directory.Lookup(ctx, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Stale || verdict.Device.KeyEpoch != 3 || verdict.Device.Status != "ACTIVE" {
		t.Fatalf("verdict = %+v", verdict)
	}
	if authHeader != "Bearer service-token-123" {
		t.Fatalf("authorization = %q", authHeader)
	}
	// Fresh cache: no second registry hit.
	if _, err := directory.Lookup(ctx, "device-1"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("registry hits = %d, want 1 (cache)", hits.Load())
	}
	// Past TTL: the directory refreshes.
	time.Sleep(60 * time.Millisecond)
	if _, err := directory.Lookup(ctx, "device-1"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("registry hits = %d, want 2 after TTL", hits.Load())
	}
	// Registry down + cached entry: STALE fallback, explicit.
	server.Close()
	time.Sleep(60 * time.Millisecond)
	verdict, err = directory.Lookup(ctx, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Stale {
		t.Fatal("unreachable registry with a cached entry must serve STALE explicitly")
	}
	// Registry down + NO cache: fail closed.
	if _, err := directory.Lookup(ctx, "device-unknown"); err == nil {
		t.Fatal("unreachable registry without cache must fail closed")
	}
}

func TestDeviceRegistryConfigFailClosed(t *testing.T) {
	t.Setenv("FERRY_DEVICE_REGISTRY_BASE_URL", "https://geo.example")
	if _, err := LoadDeviceDirectoryFromEnv(); err == nil {
		t.Fatal("partial registry config must fail closed")
	}
	t.Setenv("FERRY_DEVICE_REGISTRY_BASE_URL", "")
	directory, err := LoadDeviceDirectoryFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if directory != nil {
		t.Fatal("empty env must yield no directory")
	}
}
