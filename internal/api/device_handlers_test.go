package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/baseline"
	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

func TestHandleDevices(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	// 1. GET /api/devices
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var devices []storage.Device
	if err := json.Unmarshal(w.Body.Bytes(), &devices); err != nil {
		t.Fatalf("failed decoding devices: %v", err)
	}
	if len(devices) != 1 || devices[0].IP != "192.168.1.10" {
		t.Errorf("unexpected devices result: %v", devices)
	}

	// 2. PUT /api/devices/192.168.1.10/label (valid)
	bodyStr := `{"label": "My Router"}`
	req = httptest.NewRequest(http.MethodPut, "/api/devices/192.168.1.10/label", strings.NewReader(bodyStr))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	// 3. PUT /api/devices/1.1.1.1/label (not found)
	req = httptest.NewRequest(http.MethodPut, "/api/devices/1.1.1.1/label", strings.NewReader(bodyStr))
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status NotFound (404), got %d", w.Code)
	}
}

func TestHandleDevicesReconcilesLocalInventoryFromAggregates(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.LocalSubnets = []string{"192.168.10.0/24", "192.168.30.0/24"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{
		EmptyDevices: true,
		Sources: []flow.TopResult{
			{Key: "213.4.145.32", Bytes: 4_620_000, Packets: 3893, Flows: 3893},
			{Key: "192.168.10.236", Bytes: 1_130_000, Packets: 1723, Flows: 1723},
			{Key: "157.240.243.63", Bytes: 451_770, Packets: 539, Flows: 539},
		},
		Destinations: []flow.TopResult{
			{Key: "192.168.10.189", Bytes: 22_880, Packets: 130, Flows: 130},
			{Key: "192.168.30.128", Bytes: 40, Packets: 1, Flows: 1},
			{Key: "17.250.90.12", Bytes: 27_450, Packets: 42, Flows: 42},
		},
	}

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status OK, got %d: %s", w.Code, w.Body.String())
	}

	var devices []storage.Device
	if err := json.Unmarshal(w.Body.Bytes(), &devices); err != nil {
		t.Fatalf("failed decoding devices: %v", err)
	}
	got := map[string]bool{}
	for _, device := range devices {
		got[device.IP] = true
	}
	for _, want := range []string{"192.168.10.236", "192.168.10.189", "192.168.30.128"} {
		if !got[want] {
			t.Fatalf("expected reconciled local device %s in %+v", want, devices)
		}
	}
	for _, external := range []string{"213.4.145.32", "157.240.243.63", "17.250.90.12"} {
		if got[external] {
			t.Fatalf("did not expect external IP %s in reconciled devices: %+v", external, devices)
		}
	}
}

func TestHandleDeviceBaseline(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}
	engine := baseline.NewBaselineEngine(mockRepo, logger)

	ip := "192.168.1.10"
	mockRepo.Baseline = &storage.DeviceBaseline{
		IP:        ip,
		MeanBytes: 25000.0,
		UpdatedAt: time.Now().Truncate(time.Second),
	}
	_ = engine.LoadBaselines(context.Background())

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, engine, nil, nil, nil, nil, "")

	// 1. GET /api/devices/192.168.1.10/baseline (valid)
	req := httptest.NewRequest(http.MethodGet, "/api/devices/192.168.1.10/baseline", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var baseVal storage.DeviceBaseline
	if err := json.Unmarshal(w.Body.Bytes(), &baseVal); err != nil {
		t.Fatalf("failed decoding baseline: %v", err)
	}
	if baseVal.MeanBytes != 25000.0 {
		t.Errorf("expected mean bytes 25000.0, got %f", baseVal.MeanBytes)
	}

	// 2. GET /api/devices/1.1.1.1/baseline (not found)
	req = httptest.NewRequest(http.MethodGet, "/api/devices/1.1.1.1/baseline", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status NotFound (404), got %d", w.Code)
	}
}

func TestHandleGetDeviceProfileAndFlows(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}

	// Setup mock data
	ip := "192.168.1.10"
	mockRepo.Devices = []storage.Device{
		{IP: ip, Hostname: "test.local", Label: "Discovered Device", Vendor: "Apple", FirstSeen: time.Now(), LastSeen: time.Now()},
	}
	mockRepo.Baseline = &storage.DeviceBaseline{
		IP:        ip,
		MeanBytes: 12345.0,
		UpdatedAt: time.Now().Truncate(time.Second),
	}
	mockRepo.Anomalies = []storage.Anomaly{
		{ID: 10, IP: ip, Type: "TRAFFIC_SPIKE", Severity: "high", Status: "active", CreatedAt: time.Now()},
	}

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	// 1. Test GET /api/devices/{ip} (profile)
	req := httptest.NewRequest(http.MethodGet, "/api/devices/"+ip, nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var profile map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
		t.Fatalf("failed decoding profile: %v", err)
	}

	if profile["ip"] != ip {
		t.Errorf("expected IP %s, got %v", ip, profile["ip"])
	}
	if profile["subnet_vlan"] == nil {
		t.Error("expected subnet_vlan to be present")
	}
	if profile["risk"] == nil {
		t.Error("expected risk to be present")
	}

	// 2. Test GET /api/devices/{ip}/flows
	req = httptest.NewRequest(http.MethodGet, "/api/devices/"+ip+"/flows?bucket_seconds=60", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	var flows map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &flows); err != nil {
		t.Fatalf("failed decoding flows: %v", err)
	}

	if flows["time_series"] == nil {
		t.Error("expected time_series to be present")
	}
	if flows["top_peers"] == nil {
		t.Error("expected top_peers to be present")
	}
	if flows["top_ports"] == nil {
		t.Error("expected top_ports to be present")
	}

	// 3. Test invalid IP format
	req = httptest.NewRequest(http.MethodGet, "/api/devices/invalid-ip", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected StatusBadRequest (400), got %d", w.Code)
	}

	// 4. Test device not found
	req = httptest.NewRequest(http.MethodGet, "/api/devices/1.2.3.4", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected StatusNotFound (404), got %d", w.Code)
	}
}
