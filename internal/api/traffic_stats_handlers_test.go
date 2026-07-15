package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miquelbar/flowguard-lite/internal/collector"
	"github.com/miquelbar/flowguard-lite/internal/config"
	"github.com/miquelbar/flowguard-lite/internal/flow"
	"github.com/miquelbar/flowguard-lite/internal/risk"
	"github.com/miquelbar/flowguard-lite/internal/storage"
)

func TestHandleTopTalkers(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{
		Sources: []flow.TopResult{
			{Key: "192.168.1.10", Bytes: 1000, Packets: 10, Flows: 1},
		},
		Destinations: []flow.TopResult{
			{Key: "8.8.8.8", Bytes: 500, Packets: 5, Flows: 1},
		},
		Ports: []flow.TopResult{
			{Key: "53", Bytes: 500, Packets: 5, Flows: 1},
		},
		Protocols: []flow.TopResult{
			{Key: "17", Bytes: 500, Packets: 5, Flows: 1},
		},
	}

	server := NewAPIServer(cfg, logger, nil, mockRepo, mockRepo, nil, nil, nil, nil, nil, "")

	// 1. Sources check
	req := httptest.NewRequest(http.MethodGet, "/api/top/sources", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected OK, got %d", w.Code)
	}
	var srcRes []flow.TopResult
	if err := json.Unmarshal(w.Body.Bytes(), &srcRes); err != nil {
		t.Fatalf("failed decoding: %v", err)
	}
	if len(srcRes) != 1 || srcRes[0].Key != "192.168.1.10" {
		t.Errorf("unexpected sources output: %v", srcRes)
	}

	// 2. Destinations check
	req = httptest.NewRequest(http.MethodGet, "/api/top/destinations", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected OK, got %d", w.Code)
	}
	var dstRes []flow.TopResult
	if err := json.Unmarshal(w.Body.Bytes(), &dstRes); err != nil {
		t.Fatalf("failed decoding: %v", err)
	}
	if len(dstRes) != 1 || dstRes[0].Key != "8.8.8.8" {
		t.Errorf("unexpected destinations output: %v", dstRes)
	}

	// 3. Ports check
	req = httptest.NewRequest(http.MethodGet, "/api/top/ports", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected OK, got %d", w.Code)
	}
	var portRes []flow.TopResult
	if err := json.Unmarshal(w.Body.Bytes(), &portRes); err != nil {
		t.Fatalf("failed decoding: %v", err)
	}
	if len(portRes) != 1 || portRes[0].Key != "53" {
		t.Errorf("unexpected ports output: %v", portRes)
	}

	// 4. Protocols check
	req = httptest.NewRequest(http.MethodGet, "/api/top/protocols", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected OK, got %d", w.Code)
	}
	var protocolRes []flow.TopResult
	if err := json.Unmarshal(w.Body.Bytes(), &protocolRes); err != nil {
		t.Fatalf("failed decoding: %v", err)
	}
	if len(protocolRes) != 1 || protocolRes[0].Key != "17" {
		t.Errorf("unexpected protocols output: %v", protocolRes)
	}
}

func TestHandleTrafficTimeSeries(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{}
	server := NewAPIServer(cfg, logger, nil, mockRepo, nil, nil, nil, nil, nil, nil, "")

	start := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	end := time.Now().UTC().Format(time.RFC3339)
	req := httptest.NewRequest(http.MethodGet, "/api/traffic/timeseries?start="+start+"&end="+end+"&bucket_seconds=300", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var result []flow.TrafficTimeBucket
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed decoding traffic time series: %v", err)
	}
	if len(result) != 1 || result[0].Bytes != 1000 || result[0].Packets != 10 || result[0].Flows != 2 {
		t.Fatalf("unexpected traffic time series result: %+v", result)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/traffic/timeseries?bucket_seconds=17", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid bucket to return 400, got %d", w.Code)
	}
}

func TestHandleTrafficRecords(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	mockRepo := &MockFlowRepository{
		Records: []flow.AggregateRecord{
			{Timestamp: now.Add(-5 * time.Minute), CollectorKind: flow.CollectorKindNetFlow, CollectorID: "unifi-gateway", SrcIP: "192.168.1.10", DstIP: "8.8.8.8", DstPort: 53, Protocol: 17, Bytes: 1200, Packets: 12, Flows: 2},
		},
	}
	server := NewAPIServer(cfg, logger, nil, mockRepo, nil, nil, nil, nil, nil, nil, "")

	start := now.Add(-1 * time.Hour).Format(time.RFC3339)
	end := now.Format(time.RFC3339)
	req := httptest.NewRequest(http.MethodGet, "/api/traffic/records?start="+start+"&end="+end+"&q=192.168&protocol=17&dst_port=53&limit=200", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected records 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	var records []flow.AggregateRecord
	if err := json.Unmarshal(w.Body.Bytes(), &records); err != nil {
		t.Fatalf("failed decoding traffic records: %v", err)
	}
	if len(records) != 1 || records[0].SrcIP != "192.168.1.10" || records[0].DstPort != 53 || records[0].Protocol != 17 {
		t.Fatalf("unexpected records response: %+v", records)
	}
	if records[0].CollectorKind != flow.CollectorKindNetFlow || records[0].CollectorID != "unifi-gateway" {
		t.Fatalf("expected collector identity in records response, got %+v", records[0])
	}

	req = httptest.NewRequest(http.MethodGet, "/api/traffic/records?protocol=999", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid protocol to return 400, got %d", w.Code)
	}
}

func TestHandleSecurityOverviewEndpoints(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SuricataEvePath = "/var/log/suricata/eve.json"
	cfg.WebhookURL = "https://hooks.example.test/flowguard"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Now().UTC()
	mockRepo := &MockFlowRepository{
		Devices: []storage.Device{
			{IP: "192.168.1.10", Label: "NAS"},
			{IP: "192.168.1.20", Label: "Camera"},
		},
		Anomalies: []storage.Anomaly{
			{ID: 1, IP: "192.168.1.10", Type: "ddos", Severity: "high", Status: "active", CreatedAt: now.Add(-30 * time.Minute), Description: "UDP flood"},
			{ID: 2, IP: "192.168.1.20", Type: "scan", Severity: "medium", Status: "active", CreatedAt: now.Add(-15 * time.Minute), Description: "Fan-out scan"},
		},
	}
	riskEngine := risk.NewRiskEngine(mockRepo)
	server := NewAPIServer(cfg, logger, &MockCollector{Stats: collector.Stats{PacketsReceived: 10, QueueDepth: 2}}, mockRepo, mockRepo, nil, riskEngine, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodGet, "/api/security/summary", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected summary 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	var summary SecuritySummaryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
		t.Fatalf("failed decoding security summary: %v", err)
	}
	if summary.ActiveAlertsTotal != 2 || summary.ActiveAlertsBySeverity["high"] != 1 || summary.ActiveAlertsBySeverity["medium"] != 1 {
		t.Fatalf("unexpected summary severity counts: %+v", summary)
	}
	if summary.MaxRiskScore == 0 || summary.ElevatedRiskDevices == 0 {
		t.Fatalf("expected elevated risk summary, got %+v", summary)
	}
	if !summary.SuricataConfigured || !summary.NotificationConfigured {
		t.Fatalf("expected configured detector flags, got %+v", summary)
	}
	if summary.Collector == nil || summary.Collector.QueueDepth != 2 {
		t.Fatalf("expected collector view in summary, got %+v", summary.Collector)
	}

	start := now.Add(-1 * time.Hour).Format(time.RFC3339)
	end := now.Format(time.RFC3339)
	req = httptest.NewRequest(http.MethodGet, "/api/security/timeline?start="+start+"&end="+end+"&bucket_seconds=300", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected timeline 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	var timeline []SecurityTimelineBucket
	if err := json.Unmarshal(w.Body.Bytes(), &timeline); err != nil {
		t.Fatalf("failed decoding security timeline: %v", err)
	}
	if len(timeline) == 0 {
		t.Fatalf("expected non-empty timeline")
	}
}

func TestHandleStatsOverviewEndpoints(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockRepo := &MockFlowRepository{
		Protocols: []flow.TopResult{
			{Key: "6", Bytes: 2000, Packets: 20, Flows: 2},
		},
		TopDevices: []flow.TopResult{
			{Key: "192.168.1.10", Bytes: 5000, Packets: 50, Flows: 5},
		},
		Heatmap: []flow.DeviceHeatmapCell{
			{IP: "192.168.1.10", Hour: 13, Bytes: 5000, Packets: 50, Flows: 5},
		},
	}
	server := NewAPIServer(cfg, logger, nil, mockRepo, nil, nil, nil, nil, nil, nil, "")

	req := httptest.NewRequest(http.MethodGet, "/api/stats/protocols?limit=5", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected protocols 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	var protocols []flow.TopResult
	if err := json.Unmarshal(w.Body.Bytes(), &protocols); err != nil {
		t.Fatalf("failed decoding protocols: %v", err)
	}
	if len(protocols) != 1 || protocols[0].Key != "6" {
		t.Fatalf("unexpected protocols response: %+v", protocols)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/stats/top-devices?limit=5", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected top-devices 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	var topDevices []flow.TopResult
	if err := json.Unmarshal(w.Body.Bytes(), &topDevices); err != nil {
		t.Fatalf("failed decoding top devices: %v", err)
	}
	if len(topDevices) != 1 || topDevices[0].Key != "192.168.1.10" {
		t.Fatalf("unexpected top devices response: %+v", topDevices)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/stats/heatmap?limit=5", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected heatmap 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	var heatmap []flow.DeviceHeatmapCell
	if err := json.Unmarshal(w.Body.Bytes(), &heatmap); err != nil {
		t.Fatalf("failed decoding heatmap: %v", err)
	}
	if len(heatmap) != 1 || heatmap[0].Hour != 13 {
		t.Fatalf("unexpected heatmap response: %+v", heatmap)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/stats/top-devices?start=2026-07-01T00:00:00Z&end=2026-07-10T00:00:00Z", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unbounded range, got %d", w.Code)
	}
}

func TestHandleStatsCollectorHealth(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockCollector := &MockCollector{Stats: collector.Stats{
		PacketsReceived: 100,
		PacketsDropped:  1,
		DecodeErrors:    2,
		QueueDepth:      3,
		Sources: []collector.SourceStats{
			{Kind: "unifi_syslog", ID: "unifi_syslog", Enabled: true, Status: "listening", Port: 5514, Packets: 1},
		},
	}}
	server := NewAPIServer(cfg, logger, mockCollector, nil, nil, nil, nil, nil, nil, nil, "")

	now := time.Now().UTC()
	server.recordCollectorStats(now.Add(-15 * time.Second))
	mockCollector.Stats = collector.Stats{
		PacketsReceived: 150,
		PacketsDropped:  2,
		DecodeErrors:    3,
		QueueDepth:      4,
		Sources: []collector.SourceStats{
			{Kind: "unifi_syslog", ID: "unifi_syslog", Enabled: true, Status: "listening", Port: 5514, Packets: 2},
		},
	}
	server.recordCollectorStats(now)

	req := httptest.NewRequest(http.MethodGet, "/api/stats/collector-health?limit=1", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected collector health 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	var samples []CollectorHealthSample
	if err := json.Unmarshal(w.Body.Bytes(), &samples); err != nil {
		t.Fatalf("failed decoding collector health response: %v", err)
	}
	if len(samples) != 1 || samples[0].PacketsReceived != 150 || samples[0].QueueDepth != 4 {
		t.Fatalf("unexpected collector health samples: %+v", samples)
	}
	if len(samples[0].Sources) != 1 || samples[0].Sources[0].Kind != "unifi_syslog" || samples[0].Sources[0].Packets != 2 {
		t.Fatalf("expected bounded collector source health in sample, got %+v", samples[0].Sources)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/stats/collector-health?limit=bad", nil)
	w = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid limit to return 400, got %d", w.Code)
	}
}
