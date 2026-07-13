package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
)

// handleListAuditLogs returns a list of recent security audit log events.
func (s *APIServer) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	if s.deviceRepo == nil {
		writeError(w, s.logger, http.StatusInternalServerError, "device metadata repository is not configured")
		return
	}

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 {
			limit = val
			if limit > 100 {
				limit = 100
			}
		}
	}

	list, err := s.deviceRepo.ListAuditLogs(r.Context(), limit)
	if err != nil {
		s.logger.Error("Failed querying audit logs", slog.String("error", err.Error()))
		writeError(w, s.logger, http.StatusInternalServerError, "internal database error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(list); err != nil {
		s.logger.Error("Failed to encode audit logs response", slog.String("error", err.Error()))
	}
}

// handleGetFirewallRules returns read-only block rules templates for a target IP address.
func (s *APIServer) handleGetFirewallRules(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if net.ParseIP(ip) == nil {
		writeError(w, s.logger, http.StatusBadRequest, "invalid or missing IP address parameter")
		return
	}

	templates := map[string]string{
		"ip": ip,
		"unifi": fmt.Sprintf("UniFi Network Controller:\n"+
			"1. Go to Settings -> Routing & Firewall -> Firewall -> WAN IN -> Create New Rule\n"+
			"2. Name: \"Block FlowGuard Attacker\"\n"+
			"3. Action: Drop\n"+
			"4. Source: Address Group -> Create Group -> Add IP: %s\n"+
			"5. Save", ip),
		"opnsense": fmt.Sprintf("OPNsense Web GUI:\n"+
			"1. Go to Firewall -> Rules -> WAN -> Add Rule (Up arrow/top of list)\n"+
			"2. Action: Block\n"+
			"3. Interface: WAN\n"+
			"4. Protocol: any\n"+
			"5. Source: Single host or Network -> %s\n"+
			"6. Description: \"FlowGuard Lite Block Rule\"\n"+
			"7. Save & Apply Changes", ip),
		"mikrotik": fmt.Sprintf("/ip firewall filter add action=drop chain=input src-address=%s comment=\"FlowGuard Lite Block Rule\"", ip),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(templates); err != nil {
		s.logger.Error("Failed to encode firewall rules templates response", slog.String("error", err.Error()))
	}
}
