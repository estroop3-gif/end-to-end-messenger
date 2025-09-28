package main

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Tor status response structure
type TorStatusResponse struct {
	Connected      bool   `json:"connected"`
	Bootstrapped   bool   `json:"bootstrapped"`
	OnionAddress   string `json:"onion_address,omitempty"`
	ControlPort    int    `json:"control_port"`
	SOCKSPort      int    `json:"socks_port"`
	CircuitCount   int    `json:"circuit_count"`
	HiddenServices int    `json:"hidden_services"`
}

// Circuit response structure
type CircuitResponse struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Path     []string `json:"path"`
	Purpose  string   `json:"purpose"`
	TimeBuilt string  `json:"time_built"`
}

// getTorStatus returns the current Tor status
func (s *Server) getTorStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.torManager == nil {
		http.Error(w, "Tor manager not initialized", http.StatusServiceUnavailable)
		return
	}

	status := s.torManager.GetStatus()
	hiddenServices := s.torManager.GetHiddenServices()

	// Get onion address if available
	var onionAddress string
	if len(hiddenServices) > 0 {
		onionAddress = hiddenServices[0].OnionAddress
	}

	response := TorStatusResponse{
		Connected:      status.Connected,
		Bootstrapped:   status.Bootstrapped,
		OnionAddress:   onionAddress,
		ControlPort:    s.torManager.config.ControlPort,
		SOCKSPort:      s.torManager.config.SOCKSPort,
		CircuitCount:   len(s.networkManager.GetCircuits()),
		HiddenServices: len(hiddenServices),
	}

	json.NewEncoder(w).Encode(response)
}

// getTorCircuits returns information about active Tor circuits
func (s *Server) getTorCircuits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.networkManager == nil {
		http.Error(w, "Network manager not initialized", http.StatusServiceUnavailable)
		return
	}

	circuits := s.networkManager.GetCircuits()
	response := make([]CircuitResponse, 0, len(circuits))

	for _, circuit := range circuits {
		response = append(response, CircuitResponse{
			ID:       circuit.ID,
			Status:   circuit.Status,
			Path:     circuit.Path,
			Purpose:  circuit.Purpose,
			TimeBuilt: circuit.TimeBuilt.Format("2006-01-02 15:04:05"),
		})
	}

	json.NewEncoder(w).Encode(response)
}

// createNewCircuit creates a new Tor circuit
func (s *Server) createNewCircuit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.networkManager == nil {
		http.Error(w, "Network manager not initialized", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters for circuit preferences
	purpose := r.URL.Query().Get("purpose")
	if purpose == "" {
		purpose = "GENERAL"
	}

	// Create new circuit
	circuit, err := s.networkManager.CreateCircuit(purpose)
	if err != nil {
		http.Error(w, "Failed to create circuit: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := CircuitResponse{
		ID:       circuit.ID,
		Status:   circuit.Status,
		Path:     circuit.Path,
		Purpose:  circuit.Purpose,
		TimeBuilt: circuit.TimeBuilt.Format("2006-01-02 15:04:05"),
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// Additional helper endpoints for Tor management

// getTorConfig returns the current Tor configuration
func (s *Server) getTorConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.torManager == nil {
		http.Error(w, "Tor manager not initialized", http.StatusServiceUnavailable)
		return
	}

	json.NewEncoder(w).Encode(s.torManager.config)
}

// updateTorConfig updates Tor configuration
func (s *Server) updateTorConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.torManager == nil {
		http.Error(w, "Tor manager not initialized", http.StatusServiceUnavailable)
		return
	}

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Apply configuration updates
	for key, value := range updates {
		switch key {
		case "log_level":
			if level, ok := value.(string); ok {
				s.torManager.config.LogLevel = level
			}
		case "circuit_timeout":
			if timeout, ok := value.(float64); ok {
				s.torManager.config.CircuitTimeout = int(timeout)
			}
		case "bridge_mode":
			if bridgeMode, ok := value.(bool); ok {
				s.torManager.config.BridgeMode = bridgeMode
			}
		}
	}

	// Restart Tor with new configuration if needed
	if err := s.torManager.Restart(); err != nil {
		http.Error(w, "Failed to apply configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "configuration updated"})
}

// getHiddenServices returns information about configured hidden services
func (s *Server) getHiddenServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.torManager == nil {
		http.Error(w, "Tor manager not initialized", http.StatusServiceUnavailable)
		return
	}

	hiddenServices := s.torManager.GetHiddenServices()
	json.NewEncoder(w).Encode(hiddenServices)
}

// createHiddenService creates a new hidden service
func (s *Server) createHiddenService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.torManager == nil {
		http.Error(w, "Tor manager not initialized", http.StatusServiceUnavailable)
		return
	}

	// Parse request
	var req struct {
		Name        string    `json:"name"`
		VirtualPort int       `json:"virtual_port"`
		TargetHost  string    `json:"target_host"`
		TargetPort  string    `json:"target_port"`
		Version     int       `json:"version"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Name == "" || req.VirtualPort == 0 || req.TargetHost == "" || req.TargetPort == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Default to v3 onion services
	if req.Version == 0 {
		req.Version = 3
	}

	// Create hidden service
	portMaps := []PortMap{
		{
			VirtualPort: req.VirtualPort,
			TargetHost:  req.TargetHost,
			TargetPort:  req.TargetPort,
		},
	}

	hiddenService, err := s.torManager.CreateHiddenService(req.Name, portMaps, req.Version)
	if err != nil {
		http.Error(w, "Failed to create hidden service: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(hiddenService)
}

// deleteHiddenService removes a hidden service
func (s *Server) deleteHiddenService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.torManager == nil {
		http.Error(w, "Tor manager not initialized", http.StatusServiceUnavailable)
		return
	}

	// Get service name from URL path
	serviceName := r.URL.Query().Get("name")
	if serviceName == "" {
		http.Error(w, "Missing service name", http.StatusBadRequest)
		return
	}

	if err := s.torManager.DeleteHiddenService(serviceName); err != nil {
		http.Error(w, "Failed to delete hidden service: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "hidden service deleted"})
}

// testConnection tests connectivity through Tor
func (s *Server) testConnection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.networkManager == nil {
		http.Error(w, "Network manager not initialized", http.StatusServiceUnavailable)
		return
	}

	// Get target URL from query
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		targetURL = "https://check.torproject.org/api/ip"
	}

	// Test connection
	result, err := s.networkManager.TestConnection(targetURL)
	if err != nil {
		http.Error(w, "Connection test failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"url":       targetURL,
		"success":   result.Success,
		"response":  result.Response,
		"latency":   result.Latency.Milliseconds(),
		"timestamp": result.Timestamp,
	})
}