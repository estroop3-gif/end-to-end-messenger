package security

import (
	"net/http"
	"sync"
	"time"
)

// NewIPTracker creates a new IP tracker
func NewIPTracker(retentionPeriod time.Duration) *IPTracker {
	return &IPTracker{
		requests:        make(map[string]*RequestStats),
		lockouts:        make(map[string]time.Time),
		cleanupInterval: time.Hour,
	}
}

// UpdateStats updates statistics for an IP address
func (tracker *IPTracker) UpdateStats(ip string, r *http.Request, responseCode int, responseSize int64) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	now := time.Now()
	stats, exists := tracker.requests[ip]
	if !exists {
		stats = &RequestStats{
			UniqueEndpoints: make(map[string]bool),
			FirstSeen:       now,
			UserAgents:      make(map[string]int),
			ErrorCodes:      make(map[int]int),
			PayloadSizes:    make([]int64, 0),
		}
		tracker.requests[ip] = stats
	}

	// Update statistics
	stats.TotalRequests++
	stats.LastSeen = now
	stats.UniqueEndpoints[r.URL.Path] = true
	stats.UserAgents[r.UserAgent()]++
	stats.ErrorCodes[responseCode]++

	if responseSize > 0 {
		stats.PayloadSizes = append(stats.PayloadSizes, responseSize)
		// Keep only last 100 payload sizes to avoid memory bloat
		if len(stats.PayloadSizes) > 100 {
			stats.PayloadSizes = stats.PayloadSizes[1:]
		}
	}

	// Track failed requests
	if responseCode >= 400 {
		stats.FailedRequests++
	}
}

// GetStats returns statistics for an IP address
func (tracker *IPTracker) GetStats(ip string) *RequestStats {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()
	return tracker.requests[ip]
}

// IsLockedOut checks if an IP is currently locked out
func (tracker *IPTracker) IsLockedOut(ip string) bool {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	lockoutTime, exists := tracker.lockouts[ip]
	if !exists {
		return false
	}

	return time.Now().Before(lockoutTime)
}

// AddLockout adds an IP to the lockout list
func (tracker *IPTracker) AddLockout(ip string, duration time.Duration) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	tracker.lockouts[ip] = time.Now().Add(duration)
}

// RemoveLockout removes an IP from the lockout list
func (tracker *IPTracker) RemoveLockout(ip string) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	delete(tracker.lockouts, ip)
}

// GetLockouts returns all current lockouts
func (tracker *IPTracker) GetLockouts() map[string]time.Time {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	result := make(map[string]time.Time)
	for ip, lockoutTime := range tracker.lockouts {
		if time.Now().Before(lockoutTime) {
			result[ip] = lockoutTime
		}
	}
	return result
}

// GetTrackedIPCount returns the number of tracked IPs
func (tracker *IPTracker) GetTrackedIPCount() int {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()
	return len(tracker.requests)
}

// CleanupExpired removes expired data
func (tracker *IPTracker) CleanupExpired() {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	now := time.Now()
	retentionCutoff := now.Add(-24 * time.Hour) // Keep data for 24 hours

	// Clean up old request stats
	for ip, stats := range tracker.requests {
		if stats.LastSeen.Before(retentionCutoff) {
			delete(tracker.requests, ip)
		}
	}

	// Clean up expired lockouts
	for ip, lockoutTime := range tracker.lockouts {
		if now.After(lockoutTime) {
			delete(tracker.lockouts, ip)
		}
	}
}