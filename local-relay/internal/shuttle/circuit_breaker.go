package shuttle

import (
	"sync"
	"time"

	"local-relay/internal/config"

	"go.uber.org/zap"
)

// CircuitState represents the state of the circuit breaker
type CircuitState int

const (
	// StateClosed means requests are allowed through
	StateClosed CircuitState = iota
	// StateOpen means requests are blocked
	StateOpen
	// StateHalfOpen means limited requests are allowed for testing
	StateHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config   config.CircuitConfig
	logger   *zap.Logger
	mu       sync.RWMutex
	state    CircuitState
	failures int
	requests int
	lastFailureTime time.Time
	nextAttempt     time.Time
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config config.CircuitConfig, logger *zap.Logger) *CircuitBreaker {
	return &CircuitBreaker{
		config: config,
		logger: logger,
		state:  StateClosed,
	}
}

// IsOpen returns true if the circuit breaker is open (blocking requests)
func (cb *CircuitBreaker) IsOpen() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case StateOpen:
		// Check if we should transition to half-open
		if time.Now().After(cb.nextAttempt) {
			cb.mu.RUnlock()
			cb.mu.Lock()
			// Double-check after acquiring write lock
			if cb.state == StateOpen && time.Now().After(cb.nextAttempt) {
				cb.state = StateHalfOpen
				cb.requests = 0
				cb.logger.Info("Circuit breaker transitioning to half-open")
			}
			cb.mu.Unlock()
			cb.mu.RLock()
		}
		return cb.state == StateOpen
	case StateHalfOpen:
		// In half-open state, allow limited requests
		return cb.requests >= cb.config.MaxConcurrency
	default:
		return false
	}
}

// RecordSuccess records a successful operation
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateHalfOpen:
		// Success in half-open state - transition to closed
		cb.state = StateClosed
		cb.failures = 0
		cb.requests = 0
		cb.logger.Info("Circuit breaker closed after successful test")
	case StateClosed:
		// Reset failure count on success
		cb.failures = 0
	}
}

// RecordFailure records a failed operation
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case StateClosed:
		if cb.failures >= cb.config.FailureThreshold {
			cb.state = StateOpen
			cb.nextAttempt = time.Now().Add(cb.config.RecoveryTimeout)
			cb.logger.Warn("Circuit breaker opened",
				zap.Int("failures", cb.failures),
				zap.Time("next_attempt", cb.nextAttempt))
		}
	case StateHalfOpen:
		// Failure in half-open state - go back to open
		cb.state = StateOpen
		cb.nextAttempt = time.Now().Add(cb.config.RecoveryTimeout)
		cb.logger.Warn("Circuit breaker reopened after failed test",
			zap.Time("next_attempt", cb.nextAttempt))
	}
}

// RecordRequest records that a request is being made (for half-open state)
func (cb *CircuitBreaker) RecordRequest() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == StateHalfOpen {
		cb.requests++
	}
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetFailures returns the current failure count
func (cb *CircuitBreaker) GetFailures() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.failures
}

// GetStats returns circuit breaker statistics
func (cb *CircuitBreaker) GetStats() map[string]interface{} {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	var stateStr string
	switch cb.state {
	case StateClosed:
		stateStr = "closed"
	case StateOpen:
		stateStr = "open"
	case StateHalfOpen:
		stateStr = "half-open"
	}

	return map[string]interface{}{
		"state":             stateStr,
		"failures":          cb.failures,
		"requests":          cb.requests,
		"last_failure_time": cb.lastFailureTime.Unix(),
		"next_attempt":      cb.nextAttempt.Unix(),
	}
}