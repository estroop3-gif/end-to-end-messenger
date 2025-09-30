package security

import (
	"regexp"
	"sync"
)

// Ruleset contains compiled security rules and patterns
type Ruleset struct {
	sqlPatterns []SecurityRule
	xssPatterns []SecurityRule
	customRules []SecurityRule
	mu          sync.RWMutex
}

// SecurityRule represents a single security detection rule
type SecurityRule struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Severity    ThreatLevel
	Category    string
	Description string
	Enabled     bool
}

// NewRuleset creates a new security ruleset with default rules
func NewRuleset() *Ruleset {
	rs := &Ruleset{
		sqlPatterns: make([]SecurityRule, 0),
		xssPatterns: make([]SecurityRule, 0),
		customRules: make([]SecurityRule, 0),
	}

	// Load default rules
	rs.loadDefaultRules()

	return rs
}

// loadDefaultRules loads the default security rules
func (rs *Ruleset) loadDefaultRules() {
	// SQL Injection rules
	sqlRules := []struct {
		id, name, pattern, description string
		severity                       ThreatLevel
	}{
		{"SQL001", "Union Select", `(?i)(union\s+(all\s+)?select)`, "Detects UNION SELECT statements", ThreatLevelHigh},
		{"SQL002", "Select Star", `(?i)(select\s+\*\s+from)`, "Detects SELECT * FROM statements", ThreatLevelMedium},
		{"SQL003", "Insert Into", `(?i)(insert\s+into\s+\w+)`, "Detects INSERT INTO statements", ThreatLevelHigh},
		{"SQL004", "Delete From", `(?i)(delete\s+from\s+\w+)`, "Detects DELETE FROM statements", ThreatLevelHigh},
		{"SQL005", "Update Set", `(?i)(update\s+\w+\s+set)`, "Detects UPDATE SET statements", ThreatLevelHigh},
		{"SQL006", "Drop Table", `(?i)(drop\s+(table|database)\s+\w+)`, "Detects DROP statements", ThreatLevelCritical},
		{"SQL007", "Or Equals", `(?i)(\'\s*or\s*\'\s*=\s*\')`, "Detects OR equals bypass", ThreatLevelHigh},
		{"SQL008", "Or True", `(?i)(\'\s*or\s*1\s*=\s*1)`, "Detects OR 1=1 bypass", ThreatLevelHigh},
		{"SQL009", "Exec Command", `(?i)(exec\s*\(\s*@)`, "Detects EXEC command execution", ThreatLevelCritical},
		{"SQL010", "Script Tag", `(?i)(script\s*>)`, "Detects script tag injection", ThreatLevelHigh},
	}

	for _, rule := range sqlRules {
		pattern, err := regexp.Compile(rule.pattern)
		if err != nil {
			continue // Skip invalid patterns
		}

		rs.sqlPatterns = append(rs.sqlPatterns, SecurityRule{
			ID:          rule.id,
			Name:        rule.name,
			Pattern:     pattern,
			Severity:    rule.severity,
			Category:    "sql_injection",
			Description: rule.description,
			Enabled:     true,
		})
	}

	// XSS rules
	xssRules := []struct {
		id, name, pattern, description string
		severity                       ThreatLevel
	}{
		{"XSS001", "Script Tag", `(?i)(<script[^>]*>.*?</script>)`, "Detects script tags", ThreatLevelMedium},
		{"XSS002", "Javascript Protocol", `(?i)(javascript\s*:)`, "Detects javascript: protocol", ThreatLevelMedium},
		{"XSS003", "Event Handler", `(?i)(on\w+\s*=)`, "Detects HTML event handlers", ThreatLevelMedium},
		{"XSS004", "Iframe Tag", `(?i)(<iframe[^>]*>)`, "Detects iframe tags", ThreatLevelMedium},
		{"XSS005", "Object Tag", `(?i)(<object[^>]*>)`, "Detects object tags", ThreatLevelMedium},
		{"XSS006", "Embed Tag", `(?i)(<embed[^>]*>)`, "Detects embed tags", ThreatLevelMedium},
		{"XSS007", "Link Tag", `(?i)(<link[^>]*>)`, "Detects link tags", ThreatLevelLow},
		{"XSS008", "Document Access", `(?i)(document\.(cookie|domain|write))`, "Detects document object access", ThreatLevelMedium},
		{"XSS009", "Window Access", `(?i)(window\.(location|open))`, "Detects window object access", ThreatLevelMedium},
		{"XSS010", "Eval Function", `(?i)(eval\s*\()`, "Detects eval() function calls", ThreatLevelHigh},
	}

	for _, rule := range xssRules {
		pattern, err := regexp.Compile(rule.pattern)
		if err != nil {
			continue // Skip invalid patterns
		}

		rs.xssPatterns = append(rs.xssPatterns, SecurityRule{
			ID:          rule.id,
			Name:        rule.name,
			Pattern:     pattern,
			Severity:    rule.severity,
			Category:    "xss",
			Description: rule.description,
			Enabled:     true,
		})
	}
}

// MatchSQLInjection checks text against SQL injection rules
func (rs *Ruleset) MatchSQLInjection(text string) []SecurityRule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	var matches []SecurityRule
	for _, rule := range rs.sqlPatterns {
		if rule.Enabled && rule.Pattern.MatchString(text) {
			matches = append(matches, rule)
		}
	}
	return matches
}

// MatchXSS checks text against XSS rules
func (rs *Ruleset) MatchXSS(text string) []SecurityRule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	var matches []SecurityRule
	for _, rule := range rs.xssPatterns {
		if rule.Enabled && rule.Pattern.MatchString(text) {
			matches = append(matches, rule)
		}
	}
	return matches
}

// AddCustomRule adds a custom security rule
func (rs *Ruleset) AddCustomRule(rule SecurityRule) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.customRules = append(rs.customRules, rule)
	return nil
}

// EnableRule enables a rule by ID
func (rs *Ruleset) EnableRule(ruleID string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Check SQL patterns
	for i := range rs.sqlPatterns {
		if rs.sqlPatterns[i].ID == ruleID {
			rs.sqlPatterns[i].Enabled = true
			return true
		}
	}

	// Check XSS patterns
	for i := range rs.xssPatterns {
		if rs.xssPatterns[i].ID == ruleID {
			rs.xssPatterns[i].Enabled = true
			return true
		}
	}

	// Check custom rules
	for i := range rs.customRules {
		if rs.customRules[i].ID == ruleID {
			rs.customRules[i].Enabled = true
			return true
		}
	}

	return false
}

// DisableRule disables a rule by ID
func (rs *Ruleset) DisableRule(ruleID string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Check SQL patterns
	for i := range rs.sqlPatterns {
		if rs.sqlPatterns[i].ID == ruleID {
			rs.sqlPatterns[i].Enabled = false
			return true
		}
	}

	// Check XSS patterns
	for i := range rs.xssPatterns {
		if rs.xssPatterns[i].ID == ruleID {
			rs.xssPatterns[i].Enabled = false
			return true
		}
	}

	// Check custom rules
	for i := range rs.customRules {
		if rs.customRules[i].ID == ruleID {
			rs.customRules[i].Enabled = false
			return true
		}
	}

	return false
}

// GetAllRules returns all security rules
func (rs *Ruleset) GetAllRules() map[string][]SecurityRule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	return map[string][]SecurityRule{
		"sql_injection": append([]SecurityRule(nil), rs.sqlPatterns...),
		"xss":           append([]SecurityRule(nil), rs.xssPatterns...),
		"custom":        append([]SecurityRule(nil), rs.customRules...),
	}
}

// GetRuleStats returns statistics about the ruleset
func (rs *Ruleset) GetRuleStats() map[string]interface{} {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	sqlEnabled := 0
	for _, rule := range rs.sqlPatterns {
		if rule.Enabled {
			sqlEnabled++
		}
	}

	xssEnabled := 0
	for _, rule := range rs.xssPatterns {
		if rule.Enabled {
			xssEnabled++
		}
	}

	customEnabled := 0
	for _, rule := range rs.customRules {
		if rule.Enabled {
			customEnabled++
		}
	}

	return map[string]interface{}{
		"sql_injection_rules": map[string]int{
			"total":   len(rs.sqlPatterns),
			"enabled": sqlEnabled,
		},
		"xss_rules": map[string]int{
			"total":   len(rs.xssPatterns),
			"enabled": xssEnabled,
		},
		"custom_rules": map[string]int{
			"total":   len(rs.customRules),
			"enabled": customEnabled,
		},
	}
}