# Wipe Framework for Ephemeral Messenger

## ⚠️ SECURITY CRITICAL MODULE ⚠️

**MANDATORY SECURITY AUDIT REQUIRED BEFORE DEPLOYMENT**

This module implements the wipe framework for the hardware key enforcement system. It provides policy-based data wiping when hardware keys are absent or other security conditions are met.

## 🚨 Safety Warning

**THIS MODULE PERFORMS DESTRUCTIVE OPERATIONS**

- Can permanently delete files and data
- Multiple authorization layers required
- Extensive safety mechanisms implemented
- Default configuration is test-mode only
- Emergency stop mechanisms included
- All operations are logged and auditable

## 📋 Components

### 1. Policy Engine (`policy.go`)
- Defines wipe policies with cryptographic signatures
- Validates policy safety and risk levels
- Supports multiple authorization requirements
- Implements emergency override mechanisms

### 2. Execution Engine (`executor.go`)
- Executes wipe operations with safety checks
- Supports dry-run and test modes
- Implements secure file wiping techniques
- Provides emergency stop capabilities
- Maintains detailed audit logs

### 3. Monitoring System (`monitor.go`)
- Monitors hardware key presence
- Tracks system conditions and triggers
- Evaluates policy conditions
- Manages grace periods and confirmations
- Provides system health monitoring

## 🔒 Security Features

### Authorization Requirements
- **Cryptographic Signatures**: All policies must be Ed25519 signed
- **Multiple Authorizations**: High-risk operations require multiple signatures
- **Emergency Override**: Separate emergency override key system
- **Policy Validation**: Comprehensive policy validation with risk assessment

### Safety Mechanisms
- **Test Mode**: Default test mode prevents actual destructive operations
- **Dry Run Mode**: Simulation mode for testing without destruction
- **Confirmation Required**: User confirmation required for destructive operations
- **Emergency Stop**: Global emergency stop for all wipe operations
- **Safety Locks**: Filesystem locks prevent concurrent operations

### Risk Assessment
- **Automatic Risk Scoring**: Policies are automatically scored (low/medium/high/critical)
- **Path Validation**: Dangerous system paths are blocked
- **Size Limits**: Maximum operation size limits
- **Exclusion Lists**: System files and paths are excluded

### Audit and Monitoring
- **Complete Audit Trail**: All operations logged with timestamps
- **Operation Tracking**: Detailed tracking of files, bytes, and errors
- **Trigger History**: History of all trigger events and decisions
- **System Health**: Monitoring of system conditions

## 🛡️ Safety Constraints

### Default Safety Configuration
```go
// Default safety settings
dryRunMode = true           // No actual deletion
testMode = true             // Test mode only
confirmationRequired = true // User confirmation required
emergencyStopEnabled = true // Emergency stop enabled
maxOperationSize = 1GB      // Size limit
```

### Permanently Blocked Operations
- **System Wipe**: `WipeActionSystem` is permanently disabled
- **Root Directory**: `/`, `/usr`, `/bin`, `/etc` are never wipeable
- **Running Processes**: Files in use by running processes are protected
- **Large Recursive**: Large recursive operations require explicit authorization

### Trigger Conditions
- **Grace Periods**: Configurable grace periods before action
- **Activity Timeouts**: User inactivity requirements
- **Authentication Failures**: Failed authentication thresholds
- **Network Requirements**: Network connectivity requirements
- **Battery Levels**: Minimum battery level requirements

## 📖 Usage Examples

### Safe Policy Creation
```go
// Create a safe alert-only policy
policy := &WipePolicy{
    Version:     1,
    PolicyID:    uuid.New().String(),
    Name:        "Hardware Key Alert",
    Description: "Alert when hardware key is absent",
    Action:      WipeActionAlert,  // Safe action
    Trigger: WipeTrigger{
        KeyAbsentDuration: 5 * time.Minute,
        GracePeriodExpired: true,
    },
    TestMode: true,  // Safety mode
    DryRun:   true,  // Simulation only
}
```

### Monitor Integration
```go
// Initialize components with safety defaults
policyManager := NewWipePolicyManager()
executor := NewWipeExecutor()
monitor := NewWipeMonitor(policyManager, executor)

// Configure for maximum safety
monitor.SetConfiguration(
    30*time.Second,  // Check interval
    10*time.Minute,  // Grace period
    30*time.Minute,  // Activity timeout
    3,               // Max failed auth
    true,            // Test mode
    true,            // Require confirmation
)

// Add alert callback
monitor.AddAlertCallback(func(alertType, message, severity string) {
    log.Printf("WIPE ALERT [%s]: %s (%s)", alertType, message, severity)
})
```

### Policy Validation
```go
// Validate policy before loading
validation := policyManager.ValidatePolicy(policy)
if !validation.Valid {
    return fmt.Errorf("Policy validation failed: %v", validation.Errors)
}

if validation.RiskLevel == "critical" {
    return fmt.Errorf("Critical risk policies require additional review")
}
```

## 🔧 Configuration

### Environment Variables
```bash
WIPE_TEST_MODE=true                    # Force test mode
WIPE_DRY_RUN=true                     # Force dry run
WIPE_REQUIRE_CONFIRMATION=true        # Require confirmations
WIPE_EMERGENCY_DISABLED=true          # Emergency disable all wipe ops
WIPE_MAX_OPERATION_SIZE=1073741824    # Max operation size (1GB)
WIPE_GRACE_PERIOD=600                 # Grace period in seconds
```

### Policy File Format
```json
{
  "version": 1,
  "policy_id": "uuid-here",
  "name": "Safe Alert Policy",
  "description": "Alert when key is absent",
  "enabled": true,
  "priority": 1,
  "trigger": {
    "key_absent_duration": "5m",
    "grace_period_expired": true
  },
  "action": "alert",
  "targets": [],
  "method": {
    "log_operations": true,
    "audit_trail": true,
    "notify_admin": true
  },
  "test_mode": true,
  "dry_run": true,
  "signature": "base64-ed25519-signature"
}
```

## 🧪 Testing

### Unit Tests
```bash
cd server/wipe
go test ./... -v
```

### Integration Tests
```bash
# Test with actual policies (safe mode)
go test ./... -integration -v
```

### Policy Validation Tests
```bash
# Validate sample policies
go run cmd/validate-policy/main.go policies/sample-safe.json
```

## 🚨 Emergency Procedures

### Emergency Stop
```go
// Global emergency stop
monitor.EmergencyDisable()
executor.EmergencyStop()
```

### Recovery from Failed Wipe
1. Check audit logs for operation details
2. Restore from backups if available
3. Analyze failure cause in logs
4. Update policies to prevent recurrence

### Incident Response
1. **Immediate**: Emergency stop all operations
2. **Analysis**: Review audit logs and trigger history
3. **Recovery**: Restore affected data from backups
4. **Prevention**: Update policies and safety mechanisms

## 📋 Audit Requirements

### Pre-Deployment Audit Checklist
- [ ] Security review of all destructive operations
- [ ] Validation of safety mechanisms
- [ ] Testing of emergency stop procedures
- [ ] Review of default safety configurations
- [ ] Verification of audit logging completeness
- [ ] Testing of authorization requirements
- [ ] Risk assessment validation
- [ ] Policy signature verification
- [ ] Integration testing with key detection
- [ ] Fail-safe behavior verification

### Operational Audit Requirements
- [ ] Regular review of trigger history
- [ ] Monitoring of false positive rates
- [ ] Validation of policy effectiveness
- [ ] Review of system health metrics
- [ ] Testing of recovery procedures
- [ ] Verification of audit log integrity

## 🔍 Monitoring and Alerting

### Key Metrics
- Policy trigger frequency
- Operation success/failure rates
- False positive incidents
- Emergency stop activations
- System health status
- Authorization failures

### Alert Conditions
- Any destructive operation execution
- Policy trigger events
- Emergency stop activations
- Authorization failures
- System health degradation
- Audit log anomalies

## 📚 References

- [NIST SP 800-88: Guidelines for Media Sanitization](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final)
- [DoD 5220.22-M: Data Wiping Standards](https://www.dod.mil/dodgc/doha/industrial/5220-22m.pdf)
- [Common Criteria Protection Profiles](https://www.commoncriteriaportal.org/)
- [FIPS 140-2: Security Requirements for Cryptographic Modules](https://csrc.nist.gov/publications/detail/fips/140/2/final)

## ⚖️ Legal and Compliance

### Data Protection Compliance
- Ensure compliance with GDPR, CCPA, and local data protection laws
- Implement data retention and deletion policies
- Maintain audit trails for compliance reporting
- Provide data recovery mechanisms where legally required

### Liability Considerations
- Document all safety mechanisms and testing procedures
- Maintain insurance coverage for data loss incidents
- Implement user consent mechanisms for destructive operations
- Provide clear warnings and documentation

## 🤝 Contributing

1. **Security First**: All contributions must prioritize security and safety
2. **Test Coverage**: New features require comprehensive tests
3. **Documentation**: All changes must be documented
4. **Review Process**: Security-critical changes require multiple reviews
5. **Audit Trail**: Maintain detailed change logs

## 📄 License

This module is part of the Ephemeral Messenger project and follows the same licensing terms as the main project. Use of this module for destructive operations requires explicit understanding and acceptance of the risks involved.