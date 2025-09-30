use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

/// Security monitoring system for the client-side transport
#[derive(Debug)]
pub struct SecurityMonitor {
    config: SecurityConfig,
    metrics: Arc<RwLock<SecurityMetrics>>,
    threat_detector: ThreatDetector,
    anomaly_detector: AnomalyDetector,
    alert_handler: AlertHandler,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable security monitoring
    pub enabled: bool,

    /// Connection monitoring thresholds
    pub connection_monitoring: ConnectionMonitoringConfig,

    /// Encryption key monitoring
    pub key_monitoring: KeyMonitoringConfig,

    /// Traffic analysis detection
    pub traffic_analysis: TrafficAnalysisConfig,

    /// Alert configuration
    pub alerts: AlertConfig,

    /// Logging configuration
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMonitoringConfig {
    /// Maximum connection failures before alert
    pub max_connection_failures: u32,

    /// Time window for connection failure counting
    pub failure_window_seconds: u64,

    /// Maximum reconnection attempts
    pub max_reconnect_attempts: u32,

    /// Monitor certificate changes
    pub monitor_cert_changes: bool,

    /// Check for man-in-the-middle indicators
    pub detect_mitm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMonitoringConfig {
    /// Monitor key rotation frequency
    pub monitor_key_rotation: bool,

    /// Expected key rotation interval (seconds)
    pub expected_rotation_interval: u64,

    /// Alert on unexpected key changes
    pub alert_unexpected_changes: bool,

    /// Monitor key entropy
    pub monitor_key_entropy: bool,

    /// Minimum expected entropy for keys
    pub min_key_entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficAnalysisConfig {
    /// Monitor for timing correlation attacks
    pub monitor_timing_attacks: bool,

    /// Monitor for padding oracle attacks
    pub monitor_padding_attacks: bool,

    /// Detect unusual traffic patterns
    pub detect_traffic_patterns: bool,

    /// Maximum message frequency (per second)
    pub max_message_frequency: f64,

    /// Monitor message size patterns
    pub monitor_size_patterns: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable alerting
    pub enabled: bool,

    /// Alert destinations
    pub destinations: Vec<AlertDestination>,

    /// Minimum alert level
    pub min_alert_level: AlertLevel,

    /// Rate limiting for alerts
    pub rate_limit_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDestination {
    /// Alert type (email, webhook, log)
    pub alert_type: String,

    /// Destination address/URL
    pub destination: String,

    /// Alert format
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log security events
    pub log_events: bool,

    /// Log level for security events
    pub log_level: String,

    /// Include sensitive data in logs (for debugging)
    pub include_sensitive: bool,

    /// Rotate logs automatically
    pub auto_rotate: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum AlertLevel {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: u64,
    pub event_type: SecurityEventType,
    pub alert_level: AlertLevel,
    pub description: String,
    pub source: String,
    pub metadata: HashMap<String, serde_json::Value>,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    ConnectionFailure,
    CertificateChange,
    MitMDetected,
    UnexpectedKeyRotation,
    LowKeyEntropy,
    TimingAttackDetected,
    PaddingOracleAttack,
    UnusualTrafficPattern,
    HighMessageFrequency,
    AnomalousMessageSize,
    EncryptionFailure,
    DecryptionFailure,
    InvalidSignature,
    ReplayAttackDetected,
}

#[derive(Debug, Default)]
struct SecurityMetrics {
    connection_failures: u32,
    successful_connections: u32,
    key_rotations: u32,
    encryption_operations: u64,
    decryption_operations: u64,
    encryption_failures: u32,
    decryption_failures: u32,
    signature_verifications: u64,
    signature_failures: u32,
    messages_sent: u64,
    messages_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    alerts_generated: u32,
    last_key_rotation: Option<u64>,
    last_connection_failure: Option<u64>,
    certificate_fingerprints: Vec<String>,
    message_timing_samples: Vec<u64>,
    message_size_samples: Vec<u64>,
}

#[derive(Debug)]
struct ThreatDetector {
    config: SecurityConfig,
}

#[derive(Debug)]
struct AnomalyDetector {
    baseline_established: bool,
    timing_baseline: Option<f64>,
    size_baseline: Option<f64>,
    pattern_history: Vec<TrafficPattern>,
}

#[derive(Debug)]
struct TrafficPattern {
    timestamp: u64,
    message_count: u32,
    average_size: f64,
    timing_variance: f64,
}

#[derive(Debug)]
struct AlertHandler {
    config: AlertConfig,
    last_alert_times: HashMap<String, u64>,
}

impl SecurityMonitor {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            threat_detector: ThreatDetector::new(config.clone()),
            anomaly_detector: AnomalyDetector::new(),
            alert_handler: AlertHandler::new(config.alerts.clone()),
            config,
            metrics: Arc::new(RwLock::new(SecurityMetrics::default())),
        }
    }

    /// Monitor a connection attempt
    pub async fn monitor_connection_attempt(&self, success: bool, endpoint: &str, certificate_fingerprint: Option<&str>) {
        if !self.config.enabled {
            return;
        }

        let mut metrics = self.metrics.write().await;
        let now = current_timestamp();

        if success {
            metrics.successful_connections += 1;

            // Check for certificate changes
            if let Some(fingerprint) = certificate_fingerprint {
                if self.config.connection_monitoring.monitor_cert_changes {
                    if !metrics.certificate_fingerprints.contains(&fingerprint.to_string()) {
                        if !metrics.certificate_fingerprints.is_empty() {
                            // Certificate change detected
                            self.generate_alert(SecurityEvent {
                                timestamp: now,
                                event_type: SecurityEventType::CertificateChange,
                                alert_level: AlertLevel::Medium,
                                description: format!("Certificate change detected for endpoint: {}", endpoint),
                                source: endpoint.to_string(),
                                metadata: [
                                    ("new_fingerprint".to_string(), serde_json::Value::String(fingerprint.to_string())),
                                    ("previous_fingerprints".to_string(), serde_json::Value::Array(
                                        metrics.certificate_fingerprints.iter()
                                            .map(|f| serde_json::Value::String(f.clone()))
                                            .collect()
                                    )),
                                ].into_iter().collect(),
                                recommended_action: "Verify certificate change is legitimate".to_string(),
                            }).await;
                        }
                        metrics.certificate_fingerprints.push(fingerprint.to_string());
                    }
                }
            }
        } else {
            metrics.connection_failures += 1;
            metrics.last_connection_failure = Some(now);

            // Check for excessive connection failures
            if metrics.connection_failures >= self.config.connection_monitoring.max_connection_failures {
                self.generate_alert(SecurityEvent {
                    timestamp: now,
                    event_type: SecurityEventType::ConnectionFailure,
                    alert_level: AlertLevel::High,
                    description: format!("Excessive connection failures to endpoint: {}", endpoint),
                    source: endpoint.to_string(),
                    metadata: [
                        ("failure_count".to_string(), serde_json::Value::Number(metrics.connection_failures.into())),
                        ("max_failures".to_string(), serde_json::Value::Number(self.config.connection_monitoring.max_connection_failures.into())),
                    ].into_iter().collect(),
                    recommended_action: "Check network connectivity and endpoint availability".to_string(),
                }).await;
            }
        }
    }

    /// Monitor key rotation
    pub async fn monitor_key_rotation(&self, layer: &str, key_material: &[u8]) {
        if !self.config.enabled || !self.config.key_monitoring.monitor_key_rotation {
            return;
        }

        let mut metrics = self.metrics.write().await;
        let now = current_timestamp();

        metrics.key_rotations += 1;

        // Check rotation frequency
        if let Some(last_rotation) = metrics.last_key_rotation {
            let interval = now - last_rotation;
            let expected_interval = self.config.key_monitoring.expected_rotation_interval;

            if interval < expected_interval / 2 || interval > expected_interval * 2 {
                self.generate_alert(SecurityEvent {
                    timestamp: now,
                    event_type: SecurityEventType::UnexpectedKeyRotation,
                    alert_level: AlertLevel::Medium,
                    description: format!("Unexpected key rotation interval for layer: {}", layer),
                    source: layer.to_string(),
                    metadata: [
                        ("actual_interval".to_string(), serde_json::Value::Number(interval.into())),
                        ("expected_interval".to_string(), serde_json::Value::Number(expected_interval.into())),
                    ].into_iter().collect(),
                    recommended_action: "Verify key rotation schedule".to_string(),
                }).await;
            }
        }

        // Check key entropy
        if self.config.key_monitoring.monitor_key_entropy {
            let entropy = calculate_entropy(key_material);
            if entropy < self.config.key_monitoring.min_key_entropy {
                self.generate_alert(SecurityEvent {
                    timestamp: now,
                    event_type: SecurityEventType::LowKeyEntropy,
                    alert_level: AlertLevel::High,
                    description: format!("Low entropy detected in key material for layer: {}", layer),
                    source: layer.to_string(),
                    metadata: [
                        ("entropy".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(entropy).unwrap())),
                        ("min_entropy".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(self.config.key_monitoring.min_key_entropy).unwrap())),
                    ].into_iter().collect(),
                    recommended_action: "Check key generation process".to_string(),
                }).await;
            }
        }

        metrics.last_key_rotation = Some(now);
    }

    /// Monitor message encryption
    pub async fn monitor_encryption(&self, success: bool, operation_time_ms: u64, message_size: usize) {
        if !self.config.enabled {
            return;
        }

        let mut metrics = self.metrics.write().await;

        if success {
            metrics.encryption_operations += 1;
        } else {
            metrics.encryption_failures += 1;

            self.generate_alert(SecurityEvent {
                timestamp: current_timestamp(),
                event_type: SecurityEventType::EncryptionFailure,
                alert_level: AlertLevel::High,
                description: "Encryption operation failed".to_string(),
                source: "encryption".to_string(),
                metadata: [
                    ("message_size".to_string(), serde_json::Value::Number(message_size.into())),
                ].into_iter().collect(),
                recommended_action: "Check encryption keys and algorithms".to_string(),
            }).await;
        }

        // Monitor for timing attacks
        if self.config.traffic_analysis.monitor_timing_attacks {
            metrics.message_timing_samples.push(operation_time_ms);
            if metrics.message_timing_samples.len() > 1000 {
                metrics.message_timing_samples.remove(0);
            }

            if let Some(anomaly) = self.anomaly_detector.detect_timing_anomaly(&metrics.message_timing_samples) {
                self.generate_alert(SecurityEvent {
                    timestamp: current_timestamp(),
                    event_type: SecurityEventType::TimingAttackDetected,
                    alert_level: AlertLevel::Medium,
                    description: "Potential timing attack detected".to_string(),
                    source: "timing_analysis".to_string(),
                    metadata: [
                        ("anomaly_score".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(anomaly).unwrap())),
                    ].into_iter().collect(),
                    recommended_action: "Review encryption timing patterns".to_string(),
                }).await;
            }
        }
    }

    /// Monitor message decryption
    pub async fn monitor_decryption(&self, success: bool, operation_time_ms: u64, message_size: usize) {
        if !self.config.enabled {
            return;
        }

        let mut metrics = self.metrics.write().await;

        if success {
            metrics.decryption_operations += 1;
        } else {
            metrics.decryption_failures += 1;

            self.generate_alert(SecurityEvent {
                timestamp: current_timestamp(),
                event_type: SecurityEventType::DecryptionFailure,
                alert_level: AlertLevel::High,
                description: "Decryption operation failed".to_string(),
                source: "decryption".to_string(),
                metadata: [
                    ("message_size".to_string(), serde_json::Value::Number(message_size.into())),
                ].into_iter().collect(),
                recommended_action: "Check message integrity and keys".to_string(),
            }).await;
        }
    }

    /// Monitor message traffic patterns
    pub async fn monitor_message_traffic(&self, sent: bool, size: usize, timestamp: u64) {
        if !self.config.enabled {
            return;
        }

        let mut metrics = self.metrics.write().await;

        if sent {
            metrics.messages_sent += 1;
            metrics.bytes_sent += size as u64;
        } else {
            metrics.messages_received += 1;
            metrics.bytes_received += size as u64;
        }

        // Monitor message frequency
        if self.config.traffic_analysis.detect_traffic_patterns {
            let recent_messages = metrics.messages_sent + metrics.messages_received;
            let frequency = recent_messages as f64 / 60.0; // Messages per minute approximation

            if frequency > self.config.traffic_analysis.max_message_frequency {
                self.generate_alert(SecurityEvent {
                    timestamp: current_timestamp(),
                    event_type: SecurityEventType::HighMessageFrequency,
                    alert_level: AlertLevel::Medium,
                    description: "High message frequency detected".to_string(),
                    source: "traffic_analysis".to_string(),
                    metadata: [
                        ("frequency".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(frequency).unwrap())),
                        ("max_frequency".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(self.config.traffic_analysis.max_message_frequency).unwrap())),
                    ].into_iter().collect(),
                    recommended_action: "Review message sending patterns".to_string(),
                }).await;
            }
        }

        // Monitor message sizes
        if self.config.traffic_analysis.monitor_size_patterns {
            metrics.message_size_samples.push(size as u64);
            if metrics.message_size_samples.len() > 1000 {
                metrics.message_size_samples.remove(0);
            }

            if let Some(anomaly) = self.anomaly_detector.detect_size_anomaly(&metrics.message_size_samples) {
                self.generate_alert(SecurityEvent {
                    timestamp: current_timestamp(),
                    event_type: SecurityEventType::AnomalousMessageSize,
                    alert_level: AlertLevel::Low,
                    description: "Anomalous message size pattern detected".to_string(),
                    source: "size_analysis".to_string(),
                    metadata: [
                        ("anomaly_score".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(anomaly).unwrap())),
                    ].into_iter().collect(),
                    recommended_action: "Review message size patterns".to_string(),
                }).await;
            }
        }
    }

    /// Get current security metrics
    pub async fn get_metrics(&self) -> SecurityMetrics {
        self.metrics.read().await.clone()
    }

    /// Generate a security alert
    async fn generate_alert(&self, event: SecurityEvent) {
        if !self.config.alerts.enabled || event.alert_level < self.config.alerts.min_alert_level {
            return;
        }

        // Rate limiting
        let alert_key = format!("{}:{}", event.event_type as u8, event.source);
        if self.alert_handler.is_rate_limited(&alert_key).await {
            return;
        }

        self.alert_handler.update_rate_limit(&alert_key).await;

        // Log the event
        match event.alert_level {
            AlertLevel::Critical | AlertLevel::High => {
                error!("Security alert: {} - {}", event.description, event.recommended_action);
            }
            AlertLevel::Medium => {
                warn!("Security alert: {} - {}", event.description, event.recommended_action);
            }
            _ => {
                info!("Security event: {}", event.description);
            }
        }

        // Send to configured destinations
        self.alert_handler.send_alert(event).await;

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.alerts_generated += 1;
    }
}

impl ThreatDetector {
    fn new(config: SecurityConfig) -> Self {
        Self { config }
    }
}

impl AnomalyDetector {
    fn new() -> Self {
        Self {
            baseline_established: false,
            timing_baseline: None,
            size_baseline: None,
            pattern_history: Vec::new(),
        }
    }

    fn detect_timing_anomaly(&mut self, samples: &[u64]) -> Option<f64> {
        if samples.len() < 10 {
            return None;
        }

        let mean = samples.iter().map(|&x| x as f64).sum::<f64>() / samples.len() as f64;
        let variance = samples.iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>() / samples.len() as f64;

        if let Some(baseline) = self.timing_baseline {
            let anomaly_score = (mean - baseline).abs() / baseline;
            if anomaly_score > 0.5 {
                return Some(anomaly_score);
            }
        } else {
            self.timing_baseline = Some(mean);
        }

        None
    }

    fn detect_size_anomaly(&mut self, samples: &[u64]) -> Option<f64> {
        if samples.len() < 10 {
            return None;
        }

        let mean = samples.iter().map(|&x| x as f64).sum::<f64>() / samples.len() as f64;

        if let Some(baseline) = self.size_baseline {
            let anomaly_score = (mean - baseline).abs() / baseline;
            if anomaly_score > 0.3 {
                return Some(anomaly_score);
            }
        } else {
            self.size_baseline = Some(mean);
        }

        None
    }
}

impl AlertHandler {
    fn new(config: AlertConfig) -> Self {
        Self {
            config,
            last_alert_times: HashMap::new(),
        }
    }

    async fn is_rate_limited(&self, alert_key: &str) -> bool {
        if let Some(&last_time) = self.last_alert_times.get(alert_key) {
            let now = current_timestamp();
            return now - last_time < self.config.rate_limit_seconds;
        }
        false
    }

    async fn update_rate_limit(&mut self, alert_key: &str) {
        self.last_alert_times.insert(alert_key.to_string(), current_timestamp());
    }

    async fn send_alert(&self, event: SecurityEvent) {
        for destination in &self.config.destinations {
            // Implementation would depend on destination type
            debug!("Sending alert to {}: {}", destination.destination, event.description);
        }
    }
}

impl Clone for SecurityMetrics {
    fn clone(&self) -> Self {
        Self {
            connection_failures: self.connection_failures,
            successful_connections: self.successful_connections,
            key_rotations: self.key_rotations,
            encryption_operations: self.encryption_operations,
            decryption_operations: self.decryption_operations,
            encryption_failures: self.encryption_failures,
            decryption_failures: self.decryption_failures,
            signature_verifications: self.signature_verifications,
            signature_failures: self.signature_failures,
            messages_sent: self.messages_sent,
            messages_received: self.messages_received,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            alerts_generated: self.alerts_generated,
            last_key_rotation: self.last_key_rotation,
            last_connection_failure: self.last_connection_failure,
            certificate_fingerprints: self.certificate_fingerprints.clone(),
            message_timing_samples: self.message_timing_samples.clone(),
            message_size_samples: self.message_size_samples.clone(),
        }
    }
}

/// Calculate Shannon entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Default security configuration
impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            connection_monitoring: ConnectionMonitoringConfig {
                max_connection_failures: 5,
                failure_window_seconds: 300,
                max_reconnect_attempts: 3,
                monitor_cert_changes: true,
                detect_mitm: true,
            },
            key_monitoring: KeyMonitoringConfig {
                monitor_key_rotation: true,
                expected_rotation_interval: 86400, // 24 hours
                alert_unexpected_changes: true,
                monitor_key_entropy: true,
                min_key_entropy: 7.0,
            },
            traffic_analysis: TrafficAnalysisConfig {
                monitor_timing_attacks: true,
                monitor_padding_attacks: true,
                detect_traffic_patterns: true,
                max_message_frequency: 10.0,
                monitor_size_patterns: true,
            },
            alerts: AlertConfig {
                enabled: true,
                destinations: vec![],
                min_alert_level: AlertLevel::Medium,
                rate_limit_seconds: 300,
            },
            logging: LoggingConfig {
                log_events: true,
                log_level: "warn".to_string(),
                include_sensitive: false,
                auto_rotate: true,
            },
        }
    }
}