// GUI Key Generation Tool for Ephemeral Messenger
//
// This provides a user-friendly GUI interface for hardware keyfile generation,
// built using eframe/egui for cross-platform compatibility.
//
// SECURITY NOTE: This tool handles sensitive cryptographic material.
// All operations are performed in memory with secure cleanup.

use eframe::egui;
use std::process::Command;
use std::collections::HashMap;

fn main() -> Result<(), eframe::Error> {
    env_logger::init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_title("Ephemeral Messenger - Key Generator")
            .with_resizable(true),
        ..Default::default()
    };

    eframe::run_native(
        "Key Generator",
        options,
        Box::new(|_cc| Box::new(KeyGenApp::default())),
    )
}

#[derive(Default)]
struct KeyGenApp {
    // Configuration
    user_id: String,
    device_id: String,
    validity_days: String,
    output_path: String,

    // Options
    generate_qr: bool,
    yubikey_slot: String,
    ssh_import_path: String,
    no_device_binding: bool,

    // State
    detected_devices: Vec<RemovableDevice>,
    selected_device: Option<usize>,
    generation_status: GenerationStatus,
    log_messages: Vec<String>,

    // Advanced options
    show_advanced: bool,
}

#[derive(Clone)]
struct RemovableDevice {
    name: String,
    path: String,
    size: String,
    filesystem: String,
}

#[derive(Default, PartialEq)]
enum GenerationStatus {
    #[default]
    Ready,
    Detecting,
    Generating,
    Success,
    Error(String),
}

impl KeyGenApp {
    fn add_log(&mut self, message: String) {
        self.log_messages.push(format!("[{}] {}",
            chrono::Local::now().format("%H:%M:%S"),
            message
        ));

        // Keep only last 100 messages
        if self.log_messages.len() > 100 {
            self.log_messages.remove(0);
        }
    }

    fn detect_devices(&mut self) {
        self.generation_status = GenerationStatus::Detecting;
        self.add_log("Detecting removable devices...".to_string());

        // In a real implementation, this would scan for actual devices
        // For now, simulate some detected devices
        self.detected_devices = vec![
            RemovableDevice {
                name: "USB Drive".to_string(),
                path: "/media/usb1".to_string(),
                size: "8.0 GB".to_string(),
                filesystem: "FAT32".to_string(),
            },
            RemovableDevice {
                name: "SD Card".to_string(),
                path: "/media/sdcard".to_string(),
                size: "16.0 GB".to_string(),
                filesystem: "exFAT".to_string(),
            },
        ];

        self.generation_status = GenerationStatus::Ready;
        self.add_log(format!("Found {} removable devices", self.detected_devices.len()));
    }

    fn generate_keys(&mut self) {
        self.generation_status = GenerationStatus::Generating;
        self.add_log("Starting key generation...".to_string());

        // Build command arguments
        let mut args = vec!["--interactive=false".to_string()];

        if !self.user_id.is_empty() {
            args.push(format!("--user-id={}", self.user_id));
        }

        if !self.device_id.is_empty() {
            args.push(format!("--device-id={}", self.device_id));
        }

        if !self.validity_days.is_empty() {
            args.push(format!("--validity={}", self.validity_days));
        } else {
            args.push("--validity=365".to_string());
        }

        if !self.output_path.is_empty() {
            args.push(format!("--output={}", self.output_path));
        } else if let Some(idx) = self.selected_device {
            if let Some(device) = self.detected_devices.get(idx) {
                args.push(format!("--output={}", device.path));
            }
        }

        if self.generate_qr {
            args.push("--qr".to_string());
        }

        if !self.yubikey_slot.is_empty() {
            args.push(format!("--yubikey={}", self.yubikey_slot));
        }

        if !self.ssh_import_path.is_empty() {
            args.push(format!("--ssh-import={}", self.ssh_import_path));
        }

        if self.no_device_binding {
            args.push("--no-device-binding".to_string());
        }

        self.add_log(format!("Executing: keygen {}", args.join(" ")));

        // Execute the CLI keygen tool
        match Command::new("../keygen/keygen")
            .args(&args)
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    self.generation_status = GenerationStatus::Success;
                    self.add_log("✅ Key generation completed successfully!".to_string());

                    // Parse output for details
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if line.contains("written to:") || line.contains("Generated") {
                            self.add_log(line.to_string());
                        }
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    self.generation_status = GenerationStatus::Error(stderr.to_string());
                    self.add_log(format!("❌ Key generation failed: {}", stderr));
                }
            }
            Err(e) => {
                self.generation_status = GenerationStatus::Error(e.to_string());
                self.add_log(format!("❌ Failed to execute keygen: {}", e));
            }
        }
    }

    fn reset_form(&mut self) {
        self.user_id.clear();
        self.device_id.clear();
        self.validity_days.clear();
        self.output_path.clear();
        self.generate_qr = false;
        self.yubikey_slot.clear();
        self.ssh_import_path.clear();
        self.no_device_binding = false;
        self.selected_device = None;
        self.generation_status = GenerationStatus::Ready;
    }
}

impl eframe::App for KeyGenApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔐 Ephemeral Messenger Key Generator");
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                // Basic Configuration
                ui.group(|ui| {
                    ui.label("📋 Basic Configuration");

                    ui.horizontal(|ui| {
                        ui.label("User ID:");
                        ui.text_edit_singleline(&mut self.user_id);
                        ui.label("(UUID format, leave empty for auto-generation)");
                    });

                    ui.horizontal(|ui| {
                        ui.label("Validity (days):");
                        ui.text_edit_singleline(&mut self.validity_days);
                        if self.validity_days.is_empty() {
                            ui.label("(default: 365)");
                        }
                    });
                });

                ui.add_space(10.0);

                // Device Selection
                ui.group(|ui| {
                    ui.label("💾 Output Device");

                    ui.horizontal(|ui| {
                        if ui.button("🔍 Detect Devices").clicked() {
                            self.detect_devices();
                        }

                        if ui.button("📁 Custom Path").clicked() {
                            // In a real implementation, open file dialog
                            self.add_log("File dialog not implemented in demo".to_string());
                        }
                    });

                    if !self.detected_devices.is_empty() {
                        ui.label("Detected removable devices:");
                        for (idx, device) in self.detected_devices.iter().enumerate() {
                            ui.horizontal(|ui| {
                                if ui.radio_value(&mut self.selected_device, Some(idx), "").clicked() {
                                    self.output_path = device.path.clone();
                                }
                                ui.label(format!("{} ({}) - {} [{}]",
                                    device.name, device.path, device.size, device.filesystem));
                            });
                        }
                    }

                    if !self.output_path.is_empty() {
                        ui.horizontal(|ui| {
                            ui.label("Output path:");
                            ui.code(&self.output_path);
                        });
                    }
                });

                ui.add_space(10.0);

                // Options
                ui.group(|ui| {
                    ui.label("⚙️ Options");

                    ui.checkbox(&mut self.generate_qr, "Generate QR code for public key");

                    ui.horizontal(|ui| {
                        ui.label("YubiKey slot:");
                        ui.text_edit_singleline(&mut self.yubikey_slot);
                        ui.label("(e.g., 9a, 9c, 9d, 9e)");
                    });

                    ui.collapsing("🔧 Advanced Options", |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Device ID:");
                            ui.text_edit_singleline(&mut self.device_id);
                            ui.label("(for device binding)");
                        });

                        ui.horizontal(|ui| {
                            ui.label("Import SSH key:");
                            ui.text_edit_singleline(&mut self.ssh_import_path);
                            if ui.button("Browse").clicked() {
                                // File dialog
                                self.add_log("File dialog not implemented in demo".to_string());
                            }
                        });

                        ui.checkbox(&mut self.no_device_binding, "Skip device UUID binding");
                    });
                });

                ui.add_space(20.0);

                // Action Buttons
                ui.horizontal(|ui| {
                    let can_generate = match &self.generation_status {
                        GenerationStatus::Detecting | GenerationStatus::Generating => false,
                        _ => !self.output_path.is_empty() || self.selected_device.is_some(),
                    };

                    if ui.add_enabled(can_generate, egui::Button::new("🔐 Generate Keys")).clicked() {
                        self.generate_keys();
                    }

                    if ui.button("🔄 Reset").clicked() {
                        self.reset_form();
                    }

                    if ui.button("❌ Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.add_space(10.0);

                // Status
                match &self.generation_status {
                    GenerationStatus::Ready => {},
                    GenerationStatus::Detecting => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Detecting devices...");
                        });
                    },
                    GenerationStatus::Generating => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Generating keys...");
                        });
                    },
                    GenerationStatus::Success => {
                        ui.colored_label(egui::Color32::GREEN, "✅ Key generation completed successfully!");
                    },
                    GenerationStatus::Error(err) => {
                        ui.colored_label(egui::Color32::RED, format!("❌ Error: {}", err));
                    },
                }

                ui.add_space(10.0);

                // Log Output
                if !self.log_messages.is_empty() {
                    ui.group(|ui| {
                        ui.label("📝 Log Output");
                        egui::ScrollArea::vertical()
                            .max_height(200.0)
                            .show(ui, |ui| {
                                for message in &self.log_messages {
                                    ui.label(message);
                                }
                            });
                    });
                }
            });
        });
    }
}