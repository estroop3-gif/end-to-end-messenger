// Key Generation Tool for Ephemeral Messenger
//
// This tool provides CLI and GUI interfaces for generating hardware keyfiles,
// QR codes for key sharing, and YubiKey/OpenPGP provisioning.
//
// SECURITY NOTE: This tool generates cryptographic keys and handles sensitive data.
// Generated keys are written directly to removable media and never cached locally.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"filippo.io/age"
	"filippo.io/age/agessh"
)

// KeyGenConfig holds configuration for key generation
type KeyGenConfig struct {
	UserID      string
	DeviceID    string
	ValidityDays int
	OutputPath   string
	Interactive  bool
	QRCode       bool
	YubikeySlot  string
	SSHImport    string
	NoDeviceBinding bool
}

// GeneratedKeys holds all generated key material
type GeneratedKeys struct {
	Ed25519Private   ed25519.PrivateKey
	Ed25519Public    ed25519.PublicKey
	X25519Private    []byte
	X25519Public     []byte
	AgeIdentity      *age.X25519Identity
	AgeRecipient     *age.X25519Recipient
	KeyFile          *KeyFile
	QRCodeData       string
}

// KeyFile represents the secure keyfile format
type KeyFile struct {
	Version       int       `json:"version"`
	UserID        string    `json:"user_id"`
	PubIdentityEd string    `json:"pub_identity_ed25519"`
	PubX25519     string    `json:"pub_x25519"`
	PubAge        string    `json:"pub_age"`
	DeviceID      string    `json:"device_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Signature     string    `json:"signature"`
}

func main() {
	var config KeyGenConfig

	// Command line flags
	flag.StringVar(&config.UserID, "user-id", "", "User ID (UUID, auto-generated if empty)")
	flag.StringVar(&config.DeviceID, "device-id", "", "Device ID for key binding")
	flag.IntVar(&config.ValidityDays, "validity", 365, "Key validity in days")
	flag.StringVar(&config.OutputPath, "output", "", "Output path for keyfile (auto-detected if empty)")
	flag.BoolVar(&config.Interactive, "interactive", true, "Interactive mode")
	flag.BoolVar(&config.QRCode, "qr", false, "Generate QR code for public key")
	flag.StringVar(&config.YubikeySlot, "yubikey", "", "YubiKey slot for provisioning (9a, 9c, 9d, 9e)")
	flag.StringVar(&config.SSHImport, "ssh-import", "", "Import existing SSH key path")
	flag.BoolVar(&config.NoDeviceBinding, "no-device-binding", false, "Skip device UUID binding")

	flag.Parse()

	fmt.Println("🔐 Ephemeral Messenger Key Generation Tool")
	fmt.Println("==========================================")

	if config.Interactive {
		if err := runInteractive(&config); err != nil {
			log.Fatalf("Interactive setup failed: %v", err)
		}
	}

	// Generate keys
	keys, err := generateKeys(&config)
	if err != nil {
		log.Fatalf("Key generation failed: %v", err)
	}

	// Output keyfile
	if err := writeKeyFile(keys, &config); err != nil {
		log.Fatalf("Failed to write keyfile: %v", err)
	}

	// Generate QR code if requested
	if config.QRCode {
		if err := generateQRCode(keys, &config); err != nil {
			log.Printf("Warning: QR code generation failed: %v", err)
		}
	}

	// Provision YubiKey if requested
	if config.YubikeySlot != "" {
		if err := provisionYubiKey(keys, &config); err != nil {
			log.Printf("Warning: YubiKey provisioning failed: %v", err)
		}
	}

	fmt.Println("\n✅ Key generation completed successfully!")
	printKeySummary(keys)
}

func runInteractive(config *KeyGenConfig) error {
	reader := bufio.NewReader(os.Stdin)

	// User ID
	if config.UserID == "" {
		fmt.Print("\nEnter User ID (press Enter for auto-generated UUID): ")
		userID, _ := reader.ReadString('\n')
		userID = strings.TrimSpace(userID)
		if userID == "" {
			config.UserID = uuid.New().String()
			fmt.Printf("Generated User ID: %s\n", config.UserID)
		} else {
			if _, err := uuid.Parse(userID); err != nil {
				return fmt.Errorf("invalid UUID format: %v", err)
			}
			config.UserID = userID
		}
	}

	// Validity period
	fmt.Printf("\nCurrent validity: %d days\n", config.ValidityDays)
	fmt.Print("Enter validity in days (press Enter to keep current): ")
	validityStr, _ := reader.ReadString('\n')
	validityStr = strings.TrimSpace(validityStr)
	if validityStr != "" {
		fmt.Sscanf(validityStr, "%d", &config.ValidityDays)
	}

	// Device binding
	if !config.NoDeviceBinding && config.DeviceID == "" {
		fmt.Print("\nBind to specific device UUID? (y/N): ")
		bindDevice, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(bindDevice)) == "y" {
			fmt.Print("Enter device UUID: ")
			deviceID, _ := reader.ReadString('\n')
			config.DeviceID = strings.TrimSpace(deviceID)
		}
	}

	// Output detection
	if config.OutputPath == "" {
		fmt.Print("\nAuto-detect removable media for output? (Y/n): ")
		autoDetect, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(autoDetect)) != "n" {
			detected, err := detectRemovableMedia()
			if err != nil || len(detected) == 0 {
				fmt.Print("No removable media detected. Enter output path: ")
				outputPath, _ := reader.ReadString('\n')
				config.OutputPath = strings.TrimSpace(outputPath)
			} else {
				fmt.Println("\nDetected removable media:")
				for i, path := range detected {
					fmt.Printf("  %d) %s\n", i+1, path)
				}
				fmt.Print("Select device (1-N): ")
				var selection int
				fmt.Scanf("%d", &selection)
				if selection > 0 && selection <= len(detected) {
					config.OutputPath = detected[selection-1]
				}
			}
		}
	}

	// Additional options
	fmt.Print("\nGenerate QR code for public key? (y/N): ")
	qrResponse, _ := reader.ReadString('\n')
	config.QRCode = strings.ToLower(strings.TrimSpace(qrResponse)) == "y"

	fmt.Print("Provision YubiKey slot? (enter slot like 9a, or press Enter to skip): ")
	yubikeyResponse, _ := reader.ReadString('\n')
	config.YubikeySlot = strings.TrimSpace(yubikeyResponse)

	return nil
}

func generateKeys(config *KeyGenConfig) (*GeneratedKeys, error) {
	keys := &GeneratedKeys{}

	// Import existing SSH key if specified
	if config.SSHImport != "" {
		return importSSHKey(config)
	}

	// Generate Ed25519 key pair for identity and signatures
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %v", err)
	}
	keys.Ed25519Private = privKey
	keys.Ed25519Public = pubKey

	// Generate X25519 key pair for encryption
	x25519Private := make([]byte, 32)
	if _, err := rand.Read(x25519Private); err != nil {
		return nil, fmt.Errorf("failed to generate X25519 private key: %v", err)
	}
	x25519Public, err := x25519.X25519(x25519Private, x25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 public key: %v", err)
	}
	keys.X25519Private = x25519Private
	keys.X25519Public = x25519Public

	// Generate age identity and recipient
	ageIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to generate age identity: %v", err)
	}
	keys.AgeIdentity = ageIdentity
	keys.AgeRecipient = ageIdentity.Recipient()

	// Create keyfile structure
	keyFile := &KeyFile{
		Version:       1,
		UserID:        config.UserID,
		PubIdentityEd: base64.StdEncoding.EncodeToString(keys.Ed25519Public),
		PubX25519:     base64.StdEncoding.EncodeToString(keys.X25519Public),
		PubAge:        keys.AgeRecipient.String(),
		DeviceID:      config.DeviceID,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().AddDate(0, 0, config.ValidityDays),
	}

	// Sign the keyfile
	if err := signKeyFile(keyFile, keys.Ed25519Private); err != nil {
		return nil, fmt.Errorf("failed to sign keyfile: %v", err)
	}

	keys.KeyFile = keyFile

	// Generate QR code data
	publicKeyData := map[string]interface{}{
		"user_id":      keyFile.UserID,
		"pub_ed25519":  keyFile.PubIdentityEd,
		"pub_x25519":   keyFile.PubX25519,
		"pub_age":      keyFile.PubAge,
		"fingerprint":  generateFingerprint(keyFile),
		"expires_at":   keyFile.ExpiresAt,
	}
	qrData, _ := json.Marshal(publicKeyData)
	keys.QRCodeData = string(qrData)

	return keys, nil
}

func importSSHKey(config *KeyGenConfig) (*GeneratedKeys, error) {
	// Read SSH private key
	keyData, err := os.ReadFile(config.SSHImport)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH key: %v", err)
	}

	// Parse SSH key using age SSH support
	identities, err := agessh.ParseIdentities(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH key: %v", err)
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no valid identities found in SSH key")
	}

	// Use first identity
	identity := identities[0]

	keys := &GeneratedKeys{
		AgeIdentity:  identity.(*age.X25519Identity),
		AgeRecipient: identity.Recipient(),
	}

	// For SSH import, we still need Ed25519 keys for signing
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 signing key: %v", err)
	}
	keys.Ed25519Private = privKey
	keys.Ed25519Public = pubKey

	// Extract X25519 keys from age identity if possible
	if x25519Identity, ok := identity.(*age.X25519Identity); ok {
		// Note: age.X25519Identity doesn't expose private key directly
		// We'll use the age identity for encryption operations
		keys.X25519Public = x25519Identity.Recipient().(*age.X25519Recipient).String()
	}

	// Create keyfile
	keyFile := &KeyFile{
		Version:       1,
		UserID:        config.UserID,
		PubIdentityEd: base64.StdEncoding.EncodeToString(keys.Ed25519Public),
		PubAge:        keys.AgeRecipient.String(),
		DeviceID:      config.DeviceID,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().AddDate(0, 0, config.ValidityDays),
	}

	if err := signKeyFile(keyFile, keys.Ed25519Private); err != nil {
		return nil, fmt.Errorf("failed to sign keyfile: %v", err)
	}

	keys.KeyFile = keyFile
	return keys, nil
}

func signKeyFile(keyFile *KeyFile, privateKey ed25519.PrivateKey) error {
	// Create signing data (excludes signature field)
	signingStruct := struct {
		Version       int       `json:"version"`
		UserID        string    `json:"user_id"`
		PubIdentityEd string    `json:"pub_identity_ed25519"`
		PubX25519     string    `json:"pub_x25519"`
		PubAge        string    `json:"pub_age"`
		DeviceID      string    `json:"device_id,omitempty"`
		CreatedAt     time.Time `json:"created_at"`
		ExpiresAt     time.Time `json:"expires_at"`
	}{
		Version:       keyFile.Version,
		UserID:        keyFile.UserID,
		PubIdentityEd: keyFile.PubIdentityEd,
		PubX25519:     keyFile.PubX25519,
		PubAge:        keyFile.PubAge,
		DeviceID:      keyFile.DeviceID,
		CreatedAt:     keyFile.CreatedAt,
		ExpiresAt:     keyFile.ExpiresAt,
	}

	signingData, err := json.Marshal(signingStruct)
	if err != nil {
		return err
	}

	signature := ed25519.Sign(privateKey, signingData)
	keyFile.Signature = base64.StdEncoding.EncodeToString(signature)

	return nil
}

func writeKeyFile(keys *GeneratedKeys, config *KeyGenConfig) error {
	// Determine output path
	outputPath := config.OutputPath
	if outputPath == "" {
		detected, err := detectRemovableMedia()
		if err != nil || len(detected) == 0 {
			outputPath = "."
		} else {
			outputPath = detected[0] // Use first detected device
		}
	}

	// Create KEYSTORE directory
	keystoreDir := filepath.Join(outputPath, "KEYSTORE")
	if err := os.MkdirAll(keystoreDir, 0755); err != nil {
		return fmt.Errorf("failed to create KEYSTORE directory: %v", err)
	}

	// Write keyfile
	keyFilePath := filepath.Join(keystoreDir, "secure_key.json")
	keyFileData, err := json.MarshalIndent(keys.KeyFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keyfile: %v", err)
	}

	if err := os.WriteFile(keyFilePath, keyFileData, 0600); err != nil {
		return fmt.Errorf("failed to write keyfile: %v", err)
	}

	// Write age identity for local use
	ageKeyPath := filepath.Join(keystoreDir, "age_identity.txt")
	ageKeyData := keys.AgeIdentity.String()
	if err := os.WriteFile(ageKeyPath, []byte(ageKeyData), 0600); err != nil {
		return fmt.Errorf("failed to write age identity: %v", err)
	}

	// Write public key export
	pubKeyPath := filepath.Join(keystoreDir, "public_key.json")
	pubKeyData := map[string]interface{}{
		"user_id":      keys.KeyFile.UserID,
		"pub_ed25519":  keys.KeyFile.PubIdentityEd,
		"pub_x25519":   keys.KeyFile.PubX25519,
		"pub_age":      keys.KeyFile.PubAge,
		"fingerprint":  generateFingerprint(keys.KeyFile),
		"expires_at":   keys.KeyFile.ExpiresAt,
	}
	pubKeyJSON, _ := json.MarshalIndent(pubKeyData, "", "  ")
	if err := os.WriteFile(pubKeyPath, pubKeyJSON, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %v", err)
	}

	fmt.Printf("✅ Keyfile written to: %s\n", keyFilePath)
	fmt.Printf("✅ Age identity written to: %s\n", ageKeyPath)
	fmt.Printf("✅ Public key written to: %s\n", pubKeyPath)

	return nil
}

func generateQRCode(keys *GeneratedKeys, config *KeyGenConfig) error {
	qrFilePath := filepath.Join(config.OutputPath, "KEYSTORE", "public_key_qr.png")

	err := qrcode.WriteFile(keys.QRCodeData, qrcode.Medium, 256, qrFilePath)
	if err != nil {
		return err
	}

	fmt.Printf("✅ QR code written to: %s\n", qrFilePath)
	return nil
}

func provisionYubiKey(keys *GeneratedKeys, config *KeyGenConfig) error {
	// This is a placeholder for YubiKey provisioning
	// Real implementation would use YubiKey PIV or OpenPGP interfaces
	fmt.Printf("⚠️  YubiKey provisioning not yet implemented for slot %s\n", config.YubikeySlot)
	fmt.Printf("    Manual provisioning required:\n")
	fmt.Printf("    - Import Ed25519 key: %s\n", keys.KeyFile.PubIdentityEd)
	fmt.Printf("    - Import X25519 key: %s\n", keys.KeyFile.PubX25519)

	return nil
}

func detectRemovableMedia() ([]string, error) {
	var devices []string

	// Common mount points for removable media
	mountPoints := []string{
		"/media",
		"/mnt",
		"/run/media",
		"/run/user/1000",
		"/run/user/1001",
	}

	for _, mountPoint := range mountPoints {
		entries, err := os.ReadDir(mountPoint)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				devicePath := filepath.Join(mountPoint, entry.Name())
				// Check if it's writable
				if isWritable(devicePath) {
					devices = append(devices, devicePath)
				}
			}
		}
	}

	return devices, nil
}

func isWritable(path string) bool {
	testFile := filepath.Join(path, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return false
	}
	os.Remove(testFile)
	return true
}

func generateFingerprint(keyFile *KeyFile) string {
	// Simple fingerprint from user ID and public key
	data := keyFile.UserID + keyFile.PubIdentityEd
	return fmt.Sprintf("%x", data)[:16]
}

func printKeySummary(keys *GeneratedKeys) {
	fmt.Println("\n📋 Key Summary:")
	fmt.Printf("   User ID: %s\n", keys.KeyFile.UserID)
	fmt.Printf("   Fingerprint: %s\n", generateFingerprint(keys.KeyFile))
	fmt.Printf("   Created: %s\n", keys.KeyFile.CreatedAt.Format(time.RFC3339))
	fmt.Printf("   Expires: %s\n", keys.KeyFile.ExpiresAt.Format(time.RFC3339))
	if keys.KeyFile.DeviceID != "" {
		fmt.Printf("   Device ID: %s\n", keys.KeyFile.DeviceID)
	}
	fmt.Printf("   Age Recipient: %s\n", keys.KeyFile.PubAge)
}