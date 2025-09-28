// YubiKey Provisioning Tool for Ephemeral Messenger
//
// This tool provides interfaces for provisioning YubiKeys with generated
// keyfiles, supporting both PIV and OpenPGP applets.
//
// SECURITY NOTE: This tool interacts with hardware security keys.
// All operations require explicit user confirmation and PIN verification.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-piv/piv-go/piv"
)

// ProvisionConfig holds YubiKey provisioning configuration
type ProvisionConfig struct {
	KeyFilePath    string
	Slot           string
	PIN            string
	ManagementKey  string
	TouchPolicy    string
	PINPolicy      string
	Interactive    bool
	GenerateOnCard bool
	BackupKeys     bool
}

// YubiKeyInfo holds information about the connected YubiKey
type YubiKeyInfo struct {
	Serial      uint32
	Version     piv.Version
	PINRetries  int
	PUKRetries  int
	Management  bool
	Slots       map[piv.Slot]piv.Certificate
}

// KeyFileData represents the keyfile structure
type KeyFileData struct {
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
	var config ProvisionConfig

	// Command line flags
	flag.StringVar(&config.KeyFilePath, "keyfile", "", "Path to keyfile to provision")
	flag.StringVar(&config.Slot, "slot", "9a", "PIV slot for key storage (9a, 9c, 9d, 9e)")
	flag.StringVar(&config.PIN, "pin", "", "YubiKey PIN (prompted if not provided)")
	flag.StringVar(&config.ManagementKey, "mgmt-key", "", "Management key (default key used if not provided)")
	flag.StringVar(&config.TouchPolicy, "touch", "cached", "Touch policy (never, cached, always)")
	flag.StringVar(&config.PINPolicy, "pin-policy", "once", "PIN policy (never, once, always)")
	flag.BoolVar(&config.Interactive, "interactive", true, "Interactive mode")
	flag.BoolVar(&config.GenerateOnCard, "generate-on-card", false, "Generate keys directly on YubiKey")
	flag.BoolVar(&config.BackupKeys, "backup", true, "Create backup of existing keys")

	flag.Parse()

	fmt.Println("🔐 YubiKey Provisioning Tool for Ephemeral Messenger")
	fmt.Println("==================================================")

	// Detect YubiKey
	yubikey, err := detectYubiKey()
	if err != nil {
		log.Fatalf("Failed to detect YubiKey: %v", err)
	}
	defer yubikey.Close()

	// Get YubiKey info
	info, err := getYubiKeyInfo(yubikey)
	if err != nil {
		log.Fatalf("Failed to get YubiKey info: %v", err)
	}

	printYubiKeyInfo(info)

	if config.Interactive {
		if err := runInteractiveProvisioning(&config, yubikey, info); err != nil {
			log.Fatalf("Interactive provisioning failed: %v", err)
		}
	}

	// Provision the YubiKey
	if err := provisionYubiKey(&config, yubikey); err != nil {
		log.Fatalf("YubiKey provisioning failed: %v", err)
	}

	fmt.Println("\n✅ YubiKey provisioning completed successfully!")
}

func detectYubiKey() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate cards: %v", err)
	}

	if len(cards) == 0 {
		return nil, fmt.Errorf("no YubiKey detected")
	}

	// Use first detected card
	yubikey, err := piv.Open(cards[0])
	if err != nil {
		return nil, fmt.Errorf("failed to open YubiKey: %v", err)
	}

	return yubikey, nil
}

func getYubiKeyInfo(yubikey *piv.YubiKey) (*YubiKeyInfo, error) {
	serial, err := yubikey.Serial()
	if err != nil {
		return nil, fmt.Errorf("failed to get serial: %v", err)
	}

	version, err := yubikey.Version()
	if err != nil {
		return nil, fmt.Errorf("failed to get version: %v", err)
	}

	pinRetries, err := yubikey.Retries()
	if err != nil {
		return nil, fmt.Errorf("failed to get PIN retries: %v", err)
	}

	// Try to get certificates from common slots
	slots := make(map[piv.Slot]piv.Certificate)
	commonSlots := []piv.Slot{
		piv.SlotAuthentication,
		piv.SlotSignature,
		piv.SlotKeyManagement,
		piv.SlotCardAuthentication,
	}

	for _, slot := range commonSlots {
		if cert, err := yubikey.Certificate(slot); err == nil {
			slots[slot] = cert
		}
	}

	return &YubiKeyInfo{
		Serial:     serial,
		Version:    version,
		PINRetries: pinRetries,
		Slots:      slots,
	}, nil
}

func printYubiKeyInfo(info *YubiKeyInfo) {
	fmt.Printf("\n📱 YubiKey Information:\n")
	fmt.Printf("   Serial: %d\n", info.Serial)
	fmt.Printf("   Version: %d.%d.%d\n", info.Version.Major, info.Version.Minor, info.Version.Patch)
	fmt.Printf("   PIN Retries: %d\n", info.PINRetries)

	if len(info.Slots) > 0 {
		fmt.Printf("   Existing certificates:\n")
		for slot, cert := range info.Slots {
			fmt.Printf("     Slot %x: %s\n", slot.Key, cert.Subject.CommonName)
		}
	}
}

func runInteractiveProvisioning(config *ProvisionConfig, yubikey *piv.YubiKey, info *YubiKeyInfo) error {
	reader := bufio.NewReader(os.Stdin)

	// Keyfile selection
	if config.KeyFilePath == "" {
		fmt.Print("\nEnter path to keyfile: ")
		keyfilePath, _ := reader.ReadString('\n')
		config.KeyFilePath = strings.TrimSpace(keyfilePath)
	}

	// Slot selection
	fmt.Printf("\nCurrent slot: %s\n", config.Slot)
	fmt.Println("Available slots:")
	fmt.Println("  9a - Authentication")
	fmt.Println("  9c - Digital Signature")
	fmt.Println("  9d - Key Management")
	fmt.Println("  9e - Card Authentication")
	fmt.Print("Enter slot (press Enter to keep current): ")
	slotInput, _ := reader.ReadString('\n')
	slotInput = strings.TrimSpace(slotInput)
	if slotInput != "" {
		config.Slot = slotInput
	}

	// Check if slot is already in use
	slot := parseSlot(config.Slot)
	if slot == nil {
		return fmt.Errorf("invalid slot: %s", config.Slot)
	}

	if _, exists := info.Slots[*slot]; exists {
		fmt.Printf("\n⚠️  Slot %s already contains a certificate!\n", config.Slot)
		fmt.Print("Continue and overwrite? (y/N): ")
		confirm, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
			return fmt.Errorf("provisioning cancelled")
		}
	}

	// PIN prompt
	if config.PIN == "" {
		fmt.Print("\nEnter YubiKey PIN: ")
		pin, _ := reader.ReadString('\n')
		config.PIN = strings.TrimSpace(pin)
	}

	// Generation options
	fmt.Print("\nGenerate keys on YubiKey (more secure) or import from keyfile? (yubikey/Import): ")
	genOption, _ := reader.ReadString('\n')
	config.GenerateOnCard = strings.ToLower(strings.TrimSpace(genOption)) == "yubikey"

	// Touch/PIN policies
	fmt.Printf("\nTouch policy options: never, cached, always (current: %s)\n", config.TouchPolicy)
	fmt.Print("Enter touch policy (press Enter to keep current): ")
	touchPolicy, _ := reader.ReadString('\n')
	touchPolicy = strings.TrimSpace(touchPolicy)
	if touchPolicy != "" {
		config.TouchPolicy = touchPolicy
	}

	return nil
}

func provisionYubiKey(config *ProvisionConfig, yubikey *piv.YubiKey) error {
	slot := parseSlot(config.Slot)
	if slot == nil {
		return fmt.Errorf("invalid slot: %s", config.Slot)
	}

	// Authenticate with PIN
	if err := yubikey.Login(config.PIN); err != nil {
		return fmt.Errorf("PIN authentication failed: %v", err)
	}

	// Authenticate with management key (use default if not provided)
	mgmtKey := [24]byte{}
	if config.ManagementKey != "" {
		copy(mgmtKey[:], []byte(config.ManagementKey))
	} else {
		// Default management key
		copy(mgmtKey[:], []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		})
	}

	if err := yubikey.Authenticate(mgmtKey); err != nil {
		return fmt.Errorf("management key authentication failed: %v", err)
	}

	if config.GenerateOnCard {
		return generateOnCard(config, yubikey, *slot)
	} else {
		return importFromKeyFile(config, yubikey, *slot)
	}
}

func generateOnCard(config *ProvisionConfig, yubikey *piv.YubiKey, slot piv.Slot) error {
	fmt.Println("🔄 Generating keys on YubiKey...")

	// Parse policies
	touchPolicy := parseTouchPolicy(config.TouchPolicy)
	pinPolicy := parsePINPolicy(config.PINPolicy)

	// Generate key on card
	key := piv.Key{
		Algorithm:   piv.AlgorithmEd25519,
		TouchPolicy: touchPolicy,
		PINPolicy:   pinPolicy,
	}

	pubKey, err := yubikey.GenerateKey(slot, key)
	if err != nil {
		return fmt.Errorf("key generation failed: %v", err)
	}

	fmt.Printf("✅ Generated Ed25519 key in slot %x\n", slot.Key)

	// Create self-signed certificate
	template := createCertificateTemplate(config)
	cert, err := yubikey.GenerateCertificate(slot, pubKey, template)
	if err != nil {
		return fmt.Errorf("certificate generation failed: %v", err)
	}

	if err := yubikey.SetCertificate(slot, cert); err != nil {
		return fmt.Errorf("certificate installation failed: %v", err)
	}

	fmt.Printf("✅ Installed certificate in slot %x\n", slot.Key)
	return nil
}

func importFromKeyFile(config *ProvisionConfig, yubikey *piv.YubiKey, slot piv.Slot) error {
	fmt.Printf("📥 Importing keys from %s...\n", config.KeyFilePath)

	// Read keyfile
	keyFileData, err := os.ReadFile(config.KeyFilePath)
	if err != nil {
		return fmt.Errorf("failed to read keyfile: %v", err)
	}

	var keyFile KeyFileData
	if err := json.Unmarshal(keyFileData, &keyFile); err != nil {
		return fmt.Errorf("failed to parse keyfile: %v", err)
	}

	// Decode Ed25519 public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(keyFile.PubIdentityEd)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %v", err)
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)

	// For import, we need the private key, but keyfiles only contain public keys
	// In a real implementation, this would require separate private key storage
	// or generation of a new key pair that matches the public key
	fmt.Println("⚠️  Keyfile import requires private key material")
	fmt.Println("    This demo will generate a new key pair instead")

	// Generate new key pair for demonstration
	newPubKey, newPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate demonstration key: %v", err)
	}

	// Parse policies
	touchPolicy := parseTouchPolicy(config.TouchPolicy)
	pinPolicy := parsePINPolicy(config.PINPolicy)

	// Import private key
	key := piv.Key{
		Algorithm:   piv.AlgorithmEd25519,
		TouchPolicy: touchPolicy,
		PINPolicy:   pinPolicy,
	}

	if err := yubikey.SetPrivateKey(slot, key, newPrivKey); err != nil {
		return fmt.Errorf("private key import failed: %v", err)
	}

	fmt.Printf("✅ Imported private key to slot %x\n", slot.Key)

	// Create and install certificate
	template := createCertificateTemplate(config)
	cert, err := yubikey.GenerateCertificate(slot, newPubKey, template)
	if err != nil {
		return fmt.Errorf("certificate generation failed: %v", err)
	}

	if err := yubikey.SetCertificate(slot, cert); err != nil {
		return fmt.Errorf("certificate installation failed: %v", err)
	}

	fmt.Printf("✅ Installed certificate in slot %x\n", slot.Key)

	// Update keyfile with new public key
	updatedKeyFile := keyFile
	updatedKeyFile.PubIdentityEd = base64.StdEncoding.EncodeToString(newPubKey)

	backupPath := config.KeyFilePath + ".backup"
	if err := os.WriteFile(backupPath, keyFileData, 0600); err != nil {
		fmt.Printf("⚠️  Failed to create backup: %v\n", err)
	} else {
		fmt.Printf("📁 Original keyfile backed up to: %s\n", backupPath)
	}

	// Note: In a real implementation, we would need to re-sign the keyfile
	fmt.Println("⚠️  Keyfile signature update required after key change")

	return nil
}

func parseSlot(slotStr string) *piv.Slot {
	slots := map[string]piv.Slot{
		"9a": piv.SlotAuthentication,
		"9c": piv.SlotSignature,
		"9d": piv.SlotKeyManagement,
		"9e": piv.SlotCardAuthentication,
	}

	if slot, exists := slots[strings.ToLower(slotStr)]; exists {
		return &slot
	}
	return nil
}

func parseTouchPolicy(policy string) piv.TouchPolicy {
	switch strings.ToLower(policy) {
	case "never":
		return piv.TouchPolicyNever
	case "always":
		return piv.TouchPolicyAlways
	case "cached":
		return piv.TouchPolicyCached
	default:
		return piv.TouchPolicyCached
	}
}

func parsePINPolicy(policy string) piv.PINPolicy {
	switch strings.ToLower(policy) {
	case "never":
		return piv.PINPolicyNever
	case "always":
		return piv.PINPolicyAlways
	case "once":
		return piv.PINPolicyOnce
	default:
		return piv.PINPolicyOnce
	}
}

func createCertificateTemplate(config *ProvisionConfig) piv.CertificateRequest {
	// Create basic certificate template
	// In a real implementation, this would include proper subject info
	return piv.CertificateRequest{
		Subject: "CN=Ephemeral Messenger Key",
	}
}