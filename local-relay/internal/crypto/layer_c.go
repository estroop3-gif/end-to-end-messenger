package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	// KeySize is the size of X25519 keys and AES-256 keys
	KeySize = 32
	// NonceSize is the size of AES-GCM nonces
	NonceSize = 12
	// TagSize is the size of AES-GCM authentication tags
	TagSize = 16
)

// LayerCKey represents an AES-256-GCM key for Layer C encryption
type LayerCKey struct {
	key    [KeySize]byte
	cipher cipher.AEAD
}

// NewLayerCKey creates a new Layer C key from raw bytes
func NewLayerCKey(key [KeySize]byte) (*LayerCKey, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &LayerCKey{
		key:    key,
		cipher: aead,
	}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with additional authenticated data
func (k *LayerCKey) Encrypt(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := k.cipher.Seal(nil, nonce, plaintext, aad)

	// Prepend nonce to ciphertext
	result := make([]byte, NonceSize+len(ciphertext))
	copy(result[:NonceSize], nonce)
	copy(result[NonceSize:], ciphertext)

	return result, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with additional authenticated data
func (k *LayerCKey) Decrypt(data, aad []byte) ([]byte, error) {
	if len(data) < NonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	plaintext, err := k.cipher.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Zeroize securely clears the key material
func (k *LayerCKey) Zeroize() {
	for i := range k.key {
		k.key[i] = 0
	}
}

// LayerCContext manages Layer C encryption/decryption with key rotation
type LayerCContext struct {
	privateKey    [KeySize]byte
	publicKey     [KeySize]byte
	currentKey    *LayerCKey
	keyGeneration uint32
}

// NewLayerCContext creates a new Layer C context
func NewLayerCContext() (*LayerCContext, error) {
	privateKey := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	var privKey, pubKey [KeySize]byte
	copy(privKey[:], privateKey)
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	// Generate initial Layer C key (self-derived for testing)
	initialKey, err := deriveLayerCKey(privKey[:], pubKey[:], 0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive initial key: %w", err)
	}

	currentKey, err := NewLayerCKey(initialKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create initial key: %w", err)
	}

	return &LayerCContext{
		privateKey:    privKey,
		publicKey:     pubKey,
		currentKey:    currentKey,
		keyGeneration: 0,
	}, nil
}

// NewLayerCContextFromHex creates a new context from hex-encoded keys
func NewLayerCContextFromHex(privKeyHex, pubKeyHex string) (*LayerCContext, error) {
	if privKeyHex == "" || pubKeyHex == "" {
		return NewLayerCContext() // Generate new keys
	}

	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}

	if len(privKeyBytes) != KeySize || len(pubKeyBytes) != KeySize {
		return nil, fmt.Errorf("invalid key sizes")
	}

	var privKey, pubKey [KeySize]byte
	copy(privKey[:], privKeyBytes)
	copy(pubKey[:], pubKeyBytes)

	// Verify key pair
	var derivedPubKey [KeySize]byte
	curve25519.ScalarBaseMult(&derivedPubKey, &privKey)
	if subtle.ConstantTimeCompare(derivedPubKey[:], pubKey[:]) != 1 {
		return nil, fmt.Errorf("key pair mismatch")
	}

	// Generate initial Layer C key
	initialKey, err := deriveLayerCKey(privKey[:], pubKey[:], 0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive initial key: %w", err)
	}

	currentKey, err := NewLayerCKey(initialKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create initial key: %w", err)
	}

	return &LayerCContext{
		privateKey:    privKey,
		publicKey:     pubKey,
		currentKey:    currentKey,
		keyGeneration: 0,
	}, nil
}

// GetPublicKeyHex returns the public key as a hex string
func (ctx *LayerCContext) GetPublicKeyHex() string {
	return hex.EncodeToString(ctx.publicKey[:])
}

// GetPrivateKeyHex returns the private key as a hex string
func (ctx *LayerCContext) GetPrivateKeyHex() string {
	return hex.EncodeToString(ctx.privateKey[:])
}

// Encrypt encrypts a payload with the current Layer C key
func (ctx *LayerCContext) Encrypt(payload, aad []byte) ([]byte, error) {
	return ctx.currentKey.Encrypt(payload, aad)
}

// Decrypt decrypts a payload with the current Layer C key
func (ctx *LayerCContext) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	return ctx.currentKey.Decrypt(ciphertext, aad)
}

// RotateKeys generates a new Layer C key for the next generation
func (ctx *LayerCContext) RotateKeys() error {
	ctx.keyGeneration++

	newKey, err := deriveLayerCKey(ctx.privateKey[:], ctx.publicKey[:], ctx.keyGeneration)
	if err != nil {
		return fmt.Errorf("failed to derive new key: %w", err)
	}

	// Zeroize old key
	if ctx.currentKey != nil {
		ctx.currentKey.Zeroize()
	}

	ctx.currentKey, err = NewLayerCKey(newKey)
	if err != nil {
		return fmt.Errorf("failed to create new key: %w", err)
	}

	return nil
}

// GetKeyGeneration returns the current key generation number
func (ctx *LayerCContext) GetKeyGeneration() uint32 {
	return ctx.keyGeneration
}

// Zeroize securely clears all key material
func (ctx *LayerCContext) Zeroize() {
	for i := range ctx.privateKey {
		ctx.privateKey[i] = 0
	}
	for i := range ctx.publicKey {
		ctx.publicKey[i] = 0
	}
	if ctx.currentKey != nil {
		ctx.currentKey.Zeroize()
	}
}

// PerformHandshake performs X25519 key agreement with a remote public key
func (ctx *LayerCContext) PerformHandshake(remotePubKey [KeySize]byte) (*LayerCKey, error) {
	var sharedSecret [KeySize]byte
	curve25519.ScalarMult(&sharedSecret, &ctx.privateKey, &remotePubKey)

	// Derive session key from shared secret
	sessionKey, err := deriveLayerCKey(sharedSecret[:], remotePubKey[:], 0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	// Zeroize shared secret
	for i := range sharedSecret {
		sharedSecret[i] = 0
	}

	return NewLayerCKey(sessionKey)
}

// deriveLayerCKey derives an AES-256 key using HKDF-SHA3
func deriveLayerCKey(secret, salt []byte, generation uint32) ([KeySize]byte, error) {
	var result [KeySize]byte

	// Create HKDF with SHA3-256
	hkdf := hkdf.New(sha3.New256, secret, salt, []byte(fmt.Sprintf("layer-c-local-v1-gen-%d", generation)))

	if _, err := io.ReadFull(hkdf, result[:]); err != nil {
		return result, fmt.Errorf("HKDF expansion failed: %w", err)
	}

	return result, nil
}

// ConstantTimeCompare performs constant-time comparison of two byte slices
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}