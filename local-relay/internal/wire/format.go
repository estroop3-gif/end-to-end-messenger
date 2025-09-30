package wire

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

const (
	// WireVersion is the current wire protocol version
	WireVersion uint8 = 1
	// MaxFrameSize is the maximum allowed frame size (2MB)
	MaxFrameSize uint32 = 2 * 1024 * 1024
	// HeaderSize is the size of the wire frame header
	HeaderSize = 5 // version(1) + length(4)
)

// OnionFrame represents a complete onion frame ready for transport
type OnionFrame struct {
	CEnvelope LayerCEnvelope `json:"c_envelope"`
}

// LayerCEnvelope represents the Layer C (outer) envelope
type LayerCEnvelope struct {
	Version   uint8     `json:"v"`
	Route     RouteInfo `json:"route"`
	AAD       AADInfo   `json:"aad"`
	Ciphertext []byte   `json:"ct"`
	Nonce     []byte    `json:"nonce_c"`
}

// RouteInfo contains routing information for the frame
type RouteInfo struct {
	SessionID string `json:"session_id"`
	DstHint   string `json:"dst_hint"`
}

// AADInfo contains additional authenticated data
type AADInfo struct {
	SizeOrig  int    `json:"size_orig"`
	Bucket    int    `json:"bucket"`
	TBucket   uint64 `json:"t_bucket"`
}

// WireFrame represents the complete wire format with header
type WireFrame struct {
	Version uint8
	Length  uint32
	Payload []byte
}

// SerializeFrame serializes an OnionFrame for wire transmission
func SerializeFrame(frame *OnionFrame) ([]byte, error) {
	// Serialize the frame payload
	payload, err := json.Marshal(frame)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal frame: %w", err)
	}

	if len(payload) > int(MaxFrameSize) {
		return nil, fmt.Errorf("frame too large: %d bytes (max: %d)", len(payload), MaxFrameSize)
	}

	// Create wire frame
	wireFrame := WireFrame{
		Version: WireVersion,
		Length:  uint32(len(payload)),
		Payload: payload,
	}

	return wireFrame.Marshal()
}

// DeserializeFrame deserializes a wire frame into an OnionFrame
func DeserializeFrame(data []byte) (*OnionFrame, error) {
	wireFrame, err := UnmarshalWireFrame(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal wire frame: %w", err)
	}

	if wireFrame.Version != WireVersion {
		return nil, fmt.Errorf("unsupported wire version: %d", wireFrame.Version)
	}

	var frame OnionFrame
	if err := json.Unmarshal(wireFrame.Payload, &frame); err != nil {
		return nil, fmt.Errorf("failed to unmarshal frame payload: %w", err)
	}

	return &frame, nil
}

// Marshal serializes a WireFrame to bytes
func (wf *WireFrame) Marshal() ([]byte, error) {
	if wf.Length > MaxFrameSize {
		return nil, fmt.Errorf("frame length exceeds maximum: %d", wf.Length)
	}

	data := make([]byte, HeaderSize+int(wf.Length))

	// Write header
	data[0] = wf.Version
	binary.BigEndian.PutUint32(data[1:5], wf.Length)

	// Write payload
	copy(data[HeaderSize:], wf.Payload)

	return data, nil
}

// UnmarshalWireFrame deserializes bytes into a WireFrame
func UnmarshalWireFrame(data []byte) (*WireFrame, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("data too short for header: %d bytes", len(data))
	}

	version := data[0]
	length := binary.BigEndian.Uint32(data[1:5])

	if length > MaxFrameSize {
		return nil, fmt.Errorf("frame length exceeds maximum: %d", length)
	}

	if len(data) < HeaderSize+int(length) {
		return nil, fmt.Errorf("incomplete frame: expected %d bytes, got %d", HeaderSize+int(length), len(data))
	}

	payload := make([]byte, length)
	copy(payload, data[HeaderSize:HeaderSize+int(length)])

	return &WireFrame{
		Version: version,
		Length:  length,
		Payload: payload,
	}, nil
}

// CreateHeartbeat creates a heartbeat frame for connection keep-alive
func CreateHeartbeat() []byte {
	wireFrame := WireFrame{
		Version: WireVersion,
		Length:  0,
		Payload: nil,
	}

	data, _ := wireFrame.Marshal()
	return data
}

// IsHeartbeat checks if a frame is a heartbeat
func IsHeartbeat(data []byte) bool {
	if len(data) != HeaderSize {
		return false
	}

	version := data[0]
	length := binary.BigEndian.Uint32(data[1:5])

	return version == WireVersion && length == 0
}

// ValidateFrame performs basic validation on a frame
func ValidateFrame(frame *OnionFrame) error {
	if frame == nil {
		return fmt.Errorf("frame is nil")
	}

	envelope := &frame.CEnvelope

	// Validate version
	if envelope.Version != 1 {
		return fmt.Errorf("unsupported envelope version: %d", envelope.Version)
	}

	// Validate session ID
	if envelope.Route.SessionID == "" {
		return fmt.Errorf("session ID is required")
	}

	// Validate AAD
	if envelope.AAD.SizeOrig <= 0 {
		return fmt.Errorf("invalid original size: %d", envelope.AAD.SizeOrig)
	}

	if envelope.AAD.Bucket <= 0 {
		return fmt.Errorf("invalid bucket size: %d", envelope.AAD.Bucket)
	}

	if envelope.AAD.SizeOrig > envelope.AAD.Bucket {
		return fmt.Errorf("original size exceeds bucket: %d > %d", envelope.AAD.SizeOrig, envelope.AAD.Bucket)
	}

	// Validate bucket sizes (must match client-side buckets)
	validBuckets := []int{4096, 16384, 65536, 262144, 1048576}
	bucketValid := false
	for _, valid := range validBuckets {
		if envelope.AAD.Bucket == valid {
			bucketValid = true
			break
		}
	}
	if !bucketValid {
		return fmt.Errorf("invalid bucket size: %d", envelope.AAD.Bucket)
	}

	// Validate ciphertext
	if len(envelope.Ciphertext) == 0 {
		return fmt.Errorf("ciphertext is empty")
	}

	// Validate nonce
	if len(envelope.Nonce) != 12 {
		return fmt.Errorf("invalid nonce length: %d", len(envelope.Nonce))
	}

	// Validate timestamp (must be within reasonable range)
	now := uint64(time.Now().Unix())
	timeDiff := int64(envelope.AAD.TBucket) - int64(now)
	if timeDiff < -300 || timeDiff > 300 { // 5 minute tolerance
		return fmt.Errorf("timestamp out of range: %d", envelope.AAD.TBucket)
	}

	return nil
}

// FrameStats contains statistics about frame processing
type FrameStats struct {
	TotalFrames     uint64 `json:"total_frames"`
	ValidFrames     uint64 `json:"valid_frames"`
	InvalidFrames   uint64 `json:"invalid_frames"`
	HeartbeatFrames uint64 `json:"heartbeat_frames"`
	BytesProcessed  uint64 `json:"bytes_processed"`
	AverageSize     uint64 `json:"average_size"`
	LastFrameTime   int64  `json:"last_frame_time"`
}

// UpdateStats updates frame processing statistics
func (stats *FrameStats) UpdateStats(frameSize int, isValid bool, isHeartbeat bool) {
	stats.TotalFrames++
	stats.BytesProcessed += uint64(frameSize)
	stats.LastFrameTime = time.Now().Unix()

	if isHeartbeat {
		stats.HeartbeatFrames++
	} else if isValid {
		stats.ValidFrames++
	} else {
		stats.InvalidFrames++
	}

	if stats.TotalFrames > 0 {
		stats.AverageSize = stats.BytesProcessed / stats.TotalFrames
	}
}

// GetStats returns a copy of the current statistics
func (stats *FrameStats) GetStats() FrameStats {
	return *stats
}