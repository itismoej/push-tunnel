package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	// FCM data messages max ~4KB. With JSON overhead, ~3KB usable per chunk.
	maxChunkDataSize = 3072
	// Maximum frame size before chunking.
	maxFrameSize = 32 * 1024
	// Timeout for chunk reassembly.
	chunkTimeout = 30 * time.Second
)

// FCMTransport orchestrates sending frames via the FCM HTTP v1 API and
// receiving frames via the MCS client. Handles chunking for large frames.
type FCMTransport struct {
	crypto  *Crypto
	sender  *FCMSender
	mcs     *MCSClient
	creds   *GCMCredentials

	peerToken string // the other side's FCM token
	project   string // Firebase project ID

	onFrame func(Frame) // callback for received frames

	// Chunk reassembly state.
	chunkMu     sync.Mutex
	chunkBuffer map[string]*chunkGroup
}

// chunkGroup tracks received chunks for a single message.
type chunkGroup struct {
	total    int
	chunks   map[int][]byte
	received time.Time
}

// NewFCMTransport creates a new FCM transport.
func NewFCMTransport(crypto *Crypto, sender *FCMSender, project string, peerToken string, onFrame func(Frame)) *FCMTransport {
	return &FCMTransport{
		crypto:      crypto,
		sender:      sender,
		project:     project,
		peerToken:   peerToken,
		onFrame:     onFrame,
		chunkBuffer: make(map[string]*chunkGroup),
	}
}

// SetMCS sets the MCS client reference (for receiving).
func (t *FCMTransport) SetMCS(mcs *MCSClient) {
	t.mcs = mcs
}

// SetCredentials stores our own GCM credentials.
func (t *FCMTransport) SetCredentials(creds *GCMCredentials) {
	t.creds = creds
}

// SendFrame encrypts and sends a frame to the peer via FCM.
// Large frames are chunked into multiple FCM messages.
func (t *FCMTransport) SendFrame(frame Frame) error {
	log.Printf("[fcm-transport] sending frame type=%d ch=%d len=%d", frame.Type, frame.ChannelID, len(frame.Payload))
	raw, err := EncodeFrame(frame)
	if err != nil {
		return err
	}

	encrypted, err := t.crypto.Encrypt(raw)
	if err != nil {
		return err
	}

	encBytes := []byte(encrypted)

	if len(encBytes) <= maxChunkDataSize {
		// Single message, no chunking needed.
		err := t.sender.SendData(t.peerToken, map[string]string{
			"type": "weather_alert",
			"d":    encrypted,
		})
		if err != nil {
			log.Printf("[fcm-transport] send error: %v", err)
		}
		return err
	}

	// Chunk the encrypted data.
	mid := randomMessageID()
	chunks := splitBytes(encBytes, maxChunkDataSize)
	ct := strconv.Itoa(len(chunks))

	for i, chunk := range chunks {
		data := map[string]string{
			"type": "weather_alert",
			"mid":  mid,
			"ci":   strconv.Itoa(i),
			"ct":   ct,
			"d":    string(chunk),
		}
		if err := t.sender.SendData(t.peerToken, data); err != nil {
			return fmt.Errorf("send chunk %d/%s: %w", i, ct, err)
		}
	}

	return nil
}

// HandleMCSMessage processes an incoming MCS DataMessage.
// Called by the MCS client's onMessage callback.
func (t *FCMTransport) HandleMCSMessage(dm *DataMessage) {
	log.Printf("[fcm-transport] received MCS message from=%s category=%s fields=%d", dm.From, dm.Category, len(dm.AppDataList))
	data := make(map[string]string)
	for _, kv := range dm.AppDataList {
		data[kv.Key] = kv.Value
	}

	// Check if this is a chunked message.
	mid := data["mid"]
	if mid != "" {
		t.handleChunked(data)
		return
	}

	// Single (non-chunked) message.
	encrypted := data["d"]
	if encrypted == "" {
		return
	}

	t.decryptAndDeliver(encrypted)
}

func (t *FCMTransport) handleChunked(data map[string]string) {
	mid := data["mid"]
	ci, _ := strconv.Atoi(data["ci"])
	ct, _ := strconv.Atoi(data["ct"])
	chunk := data["d"]

	if ct <= 0 || ci < 0 || ci >= ct || chunk == "" {
		log.Printf("[fcm-transport] invalid chunk: mid=%s ci=%d ct=%d", mid, ci, ct)
		return
	}

	t.chunkMu.Lock()
	defer t.chunkMu.Unlock()

	group, ok := t.chunkBuffer[mid]
	if !ok {
		group = &chunkGroup{
			total:    ct,
			chunks:   make(map[int][]byte),
			received: time.Now(),
		}
		t.chunkBuffer[mid] = group
	}

	group.chunks[ci] = []byte(chunk)

	if len(group.chunks) < group.total {
		return
	}

	// All chunks received — reassemble.
	delete(t.chunkBuffer, mid)

	// Sort by index and concatenate.
	indices := make([]int, 0, len(group.chunks))
	for i := range group.chunks {
		indices = append(indices, i)
	}
	sort.Ints(indices)

	var assembled []byte
	for _, i := range indices {
		assembled = append(assembled, group.chunks[i]...)
	}

	t.decryptAndDeliver(string(assembled))
}

func (t *FCMTransport) decryptAndDeliver(encrypted string) {
	plaintext, err := t.crypto.Decrypt(encrypted)
	if err != nil {
		log.Printf("[fcm-transport] decrypt error: %v", err)
		return
	}

	frame, err := DecodeFrame(plaintext)
	if err != nil {
		log.Printf("[fcm-transport] frame decode error: %v", err)
		return
	}

	if t.onFrame != nil {
		t.onFrame(frame)
	}
}

// CleanStaleChunks removes chunk groups older than chunkTimeout.
func (t *FCMTransport) CleanStaleChunks() {
	t.chunkMu.Lock()
	defer t.chunkMu.Unlock()

	now := time.Now()
	for mid, group := range t.chunkBuffer {
		if now.Sub(group.received) > chunkTimeout {
			log.Printf("[fcm-transport] dropping stale chunk group %s (%d/%d received)",
				mid, len(group.chunks), group.total)
			delete(t.chunkBuffer, mid)
		}
	}
}

// StartChunkCleaner runs a periodic cleaner for stale chunk groups.
func (t *FCMTransport) StartChunkCleaner(stop chan struct{}) {
	ticker := time.NewTicker(chunkTimeout)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			t.CleanStaleChunks()
		}
	}
}

func randomMessageID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func splitBytes(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for len(data) > 0 {
		end := chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[:end])
		data = data[end:]
	}
	return chunks
}
