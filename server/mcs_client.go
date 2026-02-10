package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

const (
	mtalkHost         = "mtalk.google.com:5228"
	heartbeatInterval = 4 * time.Minute
	reconnectDelay    = 5 * time.Second
	readBufMCS        = 8192
)

// MCSClient maintains a persistent TLS connection to mtalk.google.com
// for receiving FCM push messages via the MCS protocol.
type MCSClient struct {
	androidID     uint64
	securityToken uint64

	onMessage func(*DataMessage) // callback for incoming data messages

	mu   sync.Mutex
	conn *tls.Conn
	stop chan struct{}
	wg   sync.WaitGroup

	// Stream ID tracking — MCS requires acknowledging received messages.
	streamMu             sync.Mutex
	outStreamID          int // our outgoing message counter
	lastStreamIDReceived int // last server message counter we received

	// Persistent IDs to acknowledge.
	ackMu  sync.Mutex
	ackIDs []string
}

// NewMCSClient creates a new MCS client.
func NewMCSClient(androidID, securityToken uint64, onMessage func(*DataMessage)) *MCSClient {
	return &MCSClient{
		androidID:     androidID,
		securityToken: securityToken,
		onMessage:     onMessage,
		stop:          make(chan struct{}),
	}
}

// Start begins the MCS connection loop in a goroutine.
func (m *MCSClient) Start() {
	m.wg.Add(1)
	go m.connectLoop()
}

// Stop closes the MCS connection.
func (m *MCSClient) Stop() {
	close(m.stop)
	m.mu.Lock()
	if m.conn != nil {
		m.conn.Close()
	}
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *MCSClient) connectLoop() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stop:
			return
		default:
		}

		err := m.runSession()
		if err != nil {
			log.Printf("[mcs] session error: %v", err)
		}

		select {
		case <-m.stop:
			return
		case <-time.After(reconnectDelay):
			log.Println("[mcs] reconnecting...")
		}
	}
}

func (m *MCSClient) runSession() error {
	conn, err := tls.Dial("tcp", mtalkHost, &tls.Config{})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	m.mu.Lock()
	m.conn = conn
	m.mu.Unlock()

	// Reset stream counters for new session.
	m.streamMu.Lock()
	m.outStreamID = 0
	m.lastStreamIDReceived = 0
	m.streamMu.Unlock()

	defer func() {
		conn.Close()
		m.mu.Lock()
		m.conn = nil
		m.mu.Unlock()
	}()

	log.Println("[mcs] connected to", mtalkHost)

	// Send LoginRequest (counts as our first outgoing message).
	loginMsg := BuildLoginRequest(m.androidID, m.securityToken)
	loginFrame := EncodeMCSMessage(TagLoginRequest, loginMsg, true)
	if _, err := conn.Write(loginFrame); err != nil {
		return fmt.Errorf("send login: %w", err)
	}
	m.incrementOutStream()

	// Start heartbeat ticker.
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()

	// Start heartbeat sender goroutine.
	go func() {
		for {
			select {
			case <-m.stop:
				return
			case <-heartbeat.C:
				m.sendHeartbeat(conn)
				m.flushAcks(conn)
			}
		}
	}()

	// Read loop.
	reader := NewMCSReader()
	buf := make([]byte, readBufMCS)

	for {
		select {
		case <-m.stop:
			return nil
		default:
		}

		conn.SetReadDeadline(time.Now().Add(heartbeatInterval + 30*time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			reader.Feed(buf[:n])
			m.processMessages(reader, conn)
		}
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("server closed connection")
			}
			return fmt.Errorf("read: %w", err)
		}
	}
}

func (m *MCSClient) incrementInStream() int {
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	m.lastStreamIDReceived++
	return m.lastStreamIDReceived
}

func (m *MCSClient) incrementOutStream() int {
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	m.outStreamID++
	return m.outStreamID
}

func (m *MCSClient) getStreamIDs() (int, int) {
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	return m.outStreamID, m.lastStreamIDReceived
}

func (m *MCSClient) processMessages(reader *MCSReader, conn *tls.Conn) {
	for {
		msg := reader.Next()
		if msg == nil {
			return
		}

		// Every message from the server increments our received counter.
		streamID := m.incrementInStream()

		switch msg.Tag {
		case TagLoginResponse:
			// Parse and log LoginResponse fields for debugging.
			if fields, err := decodeProtoFields(msg.Body); err == nil {
				for _, f := range fields {
					if f.wireType == 2 {
						log.Printf("[mcs] LoginResponse field %d (string): %q", f.fieldNum, string(f.data))
					} else if f.wireType == 0 {
						log.Printf("[mcs] LoginResponse field %d (varint): %d", f.fieldNum, f.varint)
					}
				}
			}
			log.Printf("[mcs] login successful (server stream_id=%d)", streamID)

			// Immediately send heartbeat to acknowledge LoginResponse.
			m.sendHeartbeat(conn)

		case TagHeartbeatPing:
			log.Printf("[mcs] received HeartbeatPing")
			// Respond with HeartbeatAck including stream ack.
			_, lastRecv := m.getStreamIDs()
			ack := EncodeMCSMessage(TagHeartbeatAck, BuildHeartbeatAck(lastRecv), false)
			conn.Write(ack)

		case TagHeartbeatAck:
			log.Printf("[mcs] received HeartbeatAck")

		case TagClose:
			log.Println("[mcs] server sent Close")

		case TagIqStanza:
			iqType, hasType := uint64(0), false
			iqID, iqFrom, iqTo := "", "", ""
			extID, hasExtID := uint64(0), false
			if fields, err := decodeProtoFields(msg.Body); err == nil {
				iqType, hasType = getVarintField(fields, 2)
				iqID = getStringField(fields, 3)
				iqFrom = getStringField(fields, 4)
				iqTo = getStringField(fields, 5)

				ext := getRepeatedMessage(fields, 7)
				if len(ext) > 0 {
					extID, hasExtID = getVarintField(ext[0], 1)
				}
			} else {
				log.Printf("[mcs] parse IqStanza error: %v", err)
			}

			if hasExtID {
				log.Printf("[mcs] received IqStanza type=%d id=%q ext=%d len=%d", iqType, iqID, extID, len(msg.Body))
			} else {
				log.Printf("[mcs] received IqStanza type=%d id=%q len=%d", iqType, iqID, len(msg.Body))
			}

			// Server IQ GET/SET stanzas expect a RESULT response with matching id.
			if hasType && (iqType == 0 || iqType == 1) {
				resultMsg := BuildIqResult(iqID, iqFrom, iqTo)
				result := EncodeMCSMessage(TagIqStanza, resultMsg, false)
				if _, err := conn.Write(result); err != nil {
					log.Printf("[mcs] iq result send error: %v", err)
				} else {
					m.incrementOutStream()
				}
			}

		case TagDataMessageStanza:
			log.Printf("[mcs] received DataMessageStanza, len=%d", len(msg.Body))
			dm, err := ParseDataMessageStanza(msg.Body)
			if err != nil {
				log.Printf("[mcs] parse data message error: %v", err)
				continue
			}

			// Queue persistent ID for acknowledgment.
			if dm.PersistentID != "" {
				m.ackMu.Lock()
				m.ackIDs = append(m.ackIDs, dm.PersistentID)
				m.ackMu.Unlock()
				// Ack promptly to reduce duplicate deliveries.
				m.flushAcks(conn)
			}

			if m.onMessage != nil {
				m.onMessage(dm)
			}

		default:
			log.Printf("[mcs] unknown tag %d, len=%d", msg.Tag, len(msg.Body))
		}
	}
}

func (m *MCSClient) sendHeartbeat(conn *tls.Conn) {
	outID, lastRecv := m.getStreamIDs()
	log.Printf("[mcs] sending HeartbeatPing (out=%d, lastRecv=%d)", outID, lastRecv)
	ping := EncodeMCSMessage(TagHeartbeatPing, BuildHeartbeatPing(outID, lastRecv), false)
	if _, err := conn.Write(ping); err != nil {
		log.Printf("[mcs] heartbeat send error: %v", err)
	}
	m.incrementOutStream()
}

func (m *MCSClient) flushAcks(conn *tls.Conn) {
	m.ackMu.Lock()
	ids := m.ackIDs
	m.ackIDs = nil
	m.ackMu.Unlock()

	if len(ids) == 0 {
		return
	}

	outID, _ := m.getStreamIDs()
	iqID := fmt.Sprintf("ack-%d", outID+1)
	ack := EncodeMCSMessage(TagIqStanza, BuildSelectiveAck(ids, iqID), false)
	if _, err := conn.Write(ack); err != nil {
		log.Printf("[mcs] ack send error: %v", err)
	}
	m.incrementOutStream()
}
