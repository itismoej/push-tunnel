package main

import (
	"io"
	"log"
	"net"
	"time"
)

const (
	dialTimeout = 10 * time.Second
	readBufSize = 16 * 1024
)

// RelayManager handles connecting to target hosts and reading data back.
type RelayManager struct {
	crypto *Crypto
}

// NewRelayManager creates a new relay manager.
func NewRelayManager(c *Crypto) *RelayManager {
	return &RelayManager{crypto: c}
}

// Connect dials the target and starts reading data back into the session's
// downstream queue.
func (r *RelayManager) Connect(session *Session, channelID uint16, target string) error {
	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		return err
	}
	ch := &Channel{ID: channelID, Conn: conn}
	session.AddChannel(ch)
	log.Printf("[relay] channel %d: connected to %s", channelID, target)

	// Read from target, queue downstream frames.
	go r.readLoop(session, ch)
	return nil
}

// Forward sends data to the target connection for a channel.
func (r *RelayManager) Forward(session *Session, channelID uint16, data []byte) {
	ch := session.GetChannel(channelID)
	if ch == nil {
		log.Printf("[relay] channel %d: not found, dropping data", channelID)
		return
	}
	if _, err := ch.Conn.Write(data); err != nil {
		log.Printf("[relay] channel %d: write error: %v", channelID, err)
		session.RemoveChannel(channelID)
		session.QueueDownstream(Frame{
			Type:      FrameDisconnect,
			ChannelID: channelID,
		})
	}
}

// Disconnect closes a channel's connection.
func (r *RelayManager) Disconnect(session *Session, channelID uint16) {
	session.RemoveChannel(channelID)
	log.Printf("[relay] channel %d: disconnected", channelID)
}

func (r *RelayManager) readLoop(session *Session, ch *Channel) {
	defer func() {
		session.RemoveChannel(ch.ID)
		session.QueueDownstream(Frame{
			Type:      FrameDisconnect,
			ChannelID: ch.ID,
		})
		log.Printf("[relay] channel %d: read loop ended", ch.ID)
	}()

	buf := make([]byte, readBufSize)
	for {
		n, err := ch.Conn.Read(buf)
		if n > 0 {
			payload := make([]byte, n)
			copy(payload, buf[:n])
			session.QueueDownstream(Frame{
				Type:      FrameData,
				ChannelID: ch.ID,
				Payload:   payload,
			})
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[relay] channel %d: read error: %v", ch.ID, err)
			}
			return
		}
	}
}
