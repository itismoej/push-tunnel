package main

import (
	"log"
	"net"
	"sync"
)

// Channel represents a single TCP connection tunnelled through the session.
type Channel struct {
	ID   uint16
	Conn net.Conn
}

// Session represents a connected client with its set of tunnelled channels.
type Session struct {
	DeviceID   string
	mu         sync.RWMutex
	channels   map[uint16]*Channel
	nextChanID uint16
	downstream chan Frame // frames queued for delivery to client
}

// NewSession creates a new client session.
func NewSession(deviceID string) *Session {
	return &Session{
		DeviceID:   deviceID,
		channels:   make(map[uint16]*Channel),
		downstream: make(chan Frame, 256),
	}
}

// GetChannel returns a channel by ID.
func (s *Session) GetChannel(id uint16) *Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.channels[id]
}

// AddChannel registers a channel.
func (s *Session) AddChannel(ch *Channel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.channels[ch.ID] = ch
}

// RemoveChannel closes and removes a channel.
func (s *Session) RemoveChannel(id uint16) {
	s.mu.Lock()
	ch, ok := s.channels[id]
	if ok {
		delete(s.channels, id)
	}
	s.mu.Unlock()
	if ok && ch.Conn != nil {
		ch.Conn.Close()
	}
}

// CloseAll tears down every channel in the session.
func (s *Session) CloseAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ch := range s.channels {
		if ch.Conn != nil {
			ch.Conn.Close()
		}
		delete(s.channels, id)
	}
}

// QueueDownstream queues a frame for downstream delivery.
func (s *Session) QueueDownstream(f Frame) {
	select {
	case s.downstream <- f:
	default:
		log.Printf("[session:%s] downstream queue full, dropping frame for channel %d", s.DeviceID, f.ChannelID)
	}
}

// SessionManager manages all active client sessions.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewSessionManager creates a new manager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
	}
}

// GetOrCreate returns an existing session or creates one.
func (m *SessionManager) GetOrCreate(deviceID string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[deviceID]; ok {
		return s
	}
	s := NewSession(deviceID)
	m.sessions[deviceID] = s
	log.Printf("[sessions] new session for device %s", deviceID)
	return s
}

// Get returns a session if it exists.
func (m *SessionManager) Get(deviceID string) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[deviceID]
}

// Remove destroys a session.
func (m *SessionManager) Remove(deviceID string) {
	m.mu.Lock()
	s, ok := m.sessions[deviceID]
	if ok {
		delete(m.sessions, deviceID)
	}
	m.mu.Unlock()
	if ok {
		s.CloseAll()
	}
}
