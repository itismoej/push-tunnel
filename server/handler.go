package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

// Server is the main HTTP server and FCM relay.
type Server struct {
	crypto    *Crypto
	sessions  *SessionManager
	relay     *RelayManager
	transport *FCMTransport // nil if FCM not configured
	cfg       Config
}

// NewServer creates a new server instance.
func NewServer(crypto *Crypto, cfg Config) *Server {
	sm := NewSessionManager()
	return &Server{
		crypto:   crypto,
		sessions: sm,
		relay:    NewRelayManager(crypto),
		cfg:      cfg,
	}
}

// SetupRoutes registers all HTTP handlers (decoy + legacy).
func (s *Server) SetupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/api/v2/health", s.handleHealth)
}

// drainDownstream reads frames from the FCM peer session's downstream
// channel and sends them to the peer via FCM transport.
func (s *Server) drainDownstream(transport *FCMTransport) {
	session := s.sessions.GetOrCreate("fcm-peer")
	log.Println("[relay] starting FCM downstream drain for peer")
	for {
		frame := <-session.downstream
		if err := transport.SendFrame(frame); err != nil {
			log.Printf("[relay] FCM send error: %v", err)
		}
		// Small delay to avoid rate limiting.
		time.Sleep(10 * time.Millisecond)
	}
}

// --- Middleware ---

func addDecoyHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Request-Id", fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		rand.Int31(), rand.Int31n(0xffff), rand.Int31n(0xffff),
		rand.Int31n(0xffff), rand.Int63n(0xffffffffffff)))
	w.Header().Set("X-RateLimit-Limit", "1000")
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(900+rand.Intn(100)))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	w.Header().Set("Server", "weatherpulse/3.2.1")
	w.Header().Set("Cache-Control", "no-store")
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	addDecoyHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"code":    code,
			"message": msg,
		},
	})
}

// --- Handlers ---

// handleRoot returns a plausible landing page for active probers.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		jsonError(w, 404, "Not found")
		return
	}
	addDecoyHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":    "WeatherPulse API",
		"version": "3.2.1",
		"docs":    "https://docs.weatherpulse.app/api/v2",
		"status":  "operational",
	})
}

// handleHealth returns a health check response.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	addDecoyHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"version": "3.2.1",
	})
}

// processUpstreamFrame handles a decrypted frame from the client.
func (s *Server) processUpstreamFrame(session *Session, f Frame) {
	switch f.Type {
	case FrameConnect:
		target := string(f.Payload)
		log.Printf("[handler] CONNECT channel %d → %s", f.ChannelID, target)
		if err := s.relay.Connect(session, f.ChannelID, target); err != nil {
			log.Printf("[handler] connect failed: %v", err)
			session.QueueDownstream(Frame{
				Type:      FrameDisconnect,
				ChannelID: f.ChannelID,
			})
		} else {
			session.QueueDownstream(Frame{
				Type:      FrameAck,
				ChannelID: f.ChannelID,
			})
		}
	case FrameData:
		s.relay.Forward(session, f.ChannelID, f.Payload)
	case FrameDisconnect:
		s.relay.Disconnect(session, f.ChannelID)
	case FrameAck:
		// Client acknowledged; no-op for now.
	}
}
