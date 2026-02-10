package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// Config holds server configuration.
type Config struct {
	ListenAddr   string `json:"listen_addr"`
	PSK          string `json:"psk"`
	FCMCreds     string `json:"firebase_credentials"`
	Project      string `json:"firebase_project"`
	SenderID     string `json:"sender_id"`
	PeerFCMToken string `json:"peer_fcm_token"`
}

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	listenAddr := flag.String("listen", ":8080", "listen address")
	psk := flag.String("psk", "", "pre-shared key")
	flag.Parse()

	cfg := loadConfig(*configPath, *listenAddr, *psk)

	if cfg.PSK == "" {
		log.Fatal("PSK is required. Set via config file or -psk flag.")
	}

	crypto, err := NewCrypto(cfg.PSK)
	if err != nil {
		log.Fatalf("crypto init: %v", err)
	}

	// FCM sender (for sending to peer via FCM HTTP v1 API).
	fcmSender, err := NewFCMSender(cfg.FCMCreds, cfg.Project)
	if err != nil {
		log.Fatalf("fcm sender init: %v", err)
	}

	srv := NewServer(crypto, cfg)

	// Set up FCM transport if credentials are provided.
	if cfg.FCMCreds != "" && cfg.SenderID != "" {
		// Register with GCM to get our own FCM token.
		creds, err := RegisterGCM(cfg.SenderID)
		if err != nil {
			log.Fatalf("gcm registration: %v", err)
		}

		fmt.Println("")
		fmt.Println("=== FCM Token (copy to peer's config as peer_fcm_token) ===")
		fmt.Println(creds.FCMToken)
		fmt.Println("============================================================")
		fmt.Println("")

		// Create FCM transport.
		transport := NewFCMTransport(crypto, fcmSender, cfg.Project, cfg.PeerFCMToken, func(frame Frame) {
			// Incoming frame from peer (client) — process as upstream.
			session := srv.sessions.GetOrCreate("fcm-peer")
			srv.processUpstreamFrame(session, frame)
		})
		transport.SetCredentials(creds)

		// Start MCS client for receiving.
		mcs := NewMCSClient(creds.AndroidID, creds.SecurityToken, func(dm *DataMessage) {
			transport.HandleMCSMessage(dm)
		})
		transport.SetMCS(mcs)
		mcs.Start()

		srv.transport = transport

		// Self-test: send a test FCM message to ourselves after a delay.
		go func() {
			time.Sleep(5 * time.Second)
			log.Println("[self-test] sending test FCM message to ourselves...")
			err := fcmSender.SendData(creds.FCMToken, map[string]string{
				"type": "test",
				"d":    "hello-self-test",
			})
			if err != nil {
				log.Printf("[self-test] send failed: %v", err)
			} else {
				log.Println("[self-test] send ok — waiting 30s for MCS delivery...")
			}
			// Wait, then check if anything arrived.
			time.Sleep(30 * time.Second)
			log.Println("[self-test] 30s elapsed — if no MCS message logged above, delivery failed")
		}()

		// Start downstream drainer: reads from session and sends via FCM.
		if cfg.PeerFCMToken != "" {
			go srv.drainDownstream(transport)
		}

		// Start chunk cleaner.
		stopCleaner := make(chan struct{})
		go transport.StartChunkCleaner(stopCleaner)

		defer func() {
			close(stopCleaner)
			mcs.Stop()
		}()
	}

	// Always run the decoy HTTP server.
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)

	log.Printf("push-tunnel relay listening on %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func loadConfig(path, listenFlag, pskFlag string) Config {
	cfg := Config{
		ListenAddr: ":8080",
	}

	// Try loading from file.
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Printf("warning: config parse error: %v", err)
		}
	}

	// CLI flags override file values.
	if listenFlag != ":8080" || cfg.ListenAddr == "" {
		cfg.ListenAddr = listenFlag
	}
	if pskFlag != "" {
		cfg.PSK = pskFlag
	}

	return cfg
}
