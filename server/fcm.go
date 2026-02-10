package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// FCMSender sends push notifications via the FCM HTTP v1 API.
// No Firebase Admin SDK — uses raw HTTP with OAuth2 service account auth.
type FCMSender struct {
	project    string
	tokenSrc   oauth2.TokenSource
	httpClient *http.Client
	enabled    bool
	mu         sync.Mutex
}

// NewFCMSender initialises the FCM sender from a service account key file.
// project is the Firebase project ID (e.g. "weatherpulse-12345").
func NewFCMSender(credFile string, project string) (*FCMSender, error) {
	if credFile == "" || project == "" {
		log.Println("[fcm] no credentials/project; FCM sending disabled")
		return &FCMSender{enabled: false}, nil
	}

	keyJSON, err := os.ReadFile(credFile)
	if err != nil {
		return nil, fmt.Errorf("read service account key: %w", err)
	}

	cfg, err := google.JWTConfigFromJSON(keyJSON, "https://www.googleapis.com/auth/firebase.messaging")
	if err != nil {
		return nil, fmt.Errorf("parse service account key: %w", err)
	}

	tokenSrc := cfg.TokenSource(oauth2.NoContext)

	log.Printf("[fcm] sender initialised for project %s", project)
	return &FCMSender{
		project:    project,
		tokenSrc:   tokenSrc,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		enabled:    true,
	}, nil
}

// SendData sends an FCM data message with the given key-value data payload.
func (f *FCMSender) SendData(fcmToken string, data map[string]string) error {
	if !f.enabled {
		return nil
	}

	url := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", f.project)

	payload := map[string]interface{}{
		"message": map[string]interface{}{
			"token": fcmToken,
			"data":  data,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	token, err := f.tokenSrc.Token()
	if err != nil {
		return fmt.Errorf("oauth2 token: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fcm send: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("[fcm] API response %d: %s", resp.StatusCode, string(respBody))

	if resp.StatusCode != 200 {
		respStr := string(respBody)
		if strings.Contains(respStr, "UNREGISTERED") || strings.Contains(respStr, "INVALID_ARGUMENT") {
			return fmt.Errorf("fcm: peer token invalid (%d): %s", resp.StatusCode, respStr)
		}
		return fmt.Errorf("fcm: %d: %s", resp.StatusCode, respStr)
	}

	return nil
}
