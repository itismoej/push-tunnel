package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	checkinURL  = "https://android.clients.google.com/checkin"
	registerURL = "https://android.clients.google.com/c2dm/register3"
	credsFile   = "gcm_credentials.json"
)

// GCMCredentials holds the device registration state.
type GCMCredentials struct {
	AndroidID     uint64 `json:"android_id"`
	SecurityToken uint64 `json:"security_token"`
	FCMToken      string `json:"fcm_token"`
}

// RegisterGCM performs checkin + registration, returning an FCM token.
// Credentials are persisted to disk so subsequent runs skip registration.
func RegisterGCM(senderID string) (*GCMCredentials, error) {
	// Try loading existing credentials.
	creds, err := loadCredentials()
	if err == nil && creds.FCMToken != "" {
		log.Printf("[gcm] loaded existing credentials (androidId=%d)", creds.AndroidID)
		return creds, nil
	}

	log.Println("[gcm] no existing credentials, performing checkin...")

	// Step 1: Checkin.
	androidID, securityToken, err := doCheckin()
	if err != nil {
		return nil, fmt.Errorf("checkin: %w", err)
	}
	log.Printf("[gcm] checkin ok: androidId=%d", androidID)

	// Step 2: Register for FCM.
	fcmToken, err := doRegister(androidID, securityToken, senderID)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	log.Printf("[gcm] registered, token=%s…", truncate(fcmToken, 20))

	creds = &GCMCredentials{
		AndroidID:     androidID,
		SecurityToken: securityToken,
		FCMToken:      fcmToken,
	}

	if err := saveCredentials(creds); err != nil {
		log.Printf("[gcm] warning: failed to save credentials: %v", err)
	}

	return creds, nil
}

func doCheckin() (uint64, uint64, error) {
	body := map[string]interface{}{
		"checkin": map[string]interface{}{
			"type": 3,
			"chromeBuild": map[string]interface{}{
				"platform":      2,
				"chromeVersion": "63.0.3234.0",
				"channel":       1,
			},
		},
		"version":       3,
		"id":            0,
		"securityToken": 0,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return 0, 0, err
	}

	resp, err := http.Post(checkinURL, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, fmt.Errorf("read checkin response: %w", err)
	}

	if resp.StatusCode != 200 {
		return 0, 0, fmt.Errorf("checkin returned %d: %s", resp.StatusCode, string(respBody))
	}

	// Response returns androidId and securityToken as either numbers or strings.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return 0, 0, fmt.Errorf("decode checkin response: %w", err)
	}

	androidID, err := parseJSONUint64(raw["android_id"])
	if err != nil {
		return 0, 0, fmt.Errorf("parse android_id: %w (response: %s)", err, string(respBody))
	}
	securityToken, err := parseJSONUint64(raw["security_token"])
	if err != nil {
		return 0, 0, fmt.Errorf("parse securityToken: %w", err)
	}

	if androidID == 0 {
		return 0, 0, fmt.Errorf("checkin returned zero androidId (response: %s)", string(respBody))
	}

	return androidID, securityToken, nil
}

// parseJSONUint64 parses a JSON value that may be a number or a quoted string.
func parseJSONUint64(raw json.RawMessage) (uint64, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("missing field")
	}
	// Try as number first.
	var n uint64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, nil
	}
	// Try as string.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strconv.ParseUint(s, 10, 64)
	}
	return 0, fmt.Errorf("cannot parse %s as uint64", string(raw))
}

func doRegister(androidID, securityToken uint64, senderID string) (string, error) {
	form := url.Values{}
	form.Set("app", "org.chromium.linux")
	form.Set("X-subtype", senderID)
	form.Set("device", strconv.FormatUint(androidID, 10))
	form.Set("sender", senderID)

	req, err := http.NewRequest("POST", registerURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", fmt.Sprintf("AidLogin %d:%d", androidID, securityToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("register returned %d: %s", resp.StatusCode, string(respBody))
	}

	// Response is key=value pairs, one per line. We want "token=...".
	for _, line := range strings.Split(string(respBody), "\n") {
		if strings.HasPrefix(line, "token=") {
			return strings.TrimPrefix(line, "token="), nil
		}
	}

	return "", fmt.Errorf("no token in register response: %s", string(respBody))
}

func loadCredentials() (*GCMCredentials, error) {
	data, err := os.ReadFile(credsFile)
	if err != nil {
		return nil, err
	}
	var creds GCMCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

func saveCredentials(creds *GCMCredentials) error {
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(credsFile, data, 0600)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
