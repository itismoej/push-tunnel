# Push Notification Covert Tunnel

Research PoC that tunnels arbitrary TCP traffic through Google's FCM push notification infrastructure. Both client and relay communicate exclusively via `fcm.googleapis.com` and `mtalk.google.com` — shared by billions of Android devices, impossible to selectively block.

## Architecture

```
CENSORED REGION                    GOOGLE INFRA                       FREE REGION

┌──────────┐  ┌──────────────┐    ┌─────────────────────┐    ┌──────────────┐  ┌──────────┐
│ Browser  │─▶│ Dart Client  │───▶│ fcm.googleapis.com  │───▶│ Go Relay     │─▶│ Internet │
│ curl     │  │ SOCKS5:1080  │    │   (send via API)    │    │              │  │          │
│ any app  │◀─│              │◀───│ mtalk.google.com    │◀───│              │◀─│          │
└──────────┘  └──────────────┘    │   (receive via MCS) │    └──────────────┘  └──────────┘
                                  └─────────────────────┘
```

Both peers are symmetric — each can send (FCM HTTP v1 API) and receive (MCS protocol).

## Traffic Profile (what a censor sees)

| Connection | Destination | Looks like |
|---|---|---|
| FCM send | `fcm.googleapis.com:443` | App sending push notification |
| FCM receive | `mtalk.google.com:5228` | Android device receiving push |
| GCM register | `android.clients.google.com:443` | Android device registering |
| Decoy (optional) | `<relay>:8080` | Weather app API |

## Setup

### 1. Firebase Project

1. Create a Firebase project (e.g. "weatherpulse-12345")
2. Download the service account key JSON file
3. Note the project's sender ID (from project settings → Cloud Messaging)

### 2. Configuration

```bash
cp config.example.json config.json
```

Edit `config.json`:
```json
{
  "psk": "your-strong-shared-secret",
  "firebase_project": "weatherpulse-12345",
  "firebase_credentials": "serviceAccountKey.json",
  "sender_id": "123456789012",
  "peer_fcm_token": "",
  "listen_addr": ":8080",
  "socks_port": 1080
}
```

Both relay and client use the same config format. Fields:

| Field | Description |
|---|---|
| `psk` | Pre-shared key (must match on both sides) |
| `firebase_project` | Firebase project ID |
| `firebase_credentials` | Path to service account key JSON |
| `sender_id` | Firebase sender ID (Cloud Messaging settings) |
| `peer_fcm_token` | The other peer's FCM token (filled after first run) |
| `listen_addr` | Relay HTTP listen address (decoy server) |
| `socks_port` | Client SOCKS5 proxy port |

### 3. Token Exchange

First run of each peer prints its FCM token:

```bash
# Start relay
cd server && go run . -config ../config.json
# → prints: === FCM Token ... ===

# Start client
cd client && dart pub get && dart run bin/main.dart ../config.json
# → prints: === FCM Token ... ===
```

Copy each peer's token into the other's config as `peer_fcm_token`, then restart both.

### 4. Test

```bash
curl --socks5 127.0.0.1:1080 http://example.com
```

Verify with tcpdump: only connections to `*.googleapis.com` and `mtalk.google.com`.

## Protocol

### Frame Format

```
[1 byte: type] [2 bytes: channel_id] [2 bytes: payload_length] [N bytes: payload]
```

Types: CONNECT (0x01), DATA (0x02), DISCONNECT (0x03), ACK (0x04)

### Encryption

- HKDF-SHA256 key derivation from pre-shared key
- AES-256-GCM per frame
- Wire format: `base64(nonce[12] || ciphertext || tag[16])`

### FCM Chunking

FCM data messages max out at ~4KB. Frames up to 32KB are chunked:

```json
{
  "mid": "<message_id>",
  "ci": "0",
  "ct": "3",
  "d": "<base64_encrypted_chunk>"
}
```

### Active Probe Resistance

The relay still runs a decoy HTTP server:

- `GET /` → WeatherPulse API landing page JSON
- `GET /api/v2/health` → `{"status": "ok", "version": "3.2.1"}`
- Unknown paths → `404` with app-like error JSON
- All responses include realistic headers (X-Request-Id, X-RateLimit-*)
