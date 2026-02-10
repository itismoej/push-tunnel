package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// MCS protocol tags.
const (
	TagHeartbeatPing     = 0
	TagHeartbeatAck      = 1
	TagLoginRequest      = 2
	TagLoginResponse     = 3
	TagClose             = 4
	TagIqStanza          = 7
	TagDataMessageStanza = 8
)

// MCS protocol version.
const mcsVersion = 41

// --- Protobuf helpers (hand-rolled, no codegen) ---

// protoField represents a single protobuf field.
type protoField struct {
	fieldNum uint64
	wireType int // 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit
	varint   uint64
	data     []byte
}

// encodeVarint encodes a varint and returns the bytes.
func encodeVarint(v uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, v)
	return buf[:n]
}

// encodeTag encodes a protobuf field tag (field number + wire type).
func encodeTag(fieldNum uint64, wireType int) []byte {
	return encodeVarint((fieldNum << 3) | uint64(wireType))
}

// encodeStringField encodes a string/bytes protobuf field.
func encodeStringField(fieldNum uint64, data []byte) []byte {
	var buf []byte
	buf = append(buf, encodeTag(fieldNum, 2)...)
	buf = append(buf, encodeVarint(uint64(len(data)))...)
	buf = append(buf, data...)
	return buf
}

// encodeVarintField encodes a varint protobuf field.
func encodeVarintField(fieldNum uint64, v uint64) []byte {
	var buf []byte
	buf = append(buf, encodeTag(fieldNum, 0)...)
	buf = append(buf, encodeVarint(v)...)
	return buf
}

// decodeProtoFields parses raw protobuf bytes into a list of fields.
func decodeProtoFields(data []byte) ([]protoField, error) {
	var fields []protoField
	offset := 0
	for offset < len(data) {
		tagVal, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			return nil, errors.New("invalid varint for tag")
		}
		offset += n

		fieldNum := tagVal >> 3
		wireType := int(tagVal & 0x07)

		f := protoField{fieldNum: fieldNum, wireType: wireType}

		switch wireType {
		case 0: // varint
			v, n := binary.Uvarint(data[offset:])
			if n <= 0 {
				return nil, errors.New("invalid varint for field value")
			}
			offset += n
			f.varint = v
		case 1: // 64-bit
			if offset+8 > len(data) {
				return nil, errors.New("truncated 64-bit field")
			}
			f.data = data[offset : offset+8]
			offset += 8
		case 2: // length-delimited
			length, n := binary.Uvarint(data[offset:])
			if n <= 0 {
				return nil, errors.New("invalid varint for length")
			}
			offset += n
			if uint64(offset)+length > uint64(len(data)) {
				return nil, fmt.Errorf("length-delimited field overflows: need %d, have %d", length, len(data)-offset)
			}
			f.data = data[offset : offset+int(length)]
			offset += int(length)
		case 5: // 32-bit
			if offset+4 > len(data) {
				return nil, errors.New("truncated 32-bit field")
			}
			f.data = data[offset : offset+4]
			offset += 4
		default:
			return nil, fmt.Errorf("unsupported wire type %d", wireType)
		}

		fields = append(fields, f)
	}
	return fields, nil
}

// getStringField returns the first length-delimited field with the given number.
func getStringField(fields []protoField, num uint64) string {
	for _, f := range fields {
		if f.fieldNum == num && f.wireType == 2 {
			return string(f.data)
		}
	}
	return ""
}

// getVarintField returns the first varint field with the given number.
func getVarintField(fields []protoField, num uint64) (uint64, bool) {
	for _, f := range fields {
		if f.fieldNum == num && f.wireType == 0 {
			return f.varint, true
		}
	}
	return 0, false
}

// getRepeatedMessage returns all length-delimited fields with the given number,
// each parsed as a sub-message.
func getRepeatedMessage(fields []protoField, num uint64) [][]protoField {
	var result [][]protoField
	for _, f := range fields {
		if f.fieldNum == num && f.wireType == 2 {
			sub, err := decodeProtoFields(f.data)
			if err == nil {
				result = append(result, sub)
			}
		}
	}
	return result
}

// --- MCS Messages ---

// LoginRequest builds a serialised MCS LoginRequest protobuf.
//
// LoginRequest proto fields (from Android MCS proto):
//
//	field 1 (string):          id — Chrome build identifier
//	field 2 (string):          domain — "mcs.android.com"
//	field 3 (string):          user — android_id as string
//	field 4 (string):          resource — android_id as string
//	field 5 (string):          auth_token — security_token as string
//	field 6 (string):          device_id — "android-HEX"
//	field 7 (int64):           last_rmq_id
//	field 8 (repeated Setting): setting — key-value pairs
//	field 9 (int32):           compress
//	field 10 (repeated string): received_persistent_id
//	field 12 (bool):           adaptive_heartbeat
//	field 14 (bool):           use_rmq2 — CRITICAL: enables message delivery
//	field 15 (int64):          account_id
//	field 16 (int32):          auth_service — 2 = ANDROID_ID
//	field 17 (int32):          network_type — 1 = WiFi
func BuildLoginRequest(androidID, securityToken uint64) []byte {
	hexID := fmt.Sprintf("%x", androidID)
	clientID := "chrome-63.0.3234.0"
	deviceID := "android-" + hexID
	aidStr := fmt.Sprintf("%d", androidID)
	tokenStr := fmt.Sprintf("%d", securityToken)

	// Build Setting message for "new_vc" = "1"
	var settingMsg []byte
	settingMsg = append(settingMsg, encodeStringField(1, []byte("new_vc"))...)
	settingMsg = append(settingMsg, encodeStringField(2, []byte("1"))...)

	var msg []byte
	msg = append(msg, encodeStringField(1, []byte(clientID))...)          // id
	msg = append(msg, encodeStringField(2, []byte("mcs.android.com"))...) // domain
	msg = append(msg, encodeStringField(3, []byte(aidStr))...)            // user
	msg = append(msg, encodeStringField(4, []byte(aidStr))...)            // resource
	msg = append(msg, encodeStringField(5, []byte(tokenStr))...)          // auth_token
	msg = append(msg, encodeStringField(6, []byte(deviceID))...)          // device_id
	msg = append(msg, encodeStringField(8, settingMsg)...)                // setting: new_vc=1
	msg = append(msg, encodeVarintField(14, 1)...)                        // use_rmq2 = true
	msg = append(msg, encodeVarintField(16, 2)...)                        // auth_service = ANDROID_ID
	msg = append(msg, encodeVarintField(17, 1)...)                        // network_type = WiFi

	return msg
}

// HeartbeatPing fields:
//
//	field 1 (int32): stream_id — our outgoing stream counter
//	field 2 (int32): last_stream_id_received — last server message we received
//	field 3 (int64): status
func BuildHeartbeatPing(streamID, lastStreamIDReceived int) []byte {
	var msg []byte
	if streamID > 0 {
		msg = append(msg, encodeVarintField(1, uint64(streamID))...)
	}
	if lastStreamIDReceived > 0 {
		msg = append(msg, encodeVarintField(2, uint64(lastStreamIDReceived))...)
	}
	msg = append(msg, encodeVarintField(3, 0)...) // status = 0
	return msg
}

// HeartbeatAck is sent in response to HeartbeatPing.
func BuildHeartbeatAck(lastStreamIDReceived int) []byte {
	var msg []byte
	if lastStreamIDReceived > 0 {
		msg = append(msg, encodeVarintField(2, uint64(lastStreamIDReceived))...)
	}
	msg = append(msg, encodeVarintField(3, 0)...) // status = 0
	return msg
}

// SelectiveAck acknowledges persistent IDs.
//
// IqStanza fields for selective ack:
//
//	field 2 (int32): type = 1 (SET)
//	field 3 (string): id
//	field 7 (message): extension (id=12, data=<SelectiveAck>)
func BuildSelectiveAck(persistentIDs []string, iqID string) []byte {
	if iqID == "" {
		iqID = "0"
	}

	// Build inner SelectiveAck message: field 1 (repeated string): id
	var innerMsg []byte
	for _, id := range persistentIDs {
		innerMsg = append(innerMsg, encodeStringField(1, []byte(id))...)
	}

	// Build extension message: field 1 (id=12), field 2 (bytes=data)
	var extMsg []byte
	extMsg = append(extMsg, encodeVarintField(1, 12)...)
	extMsg = append(extMsg, encodeStringField(2, innerMsg)...)

	// Build IqStanza
	var msg []byte
	msg = append(msg, encodeVarintField(2, 1)...)            // type = SET
	msg = append(msg, encodeStringField(3, []byte(iqID))...) // id
	msg = append(msg, encodeStringField(7, extMsg)...)       // extension
	return msg
}

// BuildIqResult builds an IqStanza response with type RESULT.
func BuildIqResult(iqID, to, from string) []byte {
	var msg []byte
	msg = append(msg, encodeVarintField(2, 2)...)            // type = RESULT
	msg = append(msg, encodeStringField(3, []byte(iqID))...) // id
	if from != "" {
		msg = append(msg, encodeStringField(4, []byte(from))...)
	}
	if to != "" {
		msg = append(msg, encodeStringField(5, []byte(to))...)
	}
	return msg
}

// AppData is a key-value pair from a DataMessageStanza.
type AppData struct {
	Key   string
	Value string
}

// DataMessage is a parsed DataMessageStanza.
type DataMessage struct {
	From         string
	Category     string
	AppDataList  []AppData
	PersistentID string
}

// ParseDataMessageStanza extracts fields from a DataMessageStanza protobuf.
//
// DataMessageStanza fields:
//
//	field 3 (string): from
//	field 5 (string): category
//	field 7 (repeated message): app_data — each has field 1 (key), field 2 (value)
//	field 9 (string): persistent_id
func ParseDataMessageStanza(data []byte) (*DataMessage, error) {
	fields, err := decodeProtoFields(data)
	if err != nil {
		return nil, err
	}

	msg := &DataMessage{
		From:         getStringField(fields, 3),
		Category:     getStringField(fields, 5),
		PersistentID: getStringField(fields, 9),
	}

	// Parse repeated app_data (field 7).
	for _, sub := range getRepeatedMessage(fields, 7) {
		kv := AppData{
			Key:   getStringField(sub, 1),
			Value: getStringField(sub, 2),
		}
		msg.AppDataList = append(msg.AppDataList, kv)
	}

	return msg, nil
}

// GetAppDataValue returns the value for a given key from a DataMessage.
func (d *DataMessage) GetAppDataValue(key string) string {
	for _, kv := range d.AppDataList {
		if kv.Key == key {
			return kv.Value
		}
	}
	return ""
}

// --- MCS wire format ---

// EncodeMCSMessage wraps a protobuf message with MCS wire framing:
// [1 byte: tag] [varint: length] [message bytes]
// On first message, prepend version byte.
func EncodeMCSMessage(tag byte, msg []byte, includeVersion bool) []byte {
	var buf []byte
	if includeVersion {
		buf = append(buf, mcsVersion)
	}
	buf = append(buf, tag)
	buf = append(buf, encodeVarint(uint64(len(msg)))...)
	buf = append(buf, msg...)
	return buf
}

// MCSReader reads MCS messages from a byte stream.
type MCSReader struct {
	buf         []byte
	versionRead bool
}

// NewMCSReader creates a new reader.
func NewMCSReader() *MCSReader {
	return &MCSReader{}
}

// Feed adds data to the reader's buffer.
func (r *MCSReader) Feed(data []byte) {
	r.buf = append(r.buf, data...)
}

// MCSMessage is a parsed MCS message (tag + body).
type MCSMessage struct {
	Tag  byte
	Body []byte
}

// Next tries to parse the next complete message from the buffer.
// Returns nil if not enough data yet.
func (r *MCSReader) Next() *MCSMessage {
	// Strip version byte from buffer on first read.
	if !r.versionRead {
		if len(r.buf) == 0 {
			return nil
		}
		r.buf = r.buf[1:] // consume version byte from buffer
		r.versionRead = true
	}

	if len(r.buf) < 2 {
		// Need at least tag + 1 byte of varint.
		return nil
	}

	// Read tag.
	tag := r.buf[0]

	// Read varint length.
	length, n := binary.Uvarint(r.buf[1:])
	if n <= 0 {
		return nil
	}

	headerLen := 1 + n // tag byte + varint bytes
	msgLen := int(length)

	if length > math.MaxInt32 {
		r.buf = r.buf[headerLen:]
		return nil
	}

	if headerLen+msgLen > len(r.buf) {
		// Not enough data for the full message body.
		return nil
	}

	body := make([]byte, msgLen)
	copy(body, r.buf[headerLen:headerLen+msgLen])
	r.buf = r.buf[headerLen+msgLen:]

	return &MCSMessage{Tag: tag, Body: body}
}
