import 'dart:typed_data';

/// MCS protocol tags.
class MCSTag {
  static const int heartbeatPing = 0;
  static const int heartbeatAck = 1;
  static const int loginRequest = 2;
  static const int loginResponse = 3;
  static const int close = 4;
  static const int iqStanza = 7;
  static const int dataMessageStanza = 8;
}

/// MCS protocol version.
const int mcsVersion = 41;

// --- Protobuf helpers (hand-rolled, no codegen) ---

/// A parsed protobuf field.
class ProtoField {
  final int fieldNum;
  final int wireType; // 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit
  final int varint;
  final Uint8List data;

  ProtoField({
    required this.fieldNum,
    required this.wireType,
    this.varint = 0,
    Uint8List? data,
  }) : data = data ?? Uint8List(0);
}

/// Encode a varint.
Uint8List encodeVarint(int v) {
  final bytes = <int>[];
  var value = v;
  while (value > 0x7f) {
    bytes.add((value & 0x7f) | 0x80);
    value >>= 7;
  }
  bytes.add(value & 0x7f);
  return Uint8List.fromList(bytes);
}

/// Encode a protobuf tag.
Uint8List encodeTag(int fieldNum, int wireType) {
  return encodeVarint((fieldNum << 3) | wireType);
}

/// Encode a string/bytes protobuf field.
Uint8List encodeStringField(int fieldNum, Uint8List data) {
  final buf = BytesBuilder();
  buf.add(encodeTag(fieldNum, 2));
  buf.add(encodeVarint(data.length));
  buf.add(data);
  return buf.toBytes();
}

/// Encode a varint protobuf field.
Uint8List encodeVarintField(int fieldNum, int value) {
  final buf = BytesBuilder();
  buf.add(encodeTag(fieldNum, 0));
  buf.add(encodeVarint(value));
  return buf.toBytes();
}

/// Decode a varint from data at offset. Returns (value, bytesConsumed).
(int, int) decodeVarInt(Uint8List data, int offset) {
  int result = 0;
  int shift = 0;
  int i = offset;
  while (i < data.length) {
    final b = data[i];
    result |= (b & 0x7f) << shift;
    i++;
    if ((b & 0x80) == 0) {
      return (result, i - offset);
    }
    shift += 7;
    if (shift >= 64) break;
  }
  throw FormatException('Invalid varint');
}

/// Parse raw protobuf bytes into a list of fields.
List<ProtoField> decodeProtoFields(Uint8List data) {
  final fields = <ProtoField>[];
  int offset = 0;
  while (offset < data.length) {
    final (tagVal, tn) = decodeVarInt(data, offset);
    offset += tn;

    final fieldNum = tagVal >> 3;
    final wireType = tagVal & 0x07;

    switch (wireType) {
      case 0: // varint
        final (v, vn) = decodeVarInt(data, offset);
        offset += vn;
        fields.add(ProtoField(fieldNum: fieldNum, wireType: wireType, varint: v));
      case 1: // 64-bit
        if (offset + 8 > data.length) throw FormatException('Truncated 64-bit');
        fields.add(ProtoField(
          fieldNum: fieldNum,
          wireType: wireType,
          data: Uint8List.fromList(data.sublist(offset, offset + 8)),
        ));
        offset += 8;
      case 2: // length-delimited
        final (length, ln) = decodeVarInt(data, offset);
        offset += ln;
        if (offset + length > data.length) {
          throw FormatException('Length-delimited overflows');
        }
        fields.add(ProtoField(
          fieldNum: fieldNum,
          wireType: wireType,
          data: Uint8List.fromList(data.sublist(offset, offset + length)),
        ));
        offset += length;
      case 5: // 32-bit
        if (offset + 4 > data.length) throw FormatException('Truncated 32-bit');
        fields.add(ProtoField(
          fieldNum: fieldNum,
          wireType: wireType,
          data: Uint8List.fromList(data.sublist(offset, offset + 4)),
        ));
        offset += 4;
      default:
        throw FormatException('Unsupported wire type $wireType');
    }
  }
  return fields;
}

/// Get the first string field with the given number.
String getStringField(List<ProtoField> fields, int num) {
  for (final f in fields) {
    if (f.fieldNum == num && f.wireType == 2) {
      return String.fromCharCodes(f.data);
    }
  }
  return '';
}

/// Get the first varint field with the given number.
int? getVarintField(List<ProtoField> fields, int num) {
  for (final f in fields) {
    if (f.fieldNum == num && f.wireType == 0) {
      return f.varint;
    }
  }
  return null;
}

/// Get all repeated sub-messages for a field number.
List<List<ProtoField>> getRepeatedMessage(List<ProtoField> fields, int num) {
  final result = <List<ProtoField>>[];
  for (final f in fields) {
    if (f.fieldNum == num && f.wireType == 2) {
      try {
        result.add(decodeProtoFields(f.data));
      } catch (_) {}
    }
  }
  return result;
}

// --- MCS Messages ---

/// Build a serialised LoginRequest protobuf.
///
/// Field numbers (from Android MCS proto):
///   1: id, 2: domain, 3: user, 4: resource, 5: auth_token,
///   6: device_id, 8: setting (repeated), 14: use_rmq2,
///   16: auth_service, 17: network_type
Uint8List buildLoginRequest(int androidId, int securityToken) {
  final hexId = androidId.toRadixString(16);
  final clientId = 'chrome-63.0.3234.0';
  final deviceId = 'android-$hexId';
  final aidStr = androidId.toString();
  final tokenStr = securityToken.toString();

  // Build Setting sub-message: name="new_vc", value="1"
  final settingBuf = BytesBuilder();
  settingBuf.add(encodeStringField(1, Uint8List.fromList('new_vc'.codeUnits)));
  settingBuf.add(encodeStringField(2, Uint8List.fromList('1'.codeUnits)));

  final buf = BytesBuilder();
  buf.add(encodeStringField(1, Uint8List.fromList(clientId.codeUnits)));   // id
  buf.add(encodeStringField(2, Uint8List.fromList('mcs.android.com'.codeUnits))); // domain
  buf.add(encodeStringField(3, Uint8List.fromList(aidStr.codeUnits)));    // user
  buf.add(encodeStringField(4, Uint8List.fromList(aidStr.codeUnits)));    // resource
  buf.add(encodeStringField(5, Uint8List.fromList(tokenStr.codeUnits))); // auth_token
  buf.add(encodeStringField(6, Uint8List.fromList(deviceId.codeUnits)));  // device_id
  buf.add(encodeStringField(8, settingBuf.toBytes()));                    // setting: new_vc=1
  buf.add(encodeVarintField(14, 1));  // use_rmq2 = true
  buf.add(encodeVarintField(16, 2));  // auth_service = ANDROID_ID
  buf.add(encodeVarintField(17, 1));  // network_type = WiFi
  return buf.toBytes();
}

/// Build a HeartbeatPing with stream ID tracking.
Uint8List buildHeartbeatPing(int streamId, int lastStreamIdReceived) {
  final buf = BytesBuilder();
  if (streamId > 0) {
    buf.add(encodeVarintField(1, streamId));
  }
  if (lastStreamIdReceived > 0) {
    buf.add(encodeVarintField(2, lastStreamIdReceived));
  }
  buf.add(encodeVarintField(3, 0)); // status = 0
  return buf.toBytes();
}

/// Build a HeartbeatAck with stream ID tracking.
Uint8List buildHeartbeatAck(int lastStreamIdReceived) {
  final buf = BytesBuilder();
  if (lastStreamIdReceived > 0) {
    buf.add(encodeVarintField(2, lastStreamIdReceived));
  }
  buf.add(encodeVarintField(3, 0)); // status = 0
  return buf.toBytes();
}

/// Build a SelectiveAck IqStanza.
Uint8List buildSelectiveAck(List<String> persistentIds, {String iqId = '0'}) {
  if (iqId.isEmpty) {
    iqId = '0';
  }

  // Inner SelectiveAck: field 1 (repeated string): id
  final innerBuf = BytesBuilder();
  for (final id in persistentIds) {
    innerBuf.add(encodeStringField(1, Uint8List.fromList(id.codeUnits)));
  }

  // Extension: field 1=id (12), field 2=data (SelectiveAck bytes)
  final extBuf = BytesBuilder();
  extBuf.add(encodeVarintField(1, 12));
  extBuf.add(encodeStringField(2, innerBuf.toBytes()));

  // IqStanza
  final buf = BytesBuilder();
  buf.add(encodeVarintField(2, 1)); // type = SET
  buf.add(encodeStringField(3, Uint8List.fromList(iqId.codeUnits))); // id
  buf.add(encodeStringField(7, extBuf.toBytes())); // extension
  return buf.toBytes();
}

/// Build an IqStanza RESULT response.
Uint8List buildIqResult(String iqId, {String to = '', String from = ''}) {
  final buf = BytesBuilder();
  buf.add(encodeVarintField(2, 2)); // type = RESULT
  buf.add(encodeStringField(3, Uint8List.fromList(iqId.codeUnits))); // id
  if (from.isNotEmpty) {
    buf.add(encodeStringField(4, Uint8List.fromList(from.codeUnits)));
  }
  if (to.isNotEmpty) {
    buf.add(encodeStringField(5, Uint8List.fromList(to.codeUnits)));
  }
  return buf.toBytes();
}

/// A key-value pair from a DataMessageStanza.
class AppData {
  final String key;
  final String value;
  AppData({required this.key, required this.value});
}

/// A parsed DataMessageStanza.
class DataMessage {
  final String from;
  final String category;
  final List<AppData> appDataList;
  final String persistentId;

  DataMessage({
    required this.from,
    required this.category,
    required this.appDataList,
    required this.persistentId,
  });

  String getAppDataValue(String key) {
    for (final kv in appDataList) {
      if (kv.key == key) return kv.value;
    }
    return '';
  }
}

/// Parse a DataMessageStanza protobuf.
DataMessage parseDataMessageStanza(Uint8List data) {
  final fields = decodeProtoFields(data);

  final appData = <AppData>[];
  for (final sub in getRepeatedMessage(fields, 7)) {
    appData.add(AppData(
      key: getStringField(sub, 1),
      value: getStringField(sub, 2),
    ));
  }

  return DataMessage(
    from: getStringField(fields, 3),
    category: getStringField(fields, 5),
    appDataList: appData,
    persistentId: getStringField(fields, 9),
  );
}

// --- MCS wire format ---

/// Encode an MCS message with wire framing.
/// [tag] [varint length] [message bytes]
/// If [includeVersion], prepend version byte (first message only).
Uint8List encodeMCSMessage(int tag, Uint8List msg, {bool includeVersion = false}) {
  final buf = BytesBuilder();
  if (includeVersion) {
    buf.addByte(mcsVersion);
  }
  buf.addByte(tag);
  buf.add(encodeVarint(msg.length));
  buf.add(msg);
  return buf.toBytes();
}

/// A parsed MCS message (tag + body).
class MCSMessage {
  final int tag;
  final Uint8List body;
  MCSMessage({required this.tag, required this.body});
}

/// Reads MCS messages from a byte stream.
class MCSReader {
  final BytesBuilder _buf = BytesBuilder();
  bool _versionRead = false;

  /// Feed data into the reader's buffer.
  void feed(Uint8List data) {
    _buf.add(data);
  }

  /// Try to parse the next complete message. Returns null if not enough data.
  MCSMessage? next() {
    var data = _buf.toBytes();
    if (data.isEmpty) return null;

    // Strip version byte from buffer on first read.
    if (!_versionRead) {
      _buf.clear();
      if (data.length > 1) {
        _buf.add(data.sublist(1));
      }
      _versionRead = true;
      data = _buf.toBytes();
      if (data.isEmpty) return null;
    }

    if (data.length < 2) return null; // need tag + varint

    // Read tag.
    final tag = data[0];

    // Read varint length.
    int length;
    int n;
    try {
      final result = decodeVarInt(Uint8List.sublistView(data, 1), 0);
      length = result.$1;
      n = result.$2;
    } catch (_) {
      return null;
    }

    final headerLen = 1 + n; // tag + varint
    if (headerLen + length > data.length) return null;

    final body = Uint8List.fromList(data.sublist(headerLen, headerLen + length));

    // Consume processed bytes.
    _buf.clear();
    if (headerLen + length < data.length) {
      _buf.add(data.sublist(headerLen + length));
    }

    return MCSMessage(tag: tag, body: body);
  }
}
