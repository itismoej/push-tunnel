import 'dart:typed_data';

/// Frame type constants.
class FrameType {
  static const int connect = 0x01;
  static const int data = 0x02;
  static const int disconnect = 0x03;
  static const int ack = 0x04;
}

const int frameHeaderSize = 5;
const int maxPayloadSize = 32 * 1024;

/// A protocol frame.
class Frame {
  final int type;
  final int channelId;
  final Uint8List payload;

  Frame({required this.type, required this.channelId, required this.payload});

  /// Encode this frame to bytes.
  Uint8List encode() {
    if (payload.length > maxPayloadSize) {
      throw ArgumentError('Payload too large: ${payload.length} > $maxPayloadSize');
    }
    final buf = ByteData(frameHeaderSize + payload.length);
    buf.setUint8(0, type);
    buf.setUint16(1, channelId, Endian.big);
    buf.setUint16(3, payload.length, Endian.big);
    final bytes = buf.buffer.asUint8List();
    bytes.setRange(frameHeaderSize, frameHeaderSize + payload.length, payload);
    return bytes;
  }

  /// Decode a single frame from bytes.
  static Frame decode(Uint8List data) {
    if (data.length < frameHeaderSize) {
      throw FormatException('Frame too short: ${data.length}');
    }
    final bd = ByteData.sublistView(data);
    final type = bd.getUint8(0);
    final channelId = bd.getUint16(1, Endian.big);
    final payloadLen = bd.getUint16(3, Endian.big);
    if (payloadLen > maxPayloadSize) {
      throw FormatException('Payload length $payloadLen exceeds max $maxPayloadSize');
    }
    if (data.length < frameHeaderSize + payloadLen) {
      throw FormatException(
          'Frame truncated: need ${frameHeaderSize + payloadLen}, got ${data.length}');
    }
    final payload = Uint8List.fromList(
        data.sublist(frameHeaderSize, frameHeaderSize + payloadLen));
    return Frame(type: type, channelId: channelId, payload: payload);
  }

  /// Decode multiple concatenated frames.
  static List<Frame> decodeAll(Uint8List data) {
    final frames = <Frame>[];
    var offset = 0;
    while (offset < data.length) {
      if (data.length - offset < frameHeaderSize) {
        throw FormatException('Trailing bytes too short for frame header');
      }
      final bd = ByteData.sublistView(data, offset);
      final payloadLen = bd.getUint16(3, Endian.big);
      final frameLen = frameHeaderSize + payloadLen;
      if (offset + frameLen > data.length) {
        throw FormatException('Frame extends past data boundary');
      }
      frames.add(Frame.decode(Uint8List.fromList(
          data.sublist(offset, offset + frameLen))));
      offset += frameLen;
    }
    return frames;
  }
}
