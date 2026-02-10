import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'crypto.dart';
import 'fcm_sender.dart';
import 'mcs_client.dart';
import 'mcs_proto.dart';
import 'protocol.dart';

const int _maxChunkDataSize = 3072;
const Duration _chunkTimeout = Duration(seconds: 30);

/// FCM transport orchestrator: send frames via FCM HTTP v1 API,
/// receive frames via MCS client, with chunking/reassembly.
class FCMTransport {
  final TunnelCrypto crypto;
  final FCMSender sender;
  final String peerToken;
  final void Function(Frame) onFrame;

  MCSClient? mcs;

  // Chunk reassembly state.
  final Map<String, _ChunkGroup> _chunkBuffer = {};
  Timer? _chunkCleaner;

  FCMTransport({
    required this.crypto,
    required this.sender,
    required this.peerToken,
    required this.onFrame,
  });

  /// Start the chunk cleaner.
  void startChunkCleaner() {
    _chunkCleaner = Timer.periodic(_chunkTimeout, (_) => _cleanStaleChunks());
  }

  /// Stop the transport.
  void stop() {
    _chunkCleaner?.cancel();
    mcs?.stop();
    sender.close();
  }

  /// Send a frame to the peer via FCM.
  Future<void> sendFrame(Frame frame) async {
    final raw = frame.encode();
    final encrypted = await crypto.encrypt(raw);
    final encBytes = utf8.encode(encrypted);

    if (encBytes.length <= _maxChunkDataSize) {
      await sender.sendData(peerToken, {
        'type': 'weather_alert',
        'd': encrypted,
      });
      return;
    }

    // Chunk the encrypted data.
    final mid = _randomMessageId();
    final chunks = _splitString(encrypted, _maxChunkDataSize);
    final ct = chunks.length.toString();

    for (int i = 0; i < chunks.length; i++) {
      await sender.sendData(peerToken, {
        'type': 'weather_alert',
        'mid': mid,
        'ci': i.toString(),
        'ct': ct,
        'd': chunks[i],
      });
    }
  }

  /// Handle an incoming MCS DataMessage.
  void handleMCSMessage(DataMessage dm) {
    print('[fcm-transport] received MCS message from=${dm.from} category=${dm.category} keys=${dm.appDataList.map((a) => a.key).toList()}');
    final data = <String, String>{};
    for (final kv in dm.appDataList) {
      data[kv.key] = kv.value;
    }

    final mid = data['mid'];
    if (mid != null && mid.isNotEmpty) {
      _handleChunked(data);
      return;
    }

    final encrypted = data['d'];
    if (encrypted == null || encrypted.isEmpty) return;

    _decryptAndDeliver(encrypted);
  }

  void _handleChunked(Map<String, String> data) {
    final mid = data['mid']!;
    final ci = int.tryParse(data['ci'] ?? '') ?? -1;
    final ct = int.tryParse(data['ct'] ?? '') ?? 0;
    final chunk = data['d'] ?? '';

    if (ct <= 0 || ci < 0 || ci >= ct || chunk.isEmpty) {
      print('[fcm-transport] invalid chunk: mid=$mid ci=$ci ct=$ct');
      return;
    }

    final group = _chunkBuffer.putIfAbsent(mid, () => _ChunkGroup(total: ct));
    group.chunks[ci] = chunk;

    if (group.chunks.length < group.total) return;

    // All chunks received — reassemble.
    _chunkBuffer.remove(mid);

    final indices = group.chunks.keys.toList()..sort();
    final assembled = StringBuffer();
    for (final i in indices) {
      assembled.write(group.chunks[i]!);
    }

    _decryptAndDeliver(assembled.toString());
  }

  Future<void> _decryptAndDeliver(String encrypted) async {
    try {
      final plaintext = await crypto.decrypt(encrypted);
      final frame = Frame.decode(plaintext);
      onFrame(frame);
    } catch (e) {
      print('[fcm-transport] decrypt/decode error: $e');
    }
  }

  void _cleanStaleChunks() {
    final now = DateTime.now();
    _chunkBuffer.removeWhere((mid, group) {
      if (now.difference(group.received) > _chunkTimeout) {
        print('[fcm-transport] dropping stale chunk group $mid '
            '(${group.chunks.length}/${group.total} received)');
        return true;
      }
      return false;
    });
  }

  static String _randomMessageId() {
    final rng = Random.secure();
    final bytes = List.generate(8, (_) => rng.nextInt(256));
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  static List<String> _splitString(String s, int chunkSize) {
    final chunks = <String>[];
    for (int i = 0; i < s.length; i += chunkSize) {
      final end = (i + chunkSize > s.length) ? s.length : i + chunkSize;
      chunks.add(s.substring(i, end));
    }
    return chunks;
  }
}

class _ChunkGroup {
  final int total;
  final Map<int, String> chunks = {};
  final DateTime received = DateTime.now();

  _ChunkGroup({required this.total});
}
