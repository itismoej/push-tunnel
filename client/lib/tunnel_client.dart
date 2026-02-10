import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'config.dart';
import 'crypto.dart';
import 'fcm_sender.dart';
import 'fcm_transport.dart';
import 'gcm_register.dart';
import 'mcs_client.dart';
import 'protocol.dart';

typedef DataCallback = void Function(Uint8List data);
typedef CloseCallback = void Function();

/// Per-channel state on the client side.
class _ChannelState {
  DataCallback? onData;
  CloseCallback? onClose;
  final Queue<Uint8List> pendingData = Queue();
  bool connected = false;
  Completer<bool>? connectCompleter;
}

/// Orchestrates the tunnel: manages channels, sends frames via FCM,
/// receives frames via MCS.
class TunnelClient {
  final Config config;
  final TunnelCrypto crypto;

  late FCMTransport _transport;
  late MCSClient _mcs;
  late GCMCredentials _creds;

  final Map<int, _ChannelState> _channels = {};
  int _nextChannelId = 1;

  /// Frames waiting to be sent, flushed periodically.
  final Queue<Frame> _sendQueue = Queue();
  Timer? _batchTimer;

  TunnelClient({required this.config, required this.crypto});

  /// Start the tunnel client: register with GCM, start MCS, begin sending.
  Future<void> start() async {
    // Register with GCM to get our FCM token.
    _creds = await registerGCM(config.senderId);

    print('');
    print('=== FCM Token (copy to peer\'s config as peer_fcm_token) ===');
    print(_creds.fcmToken);
    print('============================================================');
    print('');

    // Create FCM sender.
    final sender = await FCMSender.create(
      config.firebaseCredentials,
      config.firebaseProject,
    );

    // Create FCM transport.
    _transport = FCMTransport(
      crypto: crypto,
      sender: sender,
      peerToken: config.peerFcmToken,
      onFrame: _handleDownstreamFrame,
    );

    // Start MCS client for receiving.
    _mcs = MCSClient(
      androidId: _creds.androidId,
      securityToken: _creds.securityToken,
      onMessage: (dm) => _transport.handleMCSMessage(dm),
    );
    _transport.mcs = _mcs;
    await _mcs.start();

    _transport.startChunkCleaner();

    // Start periodic sender.
    _batchTimer = Timer.periodic(const Duration(milliseconds: 100), (_) {
      _flushSendQueue();
    });

    print('[tunnel] client started (FCM mode)');
  }

  /// Open a new channel to the given target (host:port).
  Future<int?> openChannel(String target) async {
    final channelId = _nextChannelId++;
    if (_nextChannelId > 65535) _nextChannelId = 1;

    final state = _ChannelState();
    state.connectCompleter = Completer<bool>();
    _channels[channelId] = state;

    // Send CONNECT frame.
    _enqueueFrame(Frame(
      type: FrameType.connect,
      channelId: channelId,
      payload: Uint8List.fromList(target.codeUnits),
    ));

    // Flush immediately for CONNECT.
    await _flushSendQueue();

    // Wait for ACK or DISCONNECT.
    try {
      final success = await state.connectCompleter!.future
          .timeout(const Duration(seconds: 15));
      if (!success) {
        _channels.remove(channelId);
        return null;
      }
      state.connected = true;
      return channelId;
    } catch (_) {
      _channels.remove(channelId);
      return null;
    }
  }

  /// Send data on a channel.
  void sendData(int channelId, Uint8List data) {
    _enqueueFrame(Frame(
      type: FrameType.data,
      channelId: channelId,
      payload: data,
    ));
  }

  /// Close a channel.
  void closeChannel(int channelId) {
    _enqueueFrame(Frame(
      type: FrameType.disconnect,
      channelId: channelId,
      payload: Uint8List(0),
    ));
    _cleanupChannel(channelId);
  }

  /// Register callbacks for downstream data on a channel.
  void registerChannelCallback(
      int channelId, DataCallback onData, CloseCallback onClose) {
    final state = _channels[channelId];
    if (state == null) return;
    state.onData = onData;
    state.onClose = onClose;

    // Deliver any data that arrived before callback was registered.
    while (state.pendingData.isNotEmpty) {
      onData(state.pendingData.removeFirst());
    }
  }

  void _handleDownstreamFrame(Frame frame) {
    print('[tunnel] received frame type=${frame.type} ch=${frame.channelId} len=${frame.payload.length}');
    switch (frame.type) {
      case FrameType.ack:
        final state = _channels[frame.channelId];
        if (state?.connectCompleter != null &&
            !state!.connectCompleter!.isCompleted) {
          state.connectCompleter!.complete(true);
        }
        break;

      case FrameType.data:
        final state = _channels[frame.channelId];
        if (state == null) return;
        if (state.onData != null) {
          state.onData!(frame.payload);
        } else {
          state.pendingData.add(frame.payload);
        }
        break;

      case FrameType.disconnect:
        final state = _channels[frame.channelId];
        if (state != null) {
          if (state.connectCompleter != null &&
              !state.connectCompleter!.isCompleted) {
            state.connectCompleter!.complete(false);
          }
          state.onClose?.call();
          _cleanupChannel(frame.channelId);
        }
        break;
    }
  }

  void _enqueueFrame(Frame frame) {
    _sendQueue.add(frame);
  }

  Future<void> _flushSendQueue() async {
    if (_sendQueue.isEmpty) return;

    while (_sendQueue.isNotEmpty) {
      final frame = _sendQueue.removeFirst();
      try {
        print('[tunnel] sending frame type=${frame.type} ch=${frame.channelId} len=${frame.payload.length}');
        await _transport.sendFrame(frame);
        print('[tunnel] frame sent ok');
      } catch (e) {
        print('[tunnel] FCM send error: $e, re-queuing frame');
        _sendQueue.addFirst(frame);
        return;
      }
    }
  }

  void _cleanupChannel(int channelId) {
    _channels.remove(channelId);
  }

  void stop() {
    _batchTimer?.cancel();
    _transport.stop();
    for (final id in _channels.keys.toList()) {
      _cleanupChannel(id);
    }
    print('[tunnel] client stopped');
  }
}
