import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'mcs_proto.dart';

const String _mtalkHost = 'mtalk.google.com';
const int _mtalkPort = 5228;
const Duration _heartbeatInterval = Duration(minutes: 4);
const Duration _reconnectDelay = Duration(seconds: 5);

/// MCS client that maintains a persistent TLS connection to mtalk.google.com
/// for receiving FCM push messages.
class MCSClient {
  final int androidId;
  final int securityToken;
  final void Function(DataMessage) onMessage;

  SecureSocket? _socket;
  bool _running = false;
  final List<String> _ackIds = [];
  Timer? _heartbeatTimer;

  // Stream ID tracking.
  int _outStreamId = 0;
  int _lastStreamIdReceived = 0;

  MCSClient({
    required this.androidId,
    required this.securityToken,
    required this.onMessage,
  });

  /// Start the MCS connection loop.
  Future<void> start() async {
    _running = true;
    _connectLoop();
  }

  /// Stop the MCS client.
  void stop() {
    _running = false;
    _heartbeatTimer?.cancel();
    _socket?.destroy();
    _socket = null;
  }

  Future<void> _connectLoop() async {
    while (_running) {
      try {
        await _runSession();
      } catch (e) {
        print('[mcs] session error: $e');
      }
      if (!_running) return;
      print('[mcs] reconnecting in ${_reconnectDelay.inSeconds}s...');
      await Future.delayed(_reconnectDelay);
    }
  }

  Future<void> _runSession() async {
    final socket = await SecureSocket.connect(_mtalkHost, _mtalkPort);
    _socket = socket;

    // Reset stream counters.
    _outStreamId = 0;
    _lastStreamIdReceived = 0;

    print('[mcs] connected to $_mtalkHost:$_mtalkPort');

    // Send LoginRequest (counts as outgoing message #1).
    final loginMsg = buildLoginRequest(androidId, securityToken);
    final loginFrame =
        encodeMCSMessage(MCSTag.loginRequest, loginMsg, includeVersion: true);
    socket.add(loginFrame);
    _outStreamId++;

    // Start heartbeat timer.
    _heartbeatTimer?.cancel();
    _heartbeatTimer = Timer.periodic(_heartbeatInterval, (_) {
      _sendHeartbeat();
      _flushAcks();
    });

    // Read loop.
    final reader = MCSReader();
    final completer = Completer<void>();

    socket.listen(
      (data) {
        reader.feed(Uint8List.fromList(data));
        _processMessages(reader);
      },
      onDone: () {
        print('[mcs] connection closed');
        if (!completer.isCompleted) completer.complete();
      },
      onError: (e) {
        print('[mcs] connection error: $e');
        if (!completer.isCompleted) completer.complete();
      },
    );

    await completer.future;
    _heartbeatTimer?.cancel();
    _socket = null;
  }

  void _processMessages(MCSReader reader) {
    while (true) {
      final msg = reader.next();
      if (msg == null) return;

      // Every message from server increments our received counter.
      _lastStreamIdReceived++;

      switch (msg.tag) {
        case MCSTag.loginResponse:
          print(
              '[mcs] login successful (server stream=$_lastStreamIdReceived)');
          // Immediately acknowledge login with a heartbeat.
          _sendHeartbeat();
          break;

        case MCSTag.heartbeatPing:
          print('[mcs] received HeartbeatPing');
          final ack = encodeMCSMessage(
            MCSTag.heartbeatAck,
            buildHeartbeatAck(_lastStreamIdReceived),
          );
          _socket?.add(ack);
          break;

        case MCSTag.heartbeatAck:
          print('[mcs] received HeartbeatAck');
          break;

        case MCSTag.close:
          print('[mcs] server sent Close');
          break;

        case MCSTag.iqStanza:
          try {
            final fields = decodeProtoFields(msg.body);
            final iqType = getVarintField(fields, 2);
            final iqId = getStringField(fields, 3);
            final iqFrom = getStringField(fields, 4);
            final iqTo = getStringField(fields, 5);

            int? extId;
            final extensions = getRepeatedMessage(fields, 7);
            if (extensions.isNotEmpty) {
              extId = getVarintField(extensions.first, 1);
            }

            if (extId != null) {
              print(
                  '[mcs] received IqStanza type=$iqType id=$iqId ext=$extId len=${msg.body.length}');
            } else {
              print(
                  '[mcs] received IqStanza type=$iqType id=$iqId len=${msg.body.length}');
            }

            // Server IQ GET/SET stanzas expect a RESULT response with matching id.
            if (iqType != null && (iqType == 0 || iqType == 1)) {
              final result = encodeMCSMessage(
                MCSTag.iqStanza,
                buildIqResult(iqId, to: iqFrom, from: iqTo),
              );
              _socket?.add(result);
              _outStreamId++;
            }
          } catch (e) {
            print('[mcs] parse IqStanza error: $e');
          }
          break;

        case MCSTag.dataMessageStanza:
          print('[mcs] received DataMessageStanza, len=${msg.body.length}');
          try {
            final dm = parseDataMessageStanza(msg.body);
            if (dm.persistentId.isNotEmpty) {
              _ackIds.add(dm.persistentId);
              // Ack promptly to reduce duplicate deliveries.
              _flushAcks();
            }
            onMessage(dm);
          } catch (e) {
            print('[mcs] parse data message error: $e');
          }
          break;

        default:
          print('[mcs] unknown tag ${msg.tag}, len=${msg.body.length}');
          break;
      }
    }
  }

  void _sendHeartbeat() {
    print(
        '[mcs] sending HeartbeatPing (out=$_outStreamId, lastRecv=$_lastStreamIdReceived)');
    final ping = encodeMCSMessage(
      MCSTag.heartbeatPing,
      buildHeartbeatPing(_outStreamId, _lastStreamIdReceived),
    );
    try {
      _socket?.add(ping);
      _outStreamId++;
    } catch (e) {
      print('[mcs] heartbeat send error: $e');
    }
  }

  void _flushAcks() {
    if (_ackIds.isEmpty) return;
    final ids = List<String>.from(_ackIds);
    _ackIds.clear();

    final iqId = 'ack-${_outStreamId + 1}';
    final ack =
        encodeMCSMessage(MCSTag.iqStanza, buildSelectiveAck(ids, iqId: iqId));
    try {
      _socket?.add(ack);
      _outStreamId++;
    } catch (e) {
      print('[mcs] ack send error: $e');
    }
  }
}
