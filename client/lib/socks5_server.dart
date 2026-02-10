import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'tunnel_client.dart';

/// Minimal SOCKS5 proxy server (RFC 1928) that feeds connections into the tunnel.
class Socks5Server {
  final int port;
  final TunnelClient tunnel;
  ServerSocket? _server;

  Socks5Server({required this.port, required this.tunnel});

  Future<void> start() async {
    _server = await ServerSocket.bind(InternetAddress.loopbackIPv4, port);
    print('[socks5] listening on 127.0.0.1:$port');
    _server!.listen(_handleClient);
  }

  void _handleClient(Socket client) {
    _Socks5Connection(client, tunnel).handle();
  }

  Future<void> stop() async {
    await _server?.close();
  }
}

/// Handles a single SOCKS5 client connection.
/// Uses a single socket subscription throughout, switching behavior
/// from handshake buffering to data relay via a callback variable.
class _Socks5Connection {
  final Socket _socket;
  final TunnelClient _tunnel;
  final BytesBuilder _buf = BytesBuilder(copy: false);
  final _dataReady = StreamController<void>.broadcast();
  StreamSubscription<Uint8List>? _sub;
  int? _channelId;
  bool _closed = false;

  // Called by the socket listener with incoming data.
  // During handshake: buffers bytes. After handshake: forwards to tunnel.
  late void Function(List<int> data) _onData;
  late void Function() _onDone;

  _Socks5Connection(this._socket, this._tunnel);

  void handle() async {
    // Prevent unhandled socket.done errors (e.g. broken pipe on closed peer).
    _socket.done.catchError((_) {});

    // Initial mode: buffer for handshake.
    _onData = (data) {
      if (_closed) return;
      _buf.add(data);
      if (!_dataReady.isClosed) {
        _dataReady.add(null);
      }
    };
    _onDone = () {
      if (_closed) return;
      _closed = true;
      final channelId = _channelId;
      _channelId = null;
      if (channelId != null) {
        _tunnel.closeChannel(channelId);
      }
      if (!_dataReady.isClosed) {
        _dataReady.close();
      }
    };

    _sub = _socket.listen(
      (data) => _onData(data),
      onDone: () => _onDone(),
      onError: (e) => _onDone(),
    );

    try {
      await _doHandshake();
    } catch (e) {
      print('[socks5] error: $e');
      _safeDestroy();
    }
  }

  Future<void> _doHandshake() async {
    // Read greeting: version + nmethods.
    var data = await _readExact(2);
    if (data == null) return;

    if (data[0] != 0x05) {
      _safeDestroy();
      return;
    }

    final nMethods = data[1];
    data = await _readExact(nMethods);
    if (data == null) return;

    // Reply: no auth required.
    if (!_safeWrite([0x05, 0x00])) return;

    // Read connect request header: ver, cmd, rsv, atyp.
    data = await _readExact(4);
    if (data == null) return;

    if (data[0] != 0x05 || data[1] != 0x01) {
      _safeWrite([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
      _safeDestroy();
      return;
    }

    String host;
    final addrType = data[3];

    if (addrType == 0x01) {
      final addr = await _readExact(4);
      if (addr == null) return;
      host = '${addr[0]}.${addr[1]}.${addr[2]}.${addr[3]}';
    } else if (addrType == 0x03) {
      final lenBuf = await _readExact(1);
      if (lenBuf == null) return;
      final domainBytes = await _readExact(lenBuf[0]);
      if (domainBytes == null) return;
      host = String.fromCharCodes(domainBytes);
    } else if (addrType == 0x04) {
      final addr = await _readExact(16);
      if (addr == null) return;
      final parts = <String>[];
      for (var i = 0; i < 16; i += 2) {
        parts.add(((addr[i] << 8) | addr[i + 1]).toRadixString(16));
      }
      host = '[${parts.join(':')}]';
    } else {
      _safeWrite([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
      _safeDestroy();
      return;
    }

    final portBuf = await _readExact(2);
    if (portBuf == null) return;
    final port = (portBuf[0] << 8) | portBuf[1];

    final target = '$host:$port';
    print('[socks5] CONNECT $target');

    final channelId = await _tunnel.openChannel(target);
    if (channelId == null) {
      _safeWrite([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
      _safeDestroy();
      return;
    }
    _channelId = channelId;

    // Success reply.
    if (!_safeWrite([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])) {
      _safeDestroy();
      return;
    }

    // Switch the socket listener to relay mode — no cancel/re-listen needed.
    _onData = (data) {
      _tunnel.sendData(channelId, Uint8List.fromList(data));
    };
    _onDone = () {
      if (_closed) return;
      _closed = true;
      if (_channelId != null) {
        _tunnel.closeChannel(_channelId!);
        _channelId = null;
      }
      if (!_dataReady.isClosed) {
        _dataReady.close();
      }
    };

    // Deliver any leftover buffered bytes from the handshake.
    final leftover = _buf.takeBytes();
    if (leftover.isNotEmpty) {
      _tunnel.sendData(channelId, Uint8List.fromList(leftover));
    }

    // Tunnel → client (downstream).
    _tunnel.registerChannelCallback(channelId, (Uint8List data) {
      if (!_safeWrite(data)) {
        if (_channelId != null) {
          _tunnel.closeChannel(_channelId!);
          _channelId = null;
        }
        _safeDestroy();
      }
    }, () {
      // Channel closed by remote.
      _channelId = null;
      _safeDestroy();
    });
  }

  /// Read exactly [count] bytes from the buffer, waiting for more data as needed.
  Future<Uint8List?> _readExact(int count) async {
    while (_buf.length < count) {
      try {
        await _dataReady.stream.first.timeout(const Duration(seconds: 30));
      } catch (_) {
        return null;
      }
    }
    final all = _buf.takeBytes();
    final result = Uint8List.fromList(all.sublist(0, count));
    if (all.length > count) {
      _buf.add(all.sublist(count));
    }
    return result;
  }

  bool _safeWrite(List<int> data) {
    if (_closed) return false;
    try {
      _socket.add(data);
      return true;
    } catch (e) {
      print('[socks5] socket write failed: $e');
      _safeDestroy();
      return false;
    }
  }

  void _safeDestroy() {
    if (_closed) return;
    try {
      _socket.destroy();
    } catch (_) {}
    try {
      _sub?.cancel();
    } catch (_) {}
    _onDone();
  }
}
