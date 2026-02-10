import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

const String _hkdfSalt = 'push-tunnel-v1';
const int _keySize = 32;
const int _nonceSize = 12;

/// AES-256-GCM encryption matching the Go server implementation.
class TunnelCrypto {
  late final SecretKey _key;
  final AesGcm _algo = AesGcm.with256bits();

  TunnelCrypto._();

  /// Derive key from PSK using HKDF-SHA256 and initialise.
  static Future<TunnelCrypto> create(String psk) async {
    final c = TunnelCrypto._();
    final hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: _keySize);
    final ikm = SecretKey(utf8.encode(psk));
    final derived = await hkdf.deriveKey(
      secretKey: ikm,
      nonce: utf8.encode(_hkdfSalt),
      info: <int>[],
    );
    c._key = derived;
    return c;
  }

  /// Encrypt plaintext → base64(nonce[12] || ciphertext || tag[16]).
  Future<String> encrypt(Uint8List plaintext) async {
    final nonce = _randomBytes(_nonceSize);
    final secretBox = await _algo.encrypt(
      plaintext,
      secretKey: _key,
      nonce: nonce,
    );
    // secretBox.concatenation() returns nonce + ciphertext + mac
    final combined = secretBox.concatenation();
    return base64.encode(combined);
  }

  /// Decrypt base64-encoded ciphertext.
  Future<Uint8List> decrypt(String encoded) async {
    final data = base64.decode(encoded);
    if (data.length < _nonceSize + 16) {
      throw FormatException('Ciphertext too short');
    }
    final secretBox = SecretBox.fromConcatenation(
      data,
      nonceLength: _nonceSize,
      macLength: 16,
    );
    final plaintext = await _algo.decrypt(secretBox, secretKey: _key);
    return Uint8List.fromList(plaintext);
  }

  /// Compute HMAC-SHA256 auth token matching server's ComputeAuthToken.
  static Future<String> computeAuthToken(
      String deviceId, String timestamp, List<int> key) async {
    final hmac = Hmac(Sha256());
    final mac = await hmac.calculateMac(
      utf8.encode('$deviceId:$timestamp'),
      secretKey: SecretKey(key),
    );
    return base64.encode(mac.bytes);
  }

  /// Expose raw key bytes for auth token computation.
  Future<List<int>> get keyBytes async {
    return await _key.extractBytes();
  }

  static Uint8List _randomBytes(int n) {
    final rng = Random.secure();
    return Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
  }
}
