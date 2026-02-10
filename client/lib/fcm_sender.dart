import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

/// FCM HTTP v1 API sender with OAuth2 service account authentication.
class FCMSender {
  final String project;
  final Map<String, dynamic> _serviceAccount;
  final http.Client _client = http.Client();

  String? _accessToken;
  DateTime? _tokenExpiry;

  FCMSender._({required this.project, required Map<String, dynamic> serviceAccount})
      : _serviceAccount = serviceAccount;

  /// Create an FCM sender from a service account key file.
  static Future<FCMSender> create(String credFile, String project) async {
    final data = json.decode(await File(credFile).readAsString()) as Map<String, dynamic>;
    return FCMSender._(project: project, serviceAccount: data);
  }

  /// Send an FCM data message to the given token.
  Future<void> sendData(String fcmToken, Map<String, String> data) async {
    final token = await _getAccessToken();
    final url = 'https://fcm.googleapis.com/v1/projects/$project/messages:send';

    final payload = json.encode({
      'message': {
        'token': fcmToken,
        'data': data,
      },
    });

    final resp = await _client.post(
      Uri.parse(url),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer $token',
      },
      body: payload,
    );

    if (resp.statusCode != 200) {
      throw Exception('FCM send failed (${resp.statusCode}): ${resp.body}');
    }
  }

  /// Get a valid OAuth2 access token, refreshing if needed.
  Future<String> _getAccessToken() async {
    if (_accessToken != null &&
        _tokenExpiry != null &&
        DateTime.now().isBefore(_tokenExpiry!.subtract(const Duration(minutes: 1)))) {
      return _accessToken!;
    }

    // Generate JWT and exchange for access token.
    final now = DateTime.now().toUtc();
    final exp = now.add(const Duration(hours: 1));

    final header = base64Url.encode(utf8.encode(json.encode({
      'alg': 'RS256',
      'typ': 'JWT',
    }))).replaceAll('=', '');

    final claims = base64Url.encode(utf8.encode(json.encode({
      'iss': _serviceAccount['client_email'],
      'scope': 'https://www.googleapis.com/auth/firebase.messaging',
      'aud': 'https://oauth2.googleapis.com/token',
      'iat': now.millisecondsSinceEpoch ~/ 1000,
      'exp': exp.millisecondsSinceEpoch ~/ 1000,
    }))).replaceAll('=', '');

    final signingInput = '$header.$claims';
    final signature = _signRS256(signingInput, _serviceAccount['private_key'] as String);
    final jwt = '$signingInput.$signature';

    // Exchange JWT for access token.
    final resp = await _client.post(
      Uri.parse('https://oauth2.googleapis.com/token'),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=$jwt',
    );

    if (resp.statusCode != 200) {
      throw Exception('OAuth2 token exchange failed (${resp.statusCode}): ${resp.body}');
    }

    final tokenData = json.decode(resp.body) as Map<String, dynamic>;
    _accessToken = tokenData['access_token'] as String;
    final expiresIn = tokenData['expires_in'] as int;
    _tokenExpiry = DateTime.now().add(Duration(seconds: expiresIn));

    return _accessToken!;
  }

  /// Sign data with RS256 using the service account private key.
  String _signRS256(String data, String privateKeyPem) {
    // Parse PEM to DER.
    final lines = privateKeyPem
        .split('\n')
        .where((l) => !l.startsWith('-----') && l.trim().isNotEmpty)
        .join();
    final keyBytes = base64.decode(lines);

    // Parse PKCS#8 to get the RSA private key.
    final rsaKey = _parsePKCS8(keyBytes);

    // Sign with RSASSA-PKCS1-v1_5 SHA-256.
    final dataBytes = utf8.encode(data);
    final digest = _sha256(dataBytes);

    // DER-encoded DigestInfo for SHA-256.
    final digestInfo = <int>[
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
      ...digest,
    ];

    final signature = _rsaSign(rsaKey, digestInfo);
    return base64Url.encode(signature).replaceAll('=', '');
  }

  /// SHA-256 hash.
  List<int> _sha256(List<int> data) {
    // Use Dart's built-in crypto from dart:io (backed by BoringSSL).
    final hash = _SHA256();
    hash.update(data);
    return hash.digest();
  }

  void close() {
    _client.close();
  }
}

// --- Minimal RSA implementation for JWT signing ---

class _RSAKey {
  final BigInt n; // modulus
  final BigInt d; // private exponent

  _RSAKey(this.n, this.d);
}

_RSAKey _parsePKCS8(List<int> der) {
  // PKCS#8 wraps the RSA key. We need to unwrap it.
  // Structure: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { RSAPrivateKey } }
  final seq = _parseASN1(der, 0);
  final contents = seq.contents as List<_ASN1Node>;

  // The third element is an OCTET STRING containing the RSAPrivateKey.
  final octetString = contents[2];
  final rsaKeyBytes = octetString.rawBytes;

  // Parse RSAPrivateKey: SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
  final rsaSeq = _parseASN1(rsaKeyBytes, 0);
  final rsaFields = rsaSeq.contents as List<_ASN1Node>;

  final n = _bigIntFromASN1(rsaFields[1]);
  final d = _bigIntFromASN1(rsaFields[3]);

  return _RSAKey(n, d);
}

List<int> _rsaSign(_RSAKey key, List<int> digestInfo) {
  final k = (key.n.bitLength + 7) ~/ 8;

  // PKCS#1 v1.5 padding: 0x00 0x01 [0xff...] 0x00 [digestInfo]
  final padLen = k - digestInfo.length - 3;
  if (padLen < 8) throw Exception('Key too short for signature');

  final em = <int>[0x00, 0x01, ...List.filled(padLen, 0xff), 0x00, ...digestInfo];

  // Convert to BigInt, do modular exponentiation, convert back.
  final m = _bigIntFromBytes(em);
  final s = m.modPow(key.d, key.n);
  return _bigIntToBytes(s, k);
}

BigInt _bigIntFromASN1(_ASN1Node node) {
  return _bigIntFromBytes(node.rawBytes);
}

BigInt _bigIntFromBytes(List<int> bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

List<int> _bigIntToBytes(BigInt value, int length) {
  final result = List<int>.filled(length, 0);
  var v = value;
  for (int i = length - 1; i >= 0; i--) {
    result[i] = (v & BigInt.from(0xff)).toInt();
    v >>= 8;
  }
  return result;
}

// --- Minimal ASN.1 DER parser ---

class _ASN1Node {
  final int tag;
  final List<int> rawBytes;
  final Object? contents; // List<_ASN1Node> for sequences, raw bytes for others

  _ASN1Node(this.tag, this.rawBytes, this.contents);
}

_ASN1Node _parseASN1(List<int> data, int offset) {
  final tag = data[offset];
  offset++;

  // Parse length.
  int length;
  if (data[offset] & 0x80 == 0) {
    length = data[offset];
    offset++;
  } else {
    final numBytes = data[offset] & 0x7f;
    offset++;
    length = 0;
    for (int i = 0; i < numBytes; i++) {
      length = (length << 8) | data[offset];
      offset++;
    }
  }

  final rawBytes = data.sublist(offset, offset + length);

  // If it's a SEQUENCE (0x30), parse children.
  Object? contents;
  if (tag == 0x30) {
    final children = <_ASN1Node>[];
    int childOffset = 0;
    while (childOffset < rawBytes.length) {
      final child = _parseASN1(rawBytes, childOffset);
      children.add(child);
      // Calculate consumed bytes.
      childOffset += _asn1TotalLength(rawBytes, childOffset);
    }
    contents = children;
  }

  return _ASN1Node(tag, rawBytes, contents);
}

int _asn1TotalLength(List<int> data, int offset) {
  offset++; // skip tag
  if (data[offset] & 0x80 == 0) {
    return 2 + data[offset];
  }
  final numBytes = data[offset] & 0x7f;
  offset++;
  int length = 0;
  for (int i = 0; i < numBytes; i++) {
    length = (length << 8) | data[offset + i];
  }
  return 2 + numBytes + length;
}

// --- SHA-256 implementation ---

class _SHA256 {
  static const List<int> _k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  final List<int> _h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];

  final List<int> _buffer = [];
  int _totalLength = 0;

  void update(List<int> data) {
    _buffer.addAll(data);
    _totalLength += data.length;

    while (_buffer.length >= 64) {
      _processBlock(_buffer.sublist(0, 64));
      _buffer.removeRange(0, 64);
    }
  }

  List<int> digest() {
    // Padding.
    final msgLen = _totalLength;
    _buffer.add(0x80);
    while (_buffer.length % 64 != 56) {
      _buffer.add(0);
    }
    // Append length in bits as 64-bit big-endian.
    final bitLen = msgLen * 8;
    for (int i = 56; i >= 0; i -= 8) {
      _buffer.add((bitLen >> i) & 0xff);
    }

    while (_buffer.length >= 64) {
      _processBlock(_buffer.sublist(0, 64));
      _buffer.removeRange(0, 64);
    }

    final result = <int>[];
    for (final h in _h) {
      result.add((h >> 24) & 0xff);
      result.add((h >> 16) & 0xff);
      result.add((h >> 8) & 0xff);
      result.add(h & 0xff);
    }
    return result;
  }

  void _processBlock(List<int> block) {
    final w = List<int>.filled(64, 0);
    for (int i = 0; i < 16; i++) {
      w[i] = (block[i * 4] << 24) |
          (block[i * 4 + 1] << 16) |
          (block[i * 4 + 2] << 8) |
          block[i * 4 + 3];
    }

    for (int i = 16; i < 64; i++) {
      final s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      final s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
    }

    int a = _h[0], b = _h[1], c = _h[2], d = _h[3];
    int e = _h[4], f = _h[5], g = _h[6], h = _h[7];

    for (int i = 0; i < 64; i++) {
      final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
      final ch = (e & f) ^ ((~e & 0xffffffff) & g);
      final temp1 = (h + s1 + ch + _k[i] + w[i]) & 0xffffffff;
      final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final temp2 = (s0 + maj) & 0xffffffff;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) & 0xffffffff;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & 0xffffffff;
    }

    _h[0] = (_h[0] + a) & 0xffffffff;
    _h[1] = (_h[1] + b) & 0xffffffff;
    _h[2] = (_h[2] + c) & 0xffffffff;
    _h[3] = (_h[3] + d) & 0xffffffff;
    _h[4] = (_h[4] + e) & 0xffffffff;
    _h[5] = (_h[5] + f) & 0xffffffff;
    _h[6] = (_h[6] + g) & 0xffffffff;
    _h[7] = (_h[7] + h) & 0xffffffff;
  }

  static int _rotr(int x, int n) {
    return ((x & 0xffffffff) >>> n) | ((x << (32 - n)) & 0xffffffff);
  }
}
