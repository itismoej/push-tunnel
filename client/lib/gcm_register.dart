import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

const String _checkinUrl = 'https://android.clients.google.com/checkin';
const String _registerUrl = 'https://android.clients.google.com/c2dm/register3';
const String _credsFile = 'gcm_credentials.json';

/// GCM device credentials (androidId, securityToken, FCM token).
class GCMCredentials {
  final int androidId;
  final int securityToken;
  final String fcmToken;

  GCMCredentials({
    required this.androidId,
    required this.securityToken,
    required this.fcmToken,
  });

  factory GCMCredentials.fromJson(Map<String, dynamic> json) {
    return GCMCredentials(
      androidId: json['android_id'] as int,
      securityToken: json['security_token'] as int,
      fcmToken: json['fcm_token'] as String,
    );
  }

  Map<String, dynamic> toJson() => {
        'android_id': androidId,
        'security_token': securityToken,
        'fcm_token': fcmToken,
      };
}

/// Register with GCM to obtain an FCM token.
/// Credentials are persisted to disk so subsequent runs skip registration.
Future<GCMCredentials> registerGCM(String senderId) async {
  // Try loading existing credentials.
  final existing = await _loadCredentials();
  if (existing != null && existing.fcmToken.isNotEmpty) {
    print('[gcm] loaded existing credentials (androidId=${existing.androidId})');
    return existing;
  }

  print('[gcm] no existing credentials, performing checkin...');

  // Step 1: Checkin.
  final checkin = await _doCheckin();
  print('[gcm] checkin ok: androidId=${checkin.$1}');

  // Step 2: Register.
  final fcmToken = await _doRegister(checkin.$1, checkin.$2, senderId);
  print('[gcm] registered, token=${fcmToken.substring(0, 20)}...');

  final creds = GCMCredentials(
    androidId: checkin.$1,
    securityToken: checkin.$2,
    fcmToken: fcmToken,
  );

  await _saveCredentials(creds);
  return creds;
}

Future<(int, int)> _doCheckin() async {
  final body = json.encode({
    'checkin': {
      'type': 3,
      'chromeBuild': {
        'platform': 2,
        'chromeVersion': '63.0.3234.0',
        'channel': 1,
      },
    },
    'version': 3,
    'id': 0,
    'securityToken': 0,
  });

  final resp = await http.post(
    Uri.parse(_checkinUrl),
    headers: {'Content-Type': 'application/json'},
    body: body,
  );

  if (resp.statusCode != 200) {
    throw Exception('Checkin failed (${resp.statusCode}): ${resp.body}');
  }

  final result = json.decode(resp.body) as Map<String, dynamic>;
  // Response uses snake_case field names.
  final androidId = _parseIntField(result['android_id']);
  final securityToken = _parseIntField(result['security_token']);

  if (androidId == 0) {
    throw Exception('Checkin returned zero androidId: ${resp.body}');
  }

  return (androidId, securityToken);
}

Future<String> _doRegister(int androidId, int securityToken, String senderId) async {
  final body = Uri(queryParameters: {
    'app': 'org.chromium.linux',
    'X-subtype': senderId,
    'device': androidId.toString(),
    'sender': senderId,
  }).query;

  final resp = await http.post(
    Uri.parse(_registerUrl),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'AidLogin $androidId:$securityToken',
    },
    body: body,
  );

  if (resp.statusCode != 200) {
    throw Exception('Register failed (${resp.statusCode}): ${resp.body}');
  }

  for (final line in resp.body.split('\n')) {
    if (line.startsWith('token=')) {
      return line.substring(6);
    }
  }

  throw Exception('No token in register response: ${resp.body}');
}

Future<GCMCredentials?> _loadCredentials() async {
  try {
    final file = File(_credsFile);
    if (!await file.exists()) return null;
    final data = json.decode(await file.readAsString()) as Map<String, dynamic>;
    return GCMCredentials.fromJson(data);
  } catch (_) {
    return null;
  }
}

Future<void> _saveCredentials(GCMCredentials creds) async {
  final data = const JsonEncoder.withIndent('  ').convert(creds.toJson());
  await File(_credsFile).writeAsString(data);
}

/// Parse an int field that may come as a number or a string.
int _parseIntField(dynamic value) {
  if (value is int) return value;
  if (value is String) return int.parse(value);
  return 0;
}
