import 'dart:convert';
import 'dart:io';

/// Client configuration.
class Config {
  final String psk;
  final int socksPort;
  final String firebaseProject;
  final String firebaseCredentials;
  final String senderId;
  final String peerFcmToken;

  Config({
    required this.psk,
    this.socksPort = 1080,
    required this.firebaseProject,
    required this.firebaseCredentials,
    required this.senderId,
    required this.peerFcmToken,
  });

  factory Config.fromJson(Map<String, dynamic> json) {
    return Config(
      psk: json['psk'] as String,
      socksPort: (json['socks_port'] as int?) ?? 1080,
      firebaseProject: json['firebase_project'] as String,
      firebaseCredentials: json['firebase_credentials'] as String,
      senderId: json['sender_id'] as String,
      peerFcmToken: (json['peer_fcm_token'] as String?) ?? '',
    );
  }

  static Future<Config> load(String path) async {
    final contents = await File(path).readAsString();
    return Config.fromJson(json.decode(contents) as Map<String, dynamic>);
  }
}
