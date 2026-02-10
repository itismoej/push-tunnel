import 'dart:io';

import 'package:push_tunnel_client/config.dart';
import 'package:push_tunnel_client/crypto.dart';
import 'package:push_tunnel_client/socks5_server.dart';
import 'package:push_tunnel_client/tunnel_client.dart';

Future<void> main(List<String> args) async {
  final configPath = args.isNotEmpty ? args[0] : '../config.json';

  print('push-tunnel client starting...');
  print('Loading config from $configPath');

  final config = await Config.load(configPath);
  print('Firebase project: ${config.firebaseProject}');

  final crypto = await TunnelCrypto.create(config.psk);
  print('Crypto initialised');

  final tunnel = TunnelClient(config: config, crypto: crypto);
  await tunnel.start();

  final socks = Socks5Server(port: config.socksPort, tunnel: tunnel);
  await socks.start();

  print('');
  print('Ready! Configure your applications to use SOCKS5 proxy:');
  print('  127.0.0.1:${config.socksPort}');
  print('');
  print('Example: curl --socks5 127.0.0.1:${config.socksPort} http://example.com');
  print('');
  print('Press Ctrl+C to stop.');

  // Handle graceful shutdown.
  ProcessSignal.sigint.watch().listen((_) {
    print('\nShutting down...');
    socks.stop();
    tunnel.stop();
    exit(0);
  });
}
