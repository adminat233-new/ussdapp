import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// ICE configuration for the Flutter WebRTC call path.
///
/// STUN is always present so ordinary NATs work out of the box. TURN is
/// optional but must be user-supplied: without it, symmetric NAT and strict
/// firewalls can block media even when signalling succeeds. TURN credentials
/// go to secure storage, never to a plaintext preferences file.
class CallConfig {
  String turnUrl = '';
  String turnUsername = '';
  String turnCredential = '';

  static const FlutterSecureStorage _secure = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  Future<void> load() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      turnUrl = prefs.getString('call_turn_url') ?? '';
      turnUsername = prefs.getString('call_turn_user') ?? '';
      turnCredential = await _secure.read(key: 'call_turn_credential') ?? '';
    } catch (_) {
      // Storage can be unavailable in a test host; keep the in-memory values.
    }
  }

  Future<void> save() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('call_turn_url', turnUrl.trim());
      await prefs.setString('call_turn_user', turnUsername.trim());
      final secret = turnCredential.trim();
      if (secret.isEmpty) {
        await _secure.delete(key: 'call_turn_credential');
      } else {
        await _secure.write(key: 'call_turn_credential', value: secret);
      }
    } catch (_) {
      // The caller reports persistence failure from its own SnackBar path.
      rethrow;
    }
  }

  List<Map<String, dynamic>> iceServers() {
    final servers = <Map<String, dynamic>>[
      <String, dynamic>{
        'urls': <String>[
          'stun:stun.l.google.com:19302',
          'stun:global.stun.twilio.com:3478',
        ],
      },
    ];
    final url = turnUrl.trim();
    if (url.isNotEmpty) {
      servers.add(<String, dynamic>{
        'urls': url,
        'username': turnUsername.trim(),
        'credential': turnCredential.trim(),
      });
    }
    return servers;
  }

  bool get hasTurn => turnUrl.trim().isNotEmpty;
}
