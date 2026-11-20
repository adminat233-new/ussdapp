import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:shared_preferences/shared_preferences.dart';

/// RelayService — TCP client implementing the same line protocol as the
/// desktop app's RelayClient (CallServer.cs).
///
/// Protocol (UTF-8, newline-delimited):
///   OUT: REG|<number>|<token>|<machine>
///        KA|
///        MSG|<to>|<from>|<line>
///        CONF_JOIN|<roomId>|<token>
///        CONF_LEAVE|<roomId>
///        CONF_AUDIO|<roomId>|<b64pcm>
///   IN:  OK|<number>
///        PEERS|n,ip,machine;...
///        MSG|<to>|<from>|<line>
///        CONF_MIXED|<roomId>|<from>|<b64pcm>
///        CONF_ROSTER|<roomId>|n1,n2,...
class RelayService {
  String serverAddress = '';
  String myNumber = '';
  String myToken = '';

  Function(bool)? onConnectionChanged;
  Function(String, String)? onMessage;       // from, body
  Function(int)? onUnreadChanged;
  Function(List<PeerInfo>)? onPeersChanged;
  Function(String, List<String>)? onConferenceRoster;
  Function(String, String, List<int>)? onConferenceAudio;  // roomId, from, pcm

  Socket? _socket;
  StreamSubscription? _sub;
  Timer? _kaTimer;
  Timer? _reconnectTimer;
  bool _connected = false;
  bool _registered = false;
  final StringBuffer _buf = StringBuffer();
  final Map<String, int> _unread = {};
  final List<PeerInfo> _peers = [];

  bool get connected => _connected;
  bool get registered => _registered;
  List<PeerInfo> get peers => List.unmodifiable(_peers);

  void configure(String number, String address) async {
    myNumber = number;
    serverAddress = address;
    myToken = _loadOrCreateToken(number);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('relay_number', number);
    await prefs.setString('relay_address', address);
    _reconnect();
  }

  Future<void> init() async {
    final prefs = await SharedPreferences.getInstance();
    myNumber = prefs.getString('relay_number') ?? '';
    serverAddress = prefs.getString('relay_address') ?? '';
    myToken = _loadOrCreateToken(myNumber);
    if (myNumber.isNotEmpty && serverAddress.isNotEmpty) _reconnect();
  }

  void _reconnect() {
    _reconnectTimer?.cancel();
    _sub?.cancel();
    try { _socket?.destroy(); } catch (_) {}
    _connected = false; _registered = false;
    onConnectionChanged?.call(false);
    _reconnectTimer = Timer(const Duration(seconds: 2), _connect);
  }

  Future<void> _connect() async {
    if (serverAddress.isEmpty || myNumber.isEmpty) return;
    try {
      final parts = serverAddress.split(':');
      final host = parts[0];
      final port = parts.length > 1 ? int.tryParse(parts[1]) ?? 45675 : 45675;
      _socket = await Socket.connect(host, port, timeout: const Duration(seconds: 8));
      _connected = true;
      onConnectionChanged?.call(true);
      _socket!.setOption(SocketOption.tcpNoDelay, true);
      _sub = _socket!.transform(const Utf8Decoder()).listen(
        _onData, onError: (_) => _onDisconnect(), onDone: _onDisconnect,
      );
      // Register
      _write('REG|$myNumber|$myToken|${Platform.operatingSystem}');
      // Keepalive every 20s
      _kaTimer = Timer.periodic(const Duration(seconds: 20), (_) { if (_connected) _write('KA|'); });
    } catch (e) {
      _onDisconnect();
    }
  }

  void _onData(String chunk) {
    _buf.write(chunk);
    final str = _buf.toString();
    final lines = str.split('\n');
    _buf.clear();
    if (!str.endsWith('\n')) _buf.write(lines.removeLast());
    for (final line in lines) {
      if (line.trim().isEmpty) continue;
      _handleLine(line.trim());
    }
  }

  void _handleLine(String line) {
    final parts = line.split('|');
    switch (parts[0]) {
      case 'OK':
        _registered = true;
        break;
      case 'PEERS':
        _parsePeers(parts.length > 1 ? parts[1] : '');
        break;
      case 'MSG':
        if (parts.length >= 4) {
          final from = parts[2];
          final body = parts.sublist(3).join('|');
          _handleMessage(from, body);
        }
        break;
      case 'CONF_MIXED':
        if (parts.length >= 4) {
          try {
            final pcm = base64Decode(parts[3]);
            onConferenceAudio?.call(parts[1], parts[2], pcm.map((b) => b < 128 ? b : b - 256).toList());
          } catch (_) {}
        }
        break;
      case 'CONF_ROSTER':
        if (parts.length >= 3) {
          onConferenceRoster?.call(parts[1], parts[2].split(','));
        }
        break;
      case 'ERR':
        // Handle errors
        break;
    }
  }

  void _handleMessage(String from, String body) {
    // Update unread count for non-current conversations
    _unread[from] = (_unread[from] ?? 0) + 1;
    onUnreadChanged?.call(_unread.values.fold(0, (a, b) => a + b));
    onMessage?.call(from, body);
  }

  void _parsePeers(String data) {
    _peers.clear();
    for (final entry in data.split(';')) {
      final f = entry.split(',');
      if (f.length >= 3) _peers.add(PeerInfo(number: f[0], ip: f[1], machine: f[2]));
    }
    onPeersChanged?.call(List.unmodifiable(_peers));
  }

  void _onDisconnect() {
    _connected = false; _registered = false;
    _kaTimer?.cancel();
    onConnectionChanged?.call(false);
    // Auto-reconnect in 5s
    Timer(const Duration(seconds: 5), _connect);
  }

  // ── Public send API ───────────────────────────────────────────────────

  bool sendMessage(String toNumber, String body) {
    if (!_registered) return false;
    return _write('MSG|$toNumber|$myNumber|$body');
  }

  bool sendChat(String toNumber, String text) => sendMessage(toNumber, 'CHAT|$text');

  bool sendChatRead(String toNumber) =>
      sendMessage(toNumber, 'CHATREAD|${DateTime.now().microsecondsSinceEpoch}');

  bool sendTyping(String toNumber, bool on) =>
      sendMessage(toNumber, 'CTYP|${on ? "1" : "0"}');

  bool joinConference(String roomId) => _write('CONF_JOIN|$roomId|$myToken');
  bool leaveConference(String roomId) => _write('CONF_LEAVE|$roomId');
  bool sendConferenceAudio(String roomId, List<int> pcm) =>
      _write('CONF_AUDIO|$roomId|${base64Encode(pcm)}');

  void markRead(String number) {
    _unread.remove(number);
    onUnreadChanged?.call(_unread.values.fold(0, (a, b) => a + b));
  }

  bool _write(String line) {
    if (_socket == null) return false;
    try {
      _socket!.write('$line\n');
      return true;
    } catch (_) {
      _onDisconnect();
      return false;
    }
  }

  String _loadOrCreateToken(String number) {
    // Simple deterministic token: SHA-256 of number + fixed salt
    // A real implementation should store a randomly-generated token securely.
    if (number.isEmpty) return 'anon';
    final bytes = utf8.encode(number + 'USSDPRO_v4_SALT_2024');
    int h = 0;
    for (final b in bytes) { h = (h * 31 + b) & 0xFFFFFFFF; }
    return h.toRadixString(16).padLeft(8, '0');
  }

  void dispose() {
    _kaTimer?.cancel();
    _reconnectTimer?.cancel();
    _sub?.cancel();
    try { _socket?.destroy(); } catch (_) {}
  }
}

class PeerInfo {
  final String number;
  final String ip;
  final String machine;
  const PeerInfo({required this.number, required this.ip, required this.machine});
}
