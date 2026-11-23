import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../services/relay_service.dart';

/// Video Call panel from the authoritative design: dark theater layout,
/// room signalling through the existing relay, call controls and in-call chat.
/// Live audio/video media is not implemented by this Flutter build, and the
/// interface says so instead of pretending that media is flowing.
class VideoCallScreen extends StatefulWidget {
  final RelayService relay;
  final VoidCallback? onGoToDialer;

  const VideoCallScreen({super.key, required this.relay, this.onGoToDialer});

  @override
  State<VideoCallScreen> createState() => _VideoCallScreenState();
}

class _VideoCallScreenState extends State<VideoCallScreen> {
  final _roomCtrl = TextEditingController(text: '700-1234567');
  final _peerCtrl = TextEditingController();
  final _chatCtrl = TextEditingController();
  final List<_RoomChatMessage> _chat = <_RoomChatMessage>[];
  final List<String> _roster = <String>[];

  bool _inRoom = false;
  bool _muted = false;
  bool _cameraOn = true;
  bool _sharing = false;
  bool _chatOpen = false;
  Duration _duration = Duration.zero;
  Timer? _timer;
  String _status = 'waiting...';

  @override
  void initState() {
    super.initState();
    widget.relay.onConferenceRoster = _onRoster;
    widget.relay.addMessageListener(_onRelayMessage);
  }

  @override
  void dispose() {
    _timer?.cancel();
    widget.relay.removeMessageListener(_onRelayMessage);
    if (identical(widget.relay.onConferenceRoster, _onRoster)) {
      widget.relay.onConferenceRoster = null;
    }
    _roomCtrl.dispose();
    _peerCtrl.dispose();
    _chatCtrl.dispose();
    super.dispose();
  }

  void _onRoster(String roomId, List<String> roster) {
    if (!mounted || roomId != _roomCtrl.text.trim()) return;
    setState(() {
      _roster
        ..clear()
        ..addAll(roster);
    });
  }

  void _onRelayMessage(String from, String body) {
    if (!mounted || !_inRoom) return;
    if (body.startsWith('CHAT|')) {
      setState(() {
        _chat.add(_RoomChatMessage(
          text: body.substring(5),
          mine: false,
          from: from,
        ));
      });
    }
  }

  void _note(String message) {
    if (!mounted) return;
    setState(() => _status = message);
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  void _joinRoom() {
    final room = _roomCtrl.text.trim();
    if (room.isEmpty) {
      _note('Enter a room ID first.');
      return;
    }
    if (!widget.relay.registered) {
      _note('Relay is not registered — configure it in Settings first.');
      return;
    }
    if (!widget.relay.joinConference(room)) {
      _note('Could not join the room; relay is not connected.');
      return;
    }
    _timer?.cancel();
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() => _duration += const Duration(seconds: 1));
    });
    setState(() {
      _inRoom = true;
      _duration = Duration.zero;
      _roster.clear();
      _status = 'room $room • signalling only';
    });
  }

  void _leaveRoom() {
    if (_inRoom) widget.relay.leaveConference(_roomCtrl.text.trim());
    _timer?.cancel();
    setState(() {
      _inRoom = false;
      _duration = Duration.zero;
      _roster.clear();
      _muted = false;
      _cameraOn = true;
      _sharing = false;
      _status = 'waiting...';
    });
  }

  void _sendChat() {
    final text = _chatCtrl.text.trim();
    if (text.isEmpty) return;
    final target = _peerCtrl.text.trim().isEmpty
        ? _roomCtrl.text.trim()
        : _peerCtrl.text.trim();
    if (!widget.relay.sendChat(target, text)) {
      _note('Relay is not registered — message was not sent.');
      return;
    }
    setState(() {
      _chat.add(_RoomChatMessage(text: text, mine: true, from: target));
      _chatCtrl.clear();
    });
  }

  Future<void> _copyInvite() async {
    final room = _roomCtrl.text.trim();
    if (room.isEmpty) {
      _note('Enter a room ID first.');
      return;
    }
    await Clipboard.setData(
      ClipboardData(text: 'USSD Manager Pro video room: $room'),
    );
    _note('Room ID copied. Peers still need a reachable relay.');
  }

  String _formatDuration(Duration value) {
    final minutes = value.inMinutes.remainder(60).toString().padLeft(2, '0');
    final seconds = value.inSeconds.remainder(60).toString().padLeft(2, '0');
    return '$minutes:$seconds';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0B0F19),
      body: SafeArea(
        child: Column(
          children: [
            _buildHeader(),
            Expanded(
              child: Row(
                children: [
                  Expanded(
                    child: Stack(
                      alignment: Alignment.bottomCenter,
                      children: [
                        _buildStage(),
                        _buildSelfView(),
                        _buildControlDock(),
                      ],
                    ),
                  ),
                  if (_chatOpen) _buildChatDrawer(),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      height: 56,
      padding: const EdgeInsets.symmetric(horizontal: 12),
      decoration: const BoxDecoration(
        color: Color(0xFF0F1524),
        border: Border(bottom: BorderSide(color: Color(0xFF1E293B))),
      ),
      child: Row(
        children: [
          Container(
            width: 9,
            height: 9,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: _inRoom ? const Color(0xFF10B981) : const Color(0xFF64748B),
            ),
          ),
          const SizedBox(width: 8),
          const Text(
            'Video Call',
            style: TextStyle(
              color: Colors.white,
              fontSize: 14,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              _status,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(
                color: Color(0xFF94A3B8),
                fontSize: 10,
                fontFamily: 'JetBrainsMono',
              ),
            ),
          ),
          TextButton(
            onPressed: () => setState(() => _chatOpen = !_chatOpen),
            child: Text(
              _chatOpen ? 'Hide chat' : 'Chat',
              style: const TextStyle(color: Colors.white, fontSize: 11),
            ),
          ),
          TextButton(
            onPressed: _leaveRoom,
            child: const Text(
              'End Call',
              style: TextStyle(color: Color(0xFFFB7185), fontSize: 11),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStage() {
    return Positioned.fill(
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(20, 24, 20, 150),
        child: Column(
          children: [
            Container(
              width: 92,
              height: 92,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: const LinearGradient(
                  colors: [Color(0xFF4F46E5), Color(0xFF2563EB), Color(0xFF7C3AED)],
                ),
                border: Border.all(color: const Color(0xFF312E81), width: 4),
              ),
              child: const Icon(Icons.videocam_rounded, color: Colors.white, size: 36),
            ),
            const SizedBox(height: 18),
            Text(
              _inRoom ? 'Room ${_roomCtrl.text.trim()}' : 'No active video call',
              textAlign: TextAlign.center,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 17,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              _inRoom
                  ? 'Signalling ${_formatDuration(_duration)} • ${_roster.isEmpty ? 'waiting for peers' : '${_roster.length} in roster'}. Live audio/video media requires a configured calling service.'
                  : 'Open the Chat Hub, select a peer and tap Video or dial a 700-XXXXXXX app number from the Dialer.',
              textAlign: TextAlign.center,
              style: const TextStyle(
                color: Color(0xFF94A3B8),
                fontSize: 12,
                height: 1.5,
              ),
            ),
            const SizedBox(height: 18),
            if (!_inRoom)
              ElevatedButton(
                onPressed: widget.onGoToDialer,
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF2563EB),
                  foregroundColor: Colors.white,
                ),
                child: const Text('Go to Dialer'),
              ),
            const SizedBox(height: 20),
            SizedBox(
              width: double.infinity,
              child: Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: const Color(0xFF0F1524),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: const Color(0xFF1E293B)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    TextField(
                      controller: _roomCtrl,
                      style: const TextStyle(
                        color: Colors.white,
                        fontFamily: 'JetBrainsMono',
                        fontSize: 13,
                      ),
                      decoration: const InputDecoration(
                        labelText: 'Room / app number',
                        labelStyle: TextStyle(color: Color(0xFF94A3B8), fontSize: 11),
                      ),
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        Expanded(
                          child: ElevatedButton(
                            onPressed: _inRoom ? null : _joinRoom,
                            child: Text(_inRoom ? 'In room' : 'Join room'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: OutlinedButton(
                            onPressed: _inRoom ? _leaveRoom : null,
                            child: const Text('Leave'),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSelfView() {
    return Positioned(
      right: 12,
      bottom: 116,
      child: Container(
        width: 116,
        height: 76,
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: Colors.black,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: _cameraOn ? const Color(0xFF10B981) : const Color(0xFF475569),
            width: 2,
          ),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
              color: _cameraOn
                  ? const Color(0xFF064E3B)
                  : const Color(0xFF1E293B),
              child: Text(
                _cameraOn ? 'CAM ON' : 'CAM OFF',
                style: TextStyle(
                  color: _cameraOn ? const Color(0xFF6EE7B7) : const Color(0xFF94A3B8),
                  fontSize: 9,
                  fontFamily: 'JetBrainsMono',
                ),
              ),
            ),
            const Align(
              alignment: Alignment.bottomLeft,
              child: Text('You', style: TextStyle(color: Colors.white, fontSize: 11)),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildControlDock() {
    return Positioned(
      bottom: 12,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
        decoration: BoxDecoration(
          color: const Color(0xFF0F172A).withOpacity(0.94),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: const Color(0xFF334155)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            _dockButton(
              icon: _muted ? Icons.mic_off_rounded : Icons.mic_rounded,
              label: _muted ? 'Unmute' : 'Mute',
              active: _muted,
              onTap: () {
                if (!_inRoom) {
                  _note('Join a room before changing call controls.');
                  return;
                }
                setState(() => _muted = !_muted);
              },
            ),
            _dockButton(
              icon: _cameraOn ? Icons.videocam_rounded : Icons.videocam_off_rounded,
              label: 'Camera',
              active: !_cameraOn,
              onTap: () {
                if (!_inRoom) {
                  _note('Join a room before changing call controls.');
                  return;
                }
                setState(() => _cameraOn = !_cameraOn);
              },
            ),
            _dockButton(
              icon: Icons.person_add_rounded,
              label: 'Add',
              active: false,
              onTap: _copyInvite,
            ),
            _dockButton(
              icon: Icons.screen_share_rounded,
              label: _sharing ? 'Sharing' : 'Share',
              active: _sharing,
              onTap: () {
                if (!_inRoom) {
                  _note('Join a room first.');
                  return;
                }
                setState(() => _sharing = !_sharing);
                _note(_sharing
                    ? 'Screen share flag is on, but this build has no screen-capture transport.'
                    : 'Screen share flag is off.');
              },
            ),
            _dockButton(
              icon: Icons.chat_bubble_outline_rounded,
              label: 'Chat',
              active: _chatOpen,
              onTap: () => setState(() => _chatOpen = !_chatOpen),
            ),
            _dockButton(
              icon: Icons.call_end_rounded,
              label: 'End',
              active: true,
              destructive: true,
              onTap: _leaveRoom,
            ),
          ],
        ),
      ),
    );
  }

  Widget _dockButton({
    required IconData icon,
    required String label,
    required bool active,
    required VoidCallback onTap,
    bool destructive = false,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 6),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              size: 18,
              color: destructive
                  ? Colors.white
                  : (active ? const Color(0xFF93C5FD) : const Color(0xFFCBD5E1)),
            ),
            const SizedBox(height: 3),
            Text(
              label,
              style: TextStyle(
                fontSize: 9,
                color: destructive
                    ? Colors.white
                    : (active ? const Color(0xFF93C5FD) : const Color(0xFFCBD5E1)),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildChatDrawer() {
    final drawerWidth = MediaQuery.of(context).size.width * 0.7;
    return Container(
      width: drawerWidth,
      decoration: const BoxDecoration(
        color: Color(0xFF0F1524),
        border: Border(left: BorderSide(color: Color(0xFF1E293B))),
      ),
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
            child: Row(
              children: [
                const Text(
                  'Room Chat',
                  style: TextStyle(
                    color: Color(0xFFE2E8F0),
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.close_rounded,
                      color: Color(0xFF94A3B8), size: 16),
                  onPressed: () => setState(() => _chatOpen = false),
                ),
              ],
            ),
          ),
          Expanded(
            child: _chat.isEmpty
                ? const Padding(
                    padding: EdgeInsets.all(16),
                    child: Text(
                      'Encrypted relay messages appear here while you are in a room. Incoming messages also appear in SMS.',
                      textAlign: TextAlign.center,
                      style: TextStyle(color: Color(0xFF64748B), fontSize: 11),
                    ),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.all(10),
                    itemCount: _chat.length,
                    itemBuilder: (context, index) {
                      final message = _chat[index];
                      return Align(
                        alignment: message.mine
                            ? Alignment.centerRight
                            : Alignment.centerLeft,
                        child: Container(
                          margin: const EdgeInsets.symmetric(vertical: 3),
                          padding: const EdgeInsets.symmetric(
                              horizontal: 10, vertical: 7),
                          decoration: BoxDecoration(
                            color: message.mine
                                ? const Color(0xFF4F46E5)
                                : const Color(0xFF1E293B),
                            borderRadius: BorderRadius.circular(10),
                          ),
                          child: Text(
                            message.text,
                            style: const TextStyle(color: Colors.white, fontSize: 11),
                          ),
                        ),
                      );
                    },
                  ),
          ),
          Padding(
            padding: const EdgeInsets.all(8),
            child: Column(
              children: [
                TextField(
                  controller: _peerCtrl,
                  style: const TextStyle(color: Colors.white, fontSize: 11),
                  decoration: const InputDecoration(
                    hintText: 'Peer number (optional)',
                    hintStyle: TextStyle(color: Color(0xFF64748B), fontSize: 11),
                    isDense: true,
                  ),
                ),
                const SizedBox(height: 6),
                Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _chatCtrl,
                        style: const TextStyle(color: Colors.white, fontSize: 11),
                        decoration: const InputDecoration(
                          hintText: 'Message...',
                          hintStyle:
                              TextStyle(color: Color(0xFF64748B), fontSize: 11),
                          isDense: true,
                        ),
                        onSubmitted: (_) => _sendChat(),
                      ),
                    ),
                    IconButton(
                      icon: const Icon(Icons.send_rounded,
                          color: Color(0xFF818CF8), size: 18),
                      onPressed: _sendChat,
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _RoomChatMessage {
  final String text;
  final bool mine;
  final String from;

  const _RoomChatMessage({
    required this.text,
    required this.mine,
    required this.from,
  });
}
