import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';

import '../services/call_config.dart';
import '../services/relay_service.dart';
import '../services/webrtc_call_service.dart';

/// Video Call panel from the authoritative design: dark theater layout,
/// direct WebRTC media between two Flutter peers on the same relay, call
/// controls and in-call chat. Signalling uses the existing relay; media does
/// not. Cross-client media with the Windows or iOS call stacks is explicitly
/// not claimed because those stacks use different signalling.
class VideoCallScreen extends StatefulWidget {
  final RelayService relay;
  final CallConfig callConfig;
  final VoidCallback? onGoToDialer;

  const VideoCallScreen({
    super.key,
    required this.relay,
    required this.callConfig,
    this.onGoToDialer,
  });

  @override
  State<VideoCallScreen> createState() => _VideoCallScreenState();
}

class _VideoCallScreenState extends State<VideoCallScreen> {
  final _peerCtrl = TextEditingController(text: '700-1234567');
  final _chatCtrl = TextEditingController();
  final List<_RoomChatMessage> _chat = <_RoomChatMessage>[];

  late final WebRtcCallService _call;
  WebrtcPhase _phase = WebrtcPhase.idle;
  String _detail = 'No active call.';
  String _banner = '';
  bool _muted = false;
  bool _cameraOn = true;
  bool _chatOpen = false;
  Duration _duration = Duration.zero;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _call = WebRtcCallService(
      relay: widget.relay,
      callConfig: widget.callConfig,
      onState: _onCallState,
    );
    widget.relay.addSignalListener(_onSignal);
    widget.relay.addMessageListener(_onRelayMessage);
    _call.init().then((_) {
      if (mounted) setState(() {});
    }).catchError((_) {});
  }

  @override
  void dispose() {
    _timer?.cancel();
    widget.relay.removeSignalListener(_onSignal);
    widget.relay.removeMessageListener(_onRelayMessage);
    _call.dispose();
    _peerCtrl.dispose();
    _chatCtrl.dispose();
    super.dispose();
  }

  void _onSignal(String from, String body) {
    // Fire-and-forget: handleSignal catches malformed frames and races itself.
    _call.handleSignal(from, body).catchError((_) {});
  }

  void _onRelayMessage(String from, String body) {
    if (!mounted || !body.startsWith('CHAT|')) return;
    setState(() {
      _chat.add(_RoomChatMessage(
        text: body.substring(5),
        mine: false,
        from: from,
      ));
    });
  }

  void _onCallState(WebrtcPhase phase, String detail) {
    if (!mounted) return;
    setState(() {
      _phase = phase;
      _detail = detail;
    });
    if (_call.inCall) {
      _timer ??= Timer.periodic(const Duration(seconds: 1), (_) {
        if (mounted) setState(() => _duration += const Duration(seconds: 1));
      });
    } else {
      _timer?.cancel();
      _timer = null;
      _duration = Duration.zero;
    }
  }

  void _note(String message) {
    if (!mounted) return;
    setState(() => _banner = message);
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _startCall({required bool video}) async {
    final peer = _peerCtrl.text.trim();
    if (!widget.relay.registered) {
      _note('Relay is not registered. Configure it in Settings first.');
      return;
    }
    setState(() => _banner = 'Placing ${video ? 'video' : 'voice'} call to $peer...');
    final started = await _call.start(peerNumber: peer, video: video);
    if (!started && mounted) {
      _note(_call.detail);
    }
  }

  Future<void> _hangup() async {
    if (!_call.inCall) return;
    await _call.leave();
    if (mounted) setState(() => _banner = 'Call ended.');
  }

  Future<void> _toggleMute() async {
    if (!_call.inCall) {
      _note('Start a call before changing call controls.');
      return;
    }
    final next = !_muted;
    await _call.setMicrophoneEnabled(!next);
    if (mounted) setState(() => _muted = next);
  }

  Future<void> _toggleCamera() async {
    if (!_call.inCall) {
      _note('Start a call before changing call controls.');
      return;
    }
    final next = !_cameraOn;
    await _call.setCameraEnabled(next);
    if (mounted) setState(() => _cameraOn = next);
  }

  void _sendChat() {
    final text = _chatCtrl.text.trim();
    final target = _peerCtrl.text.trim();
    if (text.isEmpty) return;
    if (target.isEmpty) {
      _note('Enter the peer number first.');
      return;
    }
    if (!widget.relay.sendChat(target, text)) {
      _note('Relay is not registered. The message was not sent.');
      return;
    }
    setState(() {
      _chat.add(_RoomChatMessage(text: text, mine: true, from: target));
      _chatCtrl.clear();
    });
  }

  Future<void> _copyInvite() async {
    final number = widget.relay.myNumber;
    if (number.isEmpty) {
      _note('This install has no 700-XXXXXXX number yet.');
      return;
    }
    await Clipboard.setData(ClipboardData(
      text: 'Call me in USSD Manager Pro: $number'
          '${widget.relay.serverAddress.isNotEmpty
              ? ' (relay ${widget.relay.serverAddress})'
              : ''}',
    ));
    _note('Invite copied. The peer must be registered on the same relay.');
  }

  String _phaseLabel() {
    switch (_phase) {
      case WebrtcPhase.idle:
        return 'Idle';
      case WebrtcPhase.signalling:
        return 'Signalling';
      case WebrtcPhase.connecting:
        return 'Connecting';
      case WebrtcPhase.connected:
        return 'Connected';
      case WebrtcPhase.failed:
        return 'Failed';
    }
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
                  Expanded(child: _buildStage()),
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
    final connected = _phase == WebrtcPhase.connected;
    final failed = _phase == WebrtcPhase.failed;
    final dot = connected
        ? const Color(0xFF10B981)
        : failed
            ? const Color(0xFFFB7185)
            : _call.inCall
                ? const Color(0xFFF59E0B)
                : const Color(0xFF64748B);
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
            decoration: BoxDecoration(shape: BoxShape.circle, color: dot),
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
              _banner.isNotEmpty
                  ? _banner
                  : '${_phaseLabel()} • ${_formatDuration(_duration)} • $_detail',
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
            onPressed: _call.inCall ? _hangup : null,
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
    return Stack(
      children: [
        Positioned.fill(child: _buildRemotePane()),
        Positioned(
          top: 12,
          left: 12,
          right: 12,
          child: _buildDialCard(),
        ),
        _buildSelfView(),
        _buildControlDock(),
        if (!widget.callConfig.hasTurn)
          Positioned(
            left: 12,
            bottom: 116,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
              decoration: BoxDecoration(
                color: const Color(0xFF451A03).withOpacity(0.92),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFFB45309)),
              ),
              child: const Text(
                'STUN only: TURN may be required on this network.',
                style: TextStyle(color: Color(0xFFFDE68A), fontSize: 9),
              ),
            ),
          ),
      ],
    );
  }

  Widget _buildRemotePane() {
    if (_call.remoteRenderer.srcObject != null) {
      return RTCVideoView(
        _call.remoteRenderer,
        objectFit: RTCVideoViewObjectFit.RTCVideoViewObjectFitCover,
      );
    }
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [Color(0xFF0B0F19), Color(0xFF111C33), Color(0xFF0B0F19)],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
      ),
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 88,
              height: 88,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: const LinearGradient(
                  colors: [Color(0xFF4F46E5), Color(0xFF2563EB), Color(0xFF7C3AED)],
                ),
                border: Border.all(color: const Color(0xFF312E81), width: 4),
              ),
              child: const Icon(Icons.videocam_rounded,
                  color: Colors.white, size: 34),
            ),
            const SizedBox(height: 16),
            Text(
              _call.inCall ? 'Peer ${_call.peer}' : 'No active call',
              style: const TextStyle(
                color: Colors.white,
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),
            SizedBox(
              width: 260,
              child: Text(
                _detail,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: Color(0xFF94A3B8),
                  fontSize: 11,
                  height: 1.4,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDialCard() {
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: const Color(0xFF0F172A).withOpacity(0.94),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF334155)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          TextField(
            controller: _peerCtrl,
            enabled: !_call.inCall,
            style: const TextStyle(
              color: Colors.white,
              fontFamily: 'JetBrainsMono',
              fontSize: 13,
            ),
            decoration: const InputDecoration(
              labelText: 'Peer 700-XXXXXXX',
              labelStyle: TextStyle(color: Color(0xFF94A3B8), fontSize: 11),
              isDense: true,
            ),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed:
                      _call.inCall ? null : () => _startCall(video: false),
                  icon: const Icon(Icons.call_rounded, size: 15),
                  label: const Text('Voice'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF059669),
                    foregroundColor: Colors.white,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _call.inCall ? null : () => _startCall(video: true),
                  icon: const Icon(Icons.videocam_rounded, size: 15),
                  label: const Text('Video'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF2563EB),
                    foregroundColor: Colors.white,
                  ),
                ),
              ),
              const SizedBox(width: 6),
              IconButton(
                onPressed: widget.onGoToDialer,
                tooltip: 'Dialer',
                icon: const Icon(Icons.dialpad_rounded,
                    color: Color(0xFFCBD5E1), size: 18),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSelfView() {
    return Positioned(
      right: 12,
      bottom: 116,
      child: Container(
        width: 116,
        height: 92,
        padding: const EdgeInsets.all(6),
        decoration: BoxDecoration(
          color: Colors.black,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: _cameraOn && _call.inCall
                ? const Color(0xFF10B981)
                : const Color(0xFF475569),
            width: 2,
          ),
        ),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(8),
          child: _call.localRenderer.srcObject != null
              ? RTCVideoView(
                  _call.localRenderer,
                  objectFit: RTCVideoViewObjectFit.RTCVideoViewObjectFitCover,
                  mirror: true,
                )
              : Center(
                  child: Text(
                    _call.inCall
                        ? (_cameraOn ? 'CAMERA\nSTARTING' : 'CAM OFF')
                        : 'YOU',
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                      color: Color(0xFF94A3B8),
                      fontSize: 9,
                      fontFamily: 'JetBrainsMono',
                    ),
                  ),
                ),
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
              onTap: _toggleMute,
            ),
            _dockButton(
              icon: _cameraOn
                  ? Icons.videocam_rounded
                  : Icons.videocam_off_rounded,
              label: 'Camera',
              active: !_cameraOn,
              onTap: _toggleCamera,
            ),
            _dockButton(
              icon: Icons.person_add_rounded,
              label: 'Invite',
              active: false,
              onTap: _copyInvite,
            ),
            _dockButton(
              icon: Icons.chat_bubble_outline_rounded,
              label: 'Chat',
              active: _chatOpen,
              onTap: () async {
                setState(() => _chatOpen = !_chatOpen);
              },
            ),
            _dockButton(
              icon: Icons.call_end_rounded,
              label: 'End',
              active: true,
              destructive: true,
              onTap: _hangup,
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
    required Future<void> Function() onTap,
    bool destructive = false,
  }) {
    return GestureDetector(
      onTap: () {
        onTap().catchError((_) {});
      },
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
                  'Call Chat',
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
                      'Relay messages to the peer entered above appear here. Offline mail requires a sealed message path; plain chat is not stored by the relay.',
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
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _chatCtrl,
                    style: const TextStyle(color: Colors.white, fontSize: 11),
                    decoration: const InputDecoration(
                      hintText: 'Message peer...',
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
          ),
          const Padding(
            padding: EdgeInsets.fromLTRB(10, 0, 10, 10),
            child: Text(
              'Direct WebRTC between Flutter peers only. No common call signalling with Windows or iOS clients; media is not forwarded by the USSD relay.',
              style: TextStyle(color: Color(0xFF64748B), fontSize: 9),
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
