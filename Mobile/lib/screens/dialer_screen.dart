import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_animate/flutter_animate.dart';
import '../services/relay_service.dart';

class DialerScreen extends StatefulWidget {
  final RelayService relay;
  const DialerScreen({super.key, required this.relay});
  @override
  State<DialerScreen> createState() => _DialerScreenState();
}

class _DialerScreenState extends State<DialerScreen> {
  final _controller = TextEditingController();
  bool _inCall = false;
  bool _isVideo = false;
  Duration _callDuration = Duration.zero;
  Timer? _callTimer;
  String _transport = 'voip'; // 'voip' | 'cellular'

  static const _keys = [
    ['1', ''], ['2', 'ABC'], ['3', 'DEF'],
    ['4', 'GHI'], ['5', 'JKL'], ['6', 'MNO'],
    ['7', 'PQRS'], ['8', 'TUV'], ['9', 'WXYZ'],
    ['*', ''], ['0', '+'], ['#', ''],
  ];

  @override
  void dispose() {
    _controller.dispose();
    _callTimer?.cancel();
    super.dispose();
  }

  void _pressKey(String k) {
    HapticFeedback.selectionClick();
    setState(() => _controller.text += k);
  }

  void _backspace() {
    final t = _controller.text;
    if (t.isNotEmpty) setState(() => _controller.text = t.substring(0, t.length - 1));
  }

  void _startCall({bool video = false}) {
    final number = _controller.text.trim();
    if (number.isEmpty) return;
    HapticFeedback.heavyImpact();
    setState(() { _inCall = true; _isVideo = video; _callDuration = Duration.zero; });
    _callTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() => _callDuration += const Duration(seconds: 1));
    });
    // Send INVITE via relay
    widget.relay.sendMessage(number, 'INVITE|${DateTime.now().millisecondsSinceEpoch}|${video ? 1 : 0}|mobile|0');
  }

  void _endCall() {
    HapticFeedback.heavyImpact();
    _callTimer?.cancel();
    setState(() { _inCall = false; _callDuration = Duration.zero; });
  }

  String _fmtDuration(Duration d) {
    final m = d.inMinutes.remainder(60).toString().padLeft(2, '0');
    final s = d.inSeconds.remainder(60).toString().padLeft(2, '0');
    return '$m:$s';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Theme.of(context).scaffoldBackgroundColor,
      body: SafeArea(
        child: Column(
          children: [
            // Transport switcher
            _buildTransportSwitcher(),
            // Active call banner
            if (_inCall) _buildCallBanner(),
            // Number input
            _buildNumberInput(),
            // Keypad
            Expanded(child: _buildKeypad()),
            // Call buttons
            _buildCallButtons(),
            const SizedBox(height: 20),
          ],
        ),
      ),
    );
  }

  Widget _buildTransportSwitcher() {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Container(
        padding: const EdgeInsets.all(4),
        decoration: BoxDecoration(
          color: const Color(0xFFF1F5F9),
          borderRadius: BorderRadius.circular(14),
        ),
        child: Row(
          children: [
            _transportBtn('voip', Icons.language_rounded, 'VoIP / LAN'),
            _transportBtn('cellular', Icons.phone_rounded, 'Cellular'),
          ],
        ),
      ),
    );
  }

  Widget _transportBtn(String id, IconData icon, String label) {
    final sel = _transport == id;
    return Expanded(
      child: GestureDetector(
        onTap: () => setState(() => _transport = id),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 200),
          padding: const EdgeInsets.symmetric(vertical: 10),
          decoration: BoxDecoration(
            color: sel ? Colors.white : Colors.transparent,
            borderRadius: BorderRadius.circular(10),
            boxShadow: sel ? [BoxShadow(color: Colors.black.withOpacity(0.06), blurRadius: 4)] : [],
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(icon, size: 16, color: sel ? const Color(0xFF2563EB) : const Color(0xFF64748B)),
              const SizedBox(width: 6),
              Text(label, style: TextStyle(
                fontSize: 12, fontWeight: FontWeight.w600,
                color: sel ? const Color(0xFF2563EB) : const Color(0xFF64748B),
              )),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildCallBanner() {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFF059669),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Row(
        children: [
          Container(
            width: 10, height: 10,
            decoration: const BoxDecoration(color: Colors.white, shape: BoxShape.circle),
          ).animate(onPlay: (c) => c.repeat()).fadeOut(duration: 800.ms),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Calling ${_controller.text}', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 13)),
                Text('${_fmtDuration(_callDuration)} • ${_isVideo ? "HD Video" : "HD Audio"}',
                  style: const TextStyle(color: Colors.white70, fontSize: 11)),
              ],
            ),
          ),
          GestureDetector(
            onTap: _endCall,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(color: const Color(0xFFDC2626), borderRadius: BorderRadius.circular(8)),
              child: const Text('Hang up', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12)),
            ),
          ),
        ],
      ),
    ).animate().slideY(begin: -0.5).fadeIn();
  }

  Widget _buildNumberInput() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: Row(
        children: [
          Expanded(
            child: Container(
              height: 56,
              padding: const EdgeInsets.symmetric(horizontal: 16),
              decoration: BoxDecoration(
                color: const Color(0xFFF1F5F9),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: const Color(0xFFE2E8F0)),
              ),
              child: TextField(
                controller: _controller,
                style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w700, fontFamily: 'JetBrainsMono', letterSpacing: 2),
                decoration: const InputDecoration(border: InputBorder.none, hintText: 'Enter number...', hintStyle: TextStyle(fontSize: 14, color: Color(0xFF94A3B8), fontFamily: 'Inter')),
              ),
            ),
          ),
          const SizedBox(width: 8),
          _iconBtn(Icons.backspace_rounded, _backspace),
          const SizedBox(width: 8),
          _iconBtn(Icons.clear_rounded, () => setState(() => _controller.clear())),
        ],
      ),
    );
  }

  Widget _iconBtn(IconData icon, VoidCallback onTap) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 48, height: 48,
        decoration: BoxDecoration(
          color: const Color(0xFFF1F5F9),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: const Color(0xFFE2E8F0)),
        ),
        child: Icon(icon, size: 20, color: const Color(0xFF64748B)),
      ),
    );
  }

  Widget _buildKeypad() {
    return GridView.builder(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      physics: const NeverScrollableScrollPhysics(),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 3, childAspectRatio: 1.5, crossAxisSpacing: 10, mainAxisSpacing: 10,
      ),
      itemCount: 12,
      itemBuilder: (ctx, i) {
        final k = _keys[i];
        return _keyButton(k[0], k[1]);
      },
    );
  }

  Widget _keyButton(String digit, String sub) {
    return GestureDetector(
      onTap: () => _pressKey(digit),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 100),
        decoration: BoxDecoration(
          color: const Color(0xFFF8FAFC),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: const Color(0xFFE2E8F0)),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(digit, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.w700, color: Color(0xFF0F172A))),
            if (sub.isNotEmpty)
              Text(sub, style: const TextStyle(fontSize: 9, fontWeight: FontWeight.w700, letterSpacing: 1.5, color: Color(0xFF94A3B8))),
          ],
        ),
      ),
    );
  }

  Widget _buildCallButtons() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: Row(
        children: [
          Expanded(
            child: GestureDetector(
              onTap: () => _inCall ? _endCall() : _startCall(),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                height: 56,
                decoration: BoxDecoration(
                  color: _inCall ? const Color(0xFFDC2626) : const Color(0xFF059669),
                  borderRadius: BorderRadius.circular(16),
                  boxShadow: [BoxShadow(color: (_inCall ? const Color(0xFFDC2626) : const Color(0xFF059669)).withOpacity(0.3), blurRadius: 12, offset: const Offset(0, 4))],
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(_inCall ? Icons.call_end_rounded : Icons.call_rounded, color: Colors.white, size: 22),
                    const SizedBox(width: 8),
                    Text(_inCall ? 'END' : 'CALL', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w800, fontSize: 14, letterSpacing: 1)),
                  ],
                ),
              ),
            ),
          ),
          const SizedBox(width: 10),
          GestureDetector(
            onTap: () => _inCall ? null : _startCall(video: true),
            child: Container(
              width: 56, height: 56,
              decoration: BoxDecoration(
                color: const Color(0xFF2563EB),
                borderRadius: BorderRadius.circular(16),
                boxShadow: [BoxShadow(color: const Color(0xFF2563EB).withOpacity(0.3), blurRadius: 12, offset: const Offset(0, 4))],
              ),
              child: const Icon(Icons.videocam_rounded, color: Colors.white, size: 22),
            ),
          ),
        ],
      ),
    );
  }
}
