import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../services/relay_service.dart';

class ChatScreen extends StatefulWidget {
  final RelayService relay;
  const ChatScreen({super.key, required this.relay});
  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  String? _openNumber;
  final Map<String, List<_Msg>> _threads = {};
  final _inputCtrl = TextEditingController();
  final _scrollCtrl = ScrollController();

  @override
  void initState() {
    super.initState();
    widget.relay.onMessage = (from, body) {
      if (!mounted) return;
      setState(() {
        final thread = _threads.putIfAbsent(from, () => []);
        // Handle different message types
        if (body.startsWith('CHAT|')) {
          thread.add(_Msg(from: from, text: body.substring(5), time: DateTime.now(), mine: false));
        } else if (body.startsWith('VCARD|')) {
          thread.add(_Msg(from: from, text: '📇 Contact card received', time: DateTime.now(), mine: false, isVCard: true, vCardData: body.substring(6)));
        } else if (body.startsWith('REACT|')) {
          final parts = body.split('|');
          if (parts.length >= 3) {
            final msgId = parts[1];
            final emoji = parts[2];
            for (final m in thread) {
              if (m.id == msgId) { m.reactions.add(emoji); break; }
            }
          }
        }
        widget.relay.markRead(from);
      });
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (_scrollCtrl.hasClients) _scrollCtrl.animateTo(_scrollCtrl.position.maxScrollExtent, duration: const Duration(milliseconds: 200), curve: Curves.easeOut);
      });
    };
  }

  void _send() {
    final text = _inputCtrl.text.trim();
    if (text.isEmpty || _openNumber == null) return;
    HapticFeedback.selectionClick();
    widget.relay.sendChat(_openNumber!, text);
    setState(() {
      _threads.putIfAbsent(_openNumber!, () => []).add(
        _Msg(from: 'me', text: text, time: DateTime.now(), mine: true),
      );
      _inputCtrl.clear();
    });
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollCtrl.hasClients) _scrollCtrl.animateTo(_scrollCtrl.position.maxScrollExtent, duration: const Duration(milliseconds: 200), curve: Curves.easeOut);
    });
  }

  @override
  Widget build(BuildContext context) {
    if (_openNumber == null) return _buildConversationList();
    return _buildChat(_openNumber!);
  }

  Widget _buildConversationList() {
    final peers = widget.relay.peers;
    final allNumbers = {..._threads.keys, ...peers.map((p) => p.number)}.toList();
    return Column(
      children: [
        // Dark header matching website SMS panel style
        Container(
          color: const Color(0xFF0F172A),
          padding: const EdgeInsets.all(14),
          child: Row(
            children: [
              Expanded(
                child: Container(
                  height: 36,
                  decoration: BoxDecoration(
                    color: const Color(0xFF1E293B),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: const Color(0xFF334155)),
                  ),
                  child: const Row(
                    children: [
                      SizedBox(width: 10),
                      Icon(Icons.search, size: 16, color: Color(0xFF64748B)),
                      SizedBox(width: 8),
                      Expanded(child: TextField(
                        style: TextStyle(color: Colors.white, fontSize: 13),
                        decoration: InputDecoration(border: InputBorder.none, hintText: 'Search...', hintStyle: TextStyle(color: Color(0xFF64748B))),
                      )),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
        // Peer list
        Expanded(
          child: Container(
            color: const Color(0xFF0F172A),
            child: allNumbers.isEmpty
              ? const Center(child: Text('No conversations yet', style: TextStyle(color: Color(0xFF64748B))))
              : ListView.builder(
                  itemCount: allNumbers.length,
                  itemBuilder: (ctx, i) {
                    final num = allNumbers[i];
                    final lastMsg = _threads[num]?.last;
                    final online = widget.relay.peers.any((p) => p.number == num);
                    return ListTile(
                      leading: CircleAvatar(
                        backgroundColor: const Color(0xFF4F46E5),
                        child: Text(num.length >= 3 ? num.substring(num.length - 3) : num,
                          style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 11)),
                      ),
                      title: Text('#$num', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 13)),
                      subtitle: Text(lastMsg?.text ?? (online ? 'Online' : 'Offline'),
                        style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 11), maxLines: 1, overflow: TextOverflow.ellipsis),
                      trailing: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          if (online) Container(width: 8, height: 8, decoration: const BoxDecoration(color: Color(0xFF22C55E), shape: BoxShape.circle)),
                          if (lastMsg != null) ...[
                            const SizedBox(width: 6),
                            Text(_fmtTime(lastMsg.time), style: const TextStyle(color: Color(0xFF64748B), fontSize: 10)),
                          ],
                        ],
                      ),
                      onTap: () => setState(() { _openNumber = num; widget.relay.markRead(num); }),
                    );
                  },
                ),
          ),
        ),
      ],
    );
  }

  Widget _buildChat(String number) {
    final messages = _threads[number] ?? [];
    return Column(
      children: [
        // Chat header
        Container(
          color: const Color(0xFF172038),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          child: Row(
            children: [
              GestureDetector(
                onTap: () { setState(() => _openNumber = null); widget.relay.sendChatRead(number); },
                child: const Icon(Icons.arrow_back_rounded, color: Colors.white),
              ),
              const SizedBox(width: 12),
              CircleAvatar(
                backgroundColor: const Color(0xFF4F46E5), radius: 18,
                child: Text(number.length >= 3 ? number.substring(number.length - 3) : number,
                  style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 11)),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('#$number', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 14)),
                    Text(widget.relay.peers.any((p) => p.number == number) ? 'Online' : 'Offline',
                      style: TextStyle(color: widget.relay.peers.any((p) => p.number == number) ? const Color(0xFF22C55E) : const Color(0xFF94A3B8), fontSize: 11)),
                  ],
                ),
              ),
              IconButton(icon: const Icon(Icons.call_rounded, color: Colors.white, size: 20), onPressed: () {}),
              IconButton(icon: const Icon(Icons.videocam_rounded, color: Colors.white, size: 20), onPressed: () {}),
              IconButton(icon: const Icon(Icons.info_outline_rounded, color: Color(0xFF94A3B8), size: 20), onPressed: () {}),
            ],
          ),
        ),
        // Messages
        Expanded(
          child: Container(
            color: const Color(0xFF131C31),
            child: ListView.builder(
              controller: _scrollCtrl,
              padding: const EdgeInsets.all(16),
              itemCount: messages.length,
              itemBuilder: (ctx, i) => _buildBubble(messages[i]),
            ),
          ),
        ),
        // Input bar
        Container(
          color: const Color(0xFF0F172A),
          padding: const EdgeInsets.all(10),
          child: Row(
            children: [
              IconButton(icon: const Icon(Icons.attach_file_rounded, color: Color(0xFF64748B)), onPressed: () {}),
              IconButton(icon: const Icon(Icons.mic_rounded, color: Color(0xFF64748B)), onPressed: () {}),
              Expanded(
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 14),
                  decoration: BoxDecoration(
                    color: const Color(0xFF1A243D),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(color: const Color(0xFF334155)),
                  ),
                  child: TextField(
                    controller: _inputCtrl,
                    style: const TextStyle(color: Colors.white, fontSize: 14),
                    decoration: const InputDecoration(border: InputBorder.none, hintText: 'Type a message...', hintStyle: TextStyle(color: Color(0xFF64748B))),
                    onSubmitted: (_) => _send(),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              GestureDetector(
                onTap: _send,
                child: Container(
                  width: 42, height: 42,
                  decoration: BoxDecoration(
                    color: const Color(0xFF4F46E5),
                    borderRadius: BorderRadius.circular(21),
                    boxShadow: [BoxShadow(color: const Color(0xFF4F46E5).withOpacity(0.4), blurRadius: 8)],
                  ),
                  child: const Icon(Icons.send_rounded, color: Colors.white, size: 18),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildBubble(_Msg msg) {
    return Align(
      alignment: msg.mine ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 3),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.72),
        decoration: BoxDecoration(
          color: msg.mine ? const Color(0xFF4F46E5) : const Color(0xFF1E293B),
          borderRadius: BorderRadius.circular(16),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(msg.text, style: const TextStyle(color: Colors.white, fontSize: 14)),
            const SizedBox(height: 4),
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(_fmtTime(msg.time), style: const TextStyle(color: Colors.white54, fontSize: 10)),
                if (msg.mine) ...[
                  const SizedBox(width: 4),
                  const Icon(Icons.done_all_rounded, color: Colors.white54, size: 14),
                ],
              ],
            ),
            if (msg.reactions.isNotEmpty) ...[
              const SizedBox(height: 4),
              Wrap(spacing: 4, children: msg.reactions.map((e) => Text(e, style: const TextStyle(fontSize: 16))).toList()),
            ],
          ],
        ),
      ),
    );
  }

  static String _fmtTime(DateTime t) {
    return '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}';
  }
}

class _Msg {
  final String id = DateTime.now().microsecondsSinceEpoch.toString();
  final String from;
  final String text;
  final DateTime time;
  final bool mine;
  final bool isVCard;
  final String? vCardData;
  final List<String> reactions = [];
  _Msg({required this.from, required this.text, required this.time, required this.mine, this.isVCard = false, this.vCardData});
}
