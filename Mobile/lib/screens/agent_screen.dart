import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import '../services/relay_service.dart';

class AgentScreen extends StatefulWidget {
  final RelayService relay;
  const AgentScreen({super.key, required this.relay});
  @override
  State<AgentScreen> createState() => _AgentScreenState();
}

class _AgentScreenState extends State<AgentScreen> {
  final _inputCtrl = TextEditingController();
  final _scrollCtrl = ScrollController();
  final List<_AgentMsg> _messages = [];
  bool _thinking = false;
  String _aiProvider = 'ollama';
  String _aiEndpoint = 'http://localhost:11434';
  String _aiModel = 'llama3';

  void _send() async {
    final text = _inputCtrl.text.trim();
    if (text.isEmpty || _thinking) return;
    setState(() {
      _messages.add(_AgentMsg(role: 'user', content: text));
      _inputCtrl.clear();
      _thinking = true;
    });
    _scrollDown();
    try {
      final reply = await _askAI(text);
      setState(() { _messages.add(_AgentMsg(role: 'assistant', content: reply)); _thinking = false; });
      _scrollDown();
    } catch (e) {
      setState(() { _messages.add(_AgentMsg(role: 'error', content: 'Error: $e')); _thinking = false; });
    }
  }

  Future<String> _askAI(String prompt) async {
    if (_aiProvider == 'ollama') {
      final res = await http.post(
        Uri.parse('$_aiEndpoint/api/generate'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'model': _aiModel, 'prompt': prompt, 'stream': false}),
      ).timeout(const Duration(seconds: 30));
      if (res.statusCode == 200) {
        final data = jsonDecode(res.body);
        return data['response'] ?? 'No response';
      }
      return 'AI error: HTTP ${res.statusCode}';
    }
    return 'Provider $_aiProvider not configured. Use Ollama (local) or add API key in Settings.';
  }

  void _scrollDown() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollCtrl.hasClients) _scrollCtrl.animateTo(_scrollCtrl.position.maxScrollExtent, duration: const Duration(milliseconds: 300), curve: Curves.easeOut);
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Column(
          children: [
            // Header
            Container(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Container(
                    width: 40, height: 40,
                    decoration: BoxDecoration(color: const Color(0xFFEFF6FF), borderRadius: BorderRadius.circular(10)),
                    child: const Icon(Icons.smart_toy_rounded, color: Color(0xFF2563EB), size: 20),
                  ),
                  const SizedBox(width: 12),
                  const Expanded(child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('AI Agent', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 15)),
                      Text('Local & cloud AI assistant', style: TextStyle(color: Color(0xFF64748B), fontSize: 11)),
                    ],
                  )),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(color: const Color(0xFFEFF6FF), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFFBFDBFE))),
                    child: const Text('AI', style: TextStyle(color: Color(0xFF2563EB), fontWeight: FontWeight.w800, fontSize: 10, letterSpacing: 1)),
                  ),
                ],
              ),
            ),
            // Messages
            Expanded(
              child: _messages.isEmpty
                ? Center(child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: const [
                      Icon(Icons.smart_toy_outlined, size: 48, color: Color(0xFFCBD5E1)),
                      SizedBox(height: 12),
                      Text('Ask me anything', style: TextStyle(color: Color(0xFF94A3B8), fontWeight: FontWeight.w600)),
                      Text('USSD help, SMS drafts, carrier info, device control', style: TextStyle(color: Color(0xFF94A3B8), fontSize: 12), textAlign: TextAlign.center),
                    ],
                  ))
                : ListView.builder(
                    controller: _scrollCtrl,
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    itemCount: _messages.length + (_thinking ? 1 : 0),
                    itemBuilder: (ctx, i) {
                      if (i == _messages.length) return _buildThinking();
                      return _buildMsg(_messages[i]);
                    },
                  ),
            ),
            // Input
            Container(
              padding: const EdgeInsets.all(12),
              decoration: const BoxDecoration(border: Border(top: BorderSide(color: Color(0xFFE2E8F0)))),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _inputCtrl,
                      decoration: InputDecoration(
                        hintText: 'Ask about USSD, SMS, calls...',
                        filled: true, fillColor: const Color(0xFFF1F5F9),
                        border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
                        contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                      ),
                      onSubmitted: (_) => _send(),
                    ),
                  ),
                  const SizedBox(width: 8),
                  GestureDetector(
                    onTap: _send,
                    child: Container(
                      width: 44, height: 44,
                      decoration: BoxDecoration(color: const Color(0xFF2563EB), borderRadius: BorderRadius.circular(12)),
                      child: const Icon(Icons.send_rounded, color: Colors.white, size: 18),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildMsg(_AgentMsg msg) {
    final isUser = msg.role == 'user';
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: isUser ? MainAxisAlignment.end : MainAxisAlignment.start,
        children: [
          if (!isUser) ...[
            Container(
              width: 32, height: 32,
              decoration: BoxDecoration(color: const Color(0xFFEFF6FF), borderRadius: BorderRadius.circular(8)),
              child: const Icon(Icons.smart_toy_rounded, color: Color(0xFF2563EB), size: 16),
            ),
            const SizedBox(width: 8),
          ],
          Flexible(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              decoration: BoxDecoration(
                color: isUser ? const Color(0xFF2563EB) : Colors.white,
                borderRadius: BorderRadius.circular(14),
                border: isUser ? null : Border.all(color: const Color(0xFFE2E8F0)),
              ),
              child: Text(msg.content, style: TextStyle(color: isUser ? Colors.white : const Color(0xFF0F172A), fontSize: 13)),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildThinking() {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          Container(
            width: 32, height: 32,
            decoration: BoxDecoration(color: const Color(0xFFEFF6FF), borderRadius: BorderRadius.circular(8)),
            child: const Icon(Icons.smart_toy_rounded, color: Color(0xFF2563EB), size: 16),
          ),
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(14), border: Border.all(color: const Color(0xFFE2E8F0))),
            child: const Row(children: [
              SizedBox(width: 4, height: 4, child: CircularProgressIndicator(strokeWidth: 2)),
              SizedBox(width: 8), Text('Thinking...', style: TextStyle(color: Color(0xFF64748B), fontSize: 13)),
            ]),
          ),
        ],
      ),
    );
  }
}

class _AgentMsg {
  final String role;
  final String content;
  _AgentMsg({required this.role, required this.content});
}
