import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import '../services/relay_service.dart';
import '../services/speech_service.dart';

/// AI settings shared by the Agent panel and Settings > AI sheet. Ordinary
/// preferences are persisted with SharedPreferences; the BYOK secret goes to
/// platform secure storage. A failed load keeps safe in-memory defaults.
class AgentConfig {
  String provider;
  String endpoint;
  String model;
  String apiKey;
  bool readAloud;

  static const FlutterSecureStorage _secure = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  AgentConfig({
    this.provider = 'ollama',
    this.endpoint = 'http://localhost:11434',
    this.model = 'llama3',
    this.apiKey = '',
    this.readAloud = true,
  });

  Future<void> load() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      provider = prefs.getString('ai_provider') ?? provider;
      endpoint = prefs.getString('ai_endpoint') ?? endpoint;
      model = prefs.getString('ai_model') ?? model;
      readAloud = prefs.getBool('ai_read_aloud') ?? readAloud;
      apiKey = await _secure.read(key: 'gemini_api_key') ?? '';
    } catch (_) {
      // Keep defaults; a settings read failure must not break the app.
    }
  }

  Future<void> save() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('ai_provider', provider);
    await prefs.setString('ai_endpoint', endpoint);
    await prefs.setString('ai_model', model);
    await prefs.setBool('ai_read_aloud', readAloud);
    final key = apiKey.trim();
    if (key.isEmpty) {
      await _secure.delete(key: 'gemini_api_key');
    } else {
      await _secure.write(key: 'gemini_api_key', value: key);
    }
  }
}

class AgentScreen extends StatefulWidget {
  final RelayService relay;
  final AgentConfig config;
  final VoidCallback? onOpenSim;
  final VoidCallback? onOpenUssd;
  final VoidCallback? onOpenSms;
  final VoidCallback? onOpenApps;
  final VoidCallback? onOpenSettingsAi;

  const AgentScreen({
    super.key,
    required this.relay,
    required this.config,
    this.onOpenSim,
    this.onOpenUssd,
    this.onOpenSms,
    this.onOpenApps,
    this.onOpenSettingsAi,
  });

  @override
  State<AgentScreen> createState() => _AgentScreenState();
}

class _AgentScreenState extends State<AgentScreen> {
  final _inputCtrl = TextEditingController();
  final _scrollCtrl = ScrollController();
  final List<_AgentMsg> _messages = <_AgentMsg>[
    const _AgentMsg(
      role: 'assistant',
      title: 'USSD Manager Pro Assistant',
      content:
          'Hello! I can execute safe local workspace navigation (for example "Run USSD *124#", "Check SIM status", "Open SMS codes") right away, or answer full natural-language queries once enabled in Settings > AI.',
    ),
  ];
  bool _thinking = false;

  bool get _readAloud => widget.config.readAloud;

  Future<void> _setReadAloud(bool value) async {
    setState(() => widget.config.readAloud = value);
    try {
      await widget.config.save();
    } catch (_) {
      if (mounted) _note('Read-aloud preference could not be saved on this device.');
    }
  }

  @override
  void dispose() {
    _inputCtrl.dispose();
    _scrollCtrl.dispose();
    super.dispose();
  }

  void _addAssistant(String text) {
    setState(() {
      _messages.add(_AgentMsg(role: 'assistant', content: text));
    });
    _scrollDown();
  }

  void _note(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _send() async {
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
      setState(() {
        _messages.add(_AgentMsg(role: 'assistant', content: reply));
        _thinking = false;
      });
      _scrollDown();
      if (_readAloud) await _readAloudOnce(reply);
    } catch (e) {
      setState(() {
        _messages.add(_AgentMsg(role: 'error', content: 'Error: $e'));
        _thinking = false;
      });
      _scrollDown();
    }
  }

  Future<String> _askAI(String prompt) async {
    if (widget.config.provider == 'ollama') {
      final endpoint = widget.config.endpoint.trim().isEmpty
          ? 'http://localhost:11434'
          : widget.config.endpoint.trim();
      final model = widget.config.model.trim().isEmpty
          ? 'llama3'
          : widget.config.model.trim();
      final res = await http.post(
        Uri.parse('$endpoint/api/generate'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'model': model, 'prompt': prompt, 'stream': false}),
      ).timeout(const Duration(seconds: 30));
      if (res.statusCode == 200) {
        final data = jsonDecode(res.body) as Map<String, dynamic>;
        return data['response']?.toString() ?? 'No response';
      }
      return 'AI error: HTTP ${res.statusCode}';
    }
    if (widget.config.provider == 'gemini') {
      final key = widget.config.apiKey.trim();
      if (key.isEmpty) {
        return 'Gemini API key is not configured in Settings > AI.';
      }
      final model = widget.config.model.trim().isEmpty
          ? 'gemini-2.0-flash'
          : widget.config.model.trim();
      final uri = Uri.parse(
        'https://generativelanguage.googleapis.com/v1beta/models/$model:generateContent?key=${Uri.encodeQueryComponent(key)}',
      );
      final res = await http.post(
        uri,
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(<String, dynamic>{
          'contents': <dynamic>[
            <String, dynamic>{
              'role': 'user',
              'parts': <dynamic>[<String, dynamic>{'text': prompt}],
            },
          ],
        }),
      ).timeout(const Duration(seconds: 30));
      if (res.statusCode == 200) {
        final data = jsonDecode(res.body) as Map<String, dynamic>;
        final candidates = data['candidates'] as List<dynamic>?;
        if (candidates != null && candidates.isNotEmpty) {
          final content = (candidates.first as Map<String, dynamic>)['content']
              as Map<String, dynamic>?;
          final parts = content?['parts'] as List<dynamic>?;
          if (parts != null && parts.isNotEmpty) {
            return (parts.first as Map<String, dynamic>)['text']?.toString() ??
                'No response';
          }
        }
        return 'No response';
      }
      return 'AI error: HTTP ${res.statusCode}';
    }
    return 'Provider ${widget.config.provider} is not configured. Use Ollama (local) or configure Gemini in Settings > AI.';
  }

  Future<void> _readAloudOnce(String text) async {
    if (!_readAloud) {
      _note('Read aloud is off. Enable it above to hear the response.');
      return;
    }
    final spoken = await SpeechService.speak(text);
    if (!spoken && mounted) {
      _note('No speech engine is attached to this Flutter build. The answer is shown on screen; the preference is saved.');
    }
  }

  void _quickPrompt(String prompt) {
    setState(() {
      _messages.add(_AgentMsg(role: 'user', content: prompt));
    });
    switch (prompt) {
      case 'Check SIM & modem status':
        widget.onOpenSim?.call();
        _addAssistant(
          'SIM Manager opened. iOS/Android builds cannot read live ICCID/IMSI or modem telemetry; the panel shows honest status and a labelled simulation.',
        );
        break;
      case 'Run USSD *124#':
        widget.onOpenUssd?.call();
        _addAssistant(
          'Opened USSD. Review *124# there and choose a transport; nothing was sent automatically.',
        );
        break;
      case 'Open SMS verification codes':
        widget.onOpenSms?.call();
        _addAssistant(
          'Opened SMS. Verification codes appear in the messages list when received.',
        );
        break;
      case 'Go to Laptop Tracker':
        widget.onOpenApps?.call();
        _addAssistant(
          'Laptop Tracker is listed in Apps. Device permissions are configured in the Windows desktop app.',
        );
        break;
    }
  }

  void _scrollDown() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollCtrl.hasClients) {
        _scrollCtrl.animateTo(
          _scrollCtrl.position.maxScrollExtent,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeOut,
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Column(
        children: [
          _buildHeader(),
          Expanded(
            child: ListView.builder(
              controller: _scrollCtrl,
              padding: const EdgeInsets.symmetric(horizontal: 14),
              itemCount: _messages.length + (_thinking ? 1 : 0),
              itemBuilder: (context, index) {
                if (index == _messages.length) return _buildThinking();
                return _buildMessage(_messages[index]);
              },
            ),
          ),
          _buildInputBar(),
        ],
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      margin: const EdgeInsets.fromLTRB(14, 14, 14, 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Theme.of(context).cardColor,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xFFE2E8F0)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 34,
                height: 34,
                decoration: BoxDecoration(
                  color: const Color(0xFFEFF6FF),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(Icons.smart_toy_rounded,
                    color: Color(0xFF2563EB), size: 18),
              ),
              const SizedBox(width: 10),
              const Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Agent panel',
                        style: TextStyle(
                            fontSize: 15, fontWeight: FontWeight.bold)),
                    Text('Your local and AI assistant',
                        style:
                            TextStyle(color: Color(0xFF64748B), fontSize: 11)),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 4),
                decoration: BoxDecoration(
                  color: const Color(0xFFFFF7ED),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFFFED7AA)),
                ),
                child: const Text(
                  'Local Commands Only',
                  style: TextStyle(
                    color: Color(0xFFB45309),
                    fontSize: 9,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          const Text(
            'Ask the configured AI assistant, use safe local navigation commands, or read a response aloud. Prompts are sent only when you click Send. Device tracking and permissions stay in Laptop Tracker.',
            style: TextStyle(color: Color(0xFF64748B), fontSize: 11, height: 1.5),
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              SizedBox(
                width: 18,
                height: 18,
                child: Checkbox(
                  value: _readAloud,
                  onChanged: (value) => _setReadAloud(value ?? false),
                  materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
              ),
              const SizedBox(width: 6),
              const Text('Read AI responses aloud',
                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.w600)),
            ],
          ),
          const SizedBox(height: 10),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: const Color(0xFFFFF7ED),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: const Color(0xFFFED7AA)),
            ),
            child: Row(
              children: [
                const Icon(Icons.error_outline_rounded,
                    color: Color(0xFFD97706), size: 16),
                const SizedBox(width: 8),
                const Expanded(
                  child: Text(
                    'Configure and enable the AI assistant in Settings > AI first.',
                    style: TextStyle(color: Color(0xFF92400E), fontSize: 11),
                  ),
                ),
                TextButton(
                  onPressed: widget.onOpenSettingsAi,
                  child: const Text('Open Settings > AI',
                      style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
                ),
              ],
            ),
          ),
          const SizedBox(height: 8),
          const Text('Quick commands:',
              style: TextStyle(color: Color(0xFF94A3B8), fontSize: 10)),
          const SizedBox(height: 4),
          Wrap(
            spacing: 6,
            runSpacing: 6,
            children: [
              _quickChip('Check SIM & modem status'),
              _quickChip('Run USSD *124#'),
              _quickChip('Open SMS verification codes'),
              _quickChip('Go to Laptop Tracker'),
            ],
          ),
        ],
      ),
    );
  }

  Widget _quickChip(String label) {
    return GestureDetector(
      onTap: () => _quickPrompt(label),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
        decoration: BoxDecoration(
          color: const Color(0xFFF1F5F9),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Text(label,
            style: const TextStyle(color: Color(0xFF334155), fontSize: 10)),
      ),
    );
  }

  Widget _buildInputBar() {
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: const BoxDecoration(
        border: Border(top: BorderSide(color: Color(0xFFE2E8F0))),
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: _inputCtrl,
              decoration: const InputDecoration(
                hintText: 'Ask AI or enter a local command...',
                isDense: true,
              ),
              onSubmitted: (_) => _send(),
            ),
          ),
          const SizedBox(width: 6),
          OutlinedButton.icon(
            onPressed: () => _readAloudOnce(
              _messages.isNotEmpty ? _messages.last.content : '',
            ),
            icon: const Icon(Icons.volume_up_rounded, size: 16),
            label: const Text('Read aloud', style: TextStyle(fontSize: 10)),
            style: OutlinedButton.styleFrom(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
            ),
          ),
          const SizedBox(width: 6),
          ElevatedButton(
            onPressed: _send,
            style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
            ),
            child: const Text('Send', style: TextStyle(fontSize: 11)),
          ),
        ],
      ),
    );
  }

  Widget _buildMessage(_AgentMsg message) {
    final isUser = message.role == 'user';
    final isError = message.role == 'error';
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: isUser ? MainAxisAlignment.end : MainAxisAlignment.start,
        children: [
          if (!isUser) ...[
            Container(
              width: 28,
              height: 28,
              decoration: BoxDecoration(
                color: const Color(0xFFEFF6FF),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.smart_toy_rounded,
                  color: Color(0xFF2563EB), size: 16),
            ),
            const SizedBox(width: 8),
          ],
          Flexible(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
              decoration: BoxDecoration(
                color: isUser
                    ? const Color(0xFF2563EB)
                    : (isError
                        ? const Color(0xFFFEF2F2)
                        : Theme.of(context).cardColor),
                borderRadius: BorderRadius.circular(12),
                border: isUser
                    ? null
                    : Border.all(
                        color: isError
                            ? const Color(0xFFFECACA)
                            : const Color(0xFFE2E8F0),
                      ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (message.title != null) ...[
                    Text(
                      message.title!,
                      style: const TextStyle(
                        color: Color(0xFF0F172A),
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 4),
                  ],
                  Text(
                    message.content,
                    style: TextStyle(
                      color: isUser
                          ? Colors.white
                          : (isError
                              ? const Color(0xFFB91C1C)
                              : const Color(0xFF334155)),
                      fontSize: 11,
                      height: 1.45,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildThinking() {
    return const Padding(
      padding: EdgeInsets.symmetric(vertical: 8),
      child: Row(
        children: [
          SizedBox(
            width: 14,
            height: 14,
            child: CircularProgressIndicator(strokeWidth: 2),
          ),
          SizedBox(width: 8),
          Text('Thinking...',
              style: TextStyle(color: Color(0xFF64748B), fontSize: 11)),
        ],
      ),
    );
  }
}

class _AgentMsg {
  final String role;
  final String? title;
  final String content;

  const _AgentMsg({required this.role, required this.content, this.title});
}
