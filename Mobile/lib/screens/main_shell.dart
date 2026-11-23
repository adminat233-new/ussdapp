import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';

import 'agent_screen.dart';
import 'apps_screen.dart';
import 'chat_screen.dart';
import 'contacts_screen.dart';
import 'dialer_screen.dart';
import 'sim_manager_screen.dart';
import 'ussd_screen.dart';
import 'video_call_screen.dart';
import '../services/call_config.dart';
import '../services/relay_service.dart';

class MainShell extends StatefulWidget {
  const MainShell({super.key});

  @override
  State<MainShell> createState() => _MainShellState();
}

class _MainShellState extends State<MainShell> with TickerProviderStateMixin {
  int _currentIndex = 0;
  late final RelayService _relay;
  final AgentConfig _agentConfig = AgentConfig();
  final CallConfig _callConfig = CallConfig();
  bool _relayConnected = false;
  int _unreadMessages = 0;

  // Exact sidebar order and labels from the authoritative design.
  final List<_NavItem> _navItems = const <_NavItem>[
    _NavItem(icon: Icons.phone_rounded, label: 'Dialer'),
    _NavItem(icon: Icons.contacts_rounded, label: 'Contacts'),
    _NavItem(icon: Icons.videocam_rounded, label: 'Video Call'),
    _NavItem(icon: Icons.message_rounded, label: 'SMS', badgeKey: 'sms'),
    _NavItem(icon: Icons.sim_card_rounded, label: 'SIM Manager'),
    _NavItem(icon: Icons.terminal_rounded, label: 'USSD'),
    _NavItem(icon: Icons.apps_rounded, label: 'Apps'),
    _NavItem(icon: Icons.smart_toy_rounded, label: 'Agent'),
  ];

  @override
  void initState() {
    super.initState();
    _relay = RelayService();
    _relay.onConnectionChanged = (connected) {
      if (mounted) setState(() => _relayConnected = connected);
    };
    _relay.onUnreadChanged = (count) {
      if (mounted) setState(() => _unreadMessages = count);
    };
    // Restore saved number/relay and register automatically on startup.
    _relay.init().then((_) {
      if (mounted) setState(() {});
    });
    _agentConfig.load().then((_) {
      if (mounted) setState(() {});
    });
    _callConfig.load().then((_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _relay.dispose();
    super.dispose();
  }

  void _openPanel(int index) {
    setState(() => _currentIndex = index);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: _buildAppBar(),
      body: _buildBody(),
      bottomNavigationBar: _buildBottomNav(),
    );
  }

  PreferredSizeWidget _buildAppBar() {
    return AppBar(
      title: Row(
        children: [
          Container(
            width: 32,
            height: 32,
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [Color(0xFF2563EB), Color(0xFF4F46E5)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(10),
            ),
            child: const Icon(Icons.radio_tower_sharp,
                color: Colors.white, size: 16),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text(
                  'USSD MANAGER PRO',
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 1.0,
                    color: Color(0xFF2563EB),
                  ),
                ),
                Text(
                  _relayConnected ? 'Relay connected' : 'Relay disconnected',
                  style: TextStyle(
                    fontSize: 10,
                    color: _relayConnected
                        ? const Color(0xFF059669)
                        : const Color(0xFFDC2626),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      actions: [
        Padding(
          padding: const EdgeInsets.only(right: 4),
          child: Center(
            child: Container(
              width: 8,
              height: 8,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: _relayConnected
                    ? const Color(0xFF22C55E)
                    : const Color(0xFFEF4444),
              ),
            ),
          ),
        ),
        IconButton(
          icon: const Icon(Icons.settings_rounded),
          onPressed: () => _openSettings(),
          tooltip: 'Settings',
        ),
      ],
    );
  }

  Widget _buildBody() {
    final screens = <Widget>[
      DialerScreen(relay: _relay),
      const ContactsScreen(),
      VideoCallScreen(
        relay: _relay,
        callConfig: _callConfig,
        onGoToDialer: () => _openPanel(0),
      ),
      ChatScreen(relay: _relay),
      const SimManagerScreen(),
      const UssdScreen(),
      AppsScreen(
        onOpenSms: () => _openPanel(3),
        onOpenUssd: () => _openPanel(5),
      ),
      AgentScreen(
        relay: _relay,
        config: _agentConfig,
        onOpenSim: () => _openPanel(4),
        onOpenUssd: () => _openPanel(5),
        onOpenSms: () => _openPanel(3),
        onOpenApps: () => _openPanel(6),
        onOpenSettingsAi: () => _openSettings(tab: 1),
      ),
    ];
    return IndexedStack(index: _currentIndex, children: screens);
  }

  Widget _buildBottomNav() {
    return Container(
      decoration: BoxDecoration(
        color: Theme.of(context).scaffoldBackgroundColor == const Color(0xFF0F172A)
            ? const Color(0xFF1E293B)
            : Colors.white,
        border: const Border(top: BorderSide(color: Color(0xFFE2E8F0))),
      ),
      child: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 4, horizontal: 2),
          child: Row(
            children: List.generate(_navItems.length, (i) {
              final item = _navItems[i];
              final selected = i == _currentIndex;
              final hasBadge =
                  item.badgeKey == 'sms' && _unreadMessages > 0;
              final color = selected
                  ? const Color(0xFF2563EB)
                  : const Color(0xFF94A3B8);
              return Expanded(
                child: GestureDetector(
                  onTap: () => _openPanel(i),
                  child: AnimatedContainer(
                    duration: const Duration(milliseconds: 200),
                    padding: const EdgeInsets.symmetric(vertical: 5),
                    decoration: BoxDecoration(
                      color: selected
                          ? const Color(0xFF2563EB).withOpacity(0.1)
                          : Colors.transparent,
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Stack(
                      clipBehavior: Clip.none,
                      children: [
                        Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(item.icon, color: color, size: 19),
                            const SizedBox(height: 2),
                            Text(
                              item.label,
                              textAlign: TextAlign.center,
                              maxLines: 2,
                              style: TextStyle(
                                fontSize: 8.5,
                                height: 1.05,
                                fontWeight: FontWeight.w600,
                                color: color,
                              ),
                            ),
                          ],
                        ),
                        if (hasBadge)
                          Positioned(
                            top: -3,
                            right: 2,
                            child: Container(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 3, vertical: 1),
                              decoration: BoxDecoration(
                                color: const Color(0xFFEF4444),
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: Text(
                                _unreadMessages > 99
                                    ? '99+'
                                    : '$_unreadMessages',
                                style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 8,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ),
                      ],
                    ),
                  ).animate(target: selected ? 1 : 0).scaleXY(
                        end: 1.03, duration: 150.ms),
                ),
              );
            }),
          ),
        ),
      ),
    );
  }

  void _openSettings({int tab = 0}) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => _SettingsSheet(
        relay: _relay,
        config: _agentConfig,
        callConfig: _callConfig,
        initialTab: tab,
      ),
    );
  }
}

class _NavItem {
  final IconData icon;
  final String label;
  final String? badgeKey;

  const _NavItem({required this.icon, required this.label, this.badgeKey});
}

class _SettingsSheet extends StatefulWidget {
  final RelayService relay;
  final AgentConfig config;
  final CallConfig callConfig;
  final int initialTab;

  const _SettingsSheet({
    required this.relay,
    required this.config,
    required this.callConfig,
    this.initialTab = 0,
  });

  @override
  State<_SettingsSheet> createState() => _SettingsSheetState();
}

class _SettingsSheetState extends State<_SettingsSheet> {
  late int _tab;
  late TextEditingController _relayCtrl;
  late TextEditingController _numberCtrl;
  late TextEditingController _endpointCtrl;
  late TextEditingController _modelCtrl;
  late TextEditingController _keyCtrl;
  late TextEditingController _turnUrlCtrl;
  late TextEditingController _turnUserCtrl;
  late TextEditingController _turnCredentialCtrl;
  late String _provider;

  @override
  void initState() {
    super.initState();
    _tab = widget.initialTab;
    _relayCtrl = TextEditingController(text: widget.relay.serverAddress);
    _numberCtrl = TextEditingController(text: widget.relay.myNumber);
    _endpointCtrl = TextEditingController(text: widget.config.endpoint);
    _modelCtrl = TextEditingController(text: widget.config.model);
    _keyCtrl = TextEditingController(text: widget.config.apiKey);
    _turnUrlCtrl = TextEditingController(text: widget.callConfig.turnUrl);
    _turnUserCtrl = TextEditingController(text: widget.callConfig.turnUsername);
    _turnCredentialCtrl =
        TextEditingController(text: widget.callConfig.turnCredential);
    _provider = widget.config.provider;
  }

  @override
  void dispose() {
    _relayCtrl.dispose();
    _numberCtrl.dispose();
    _endpointCtrl.dispose();
    _modelCtrl.dispose();
    _keyCtrl.dispose();
    _turnUrlCtrl.dispose();
    _turnUserCtrl.dispose();
    _turnCredentialCtrl.dispose();
    super.dispose();
  }

  void _saveRelay() {
    final messenger = ScaffoldMessenger.of(context);
    widget.relay.configure(_numberCtrl.text.trim(), _relayCtrl.text.trim());
    Navigator.pop(context);
    messenger.showSnackBar(
      const SnackBar(content: Text('Relay settings saved. Connecting...')),
    );
  }

  Future<void> _saveAi() async {
    final messenger = ScaffoldMessenger.of(context);
    setState(() {
      widget.config
        ..provider = _provider
        ..endpoint = _endpointCtrl.text.trim()
        ..model = _modelCtrl.text.trim()
        ..apiKey = _keyCtrl.text.trim();
    });
    String message = 'AI settings saved on this device.';
    try {
      await widget.config.save();
    } catch (_) {
      message = 'AI settings changed in memory but could not be persisted.';
    }
    if (!context.mounted) return;
    Navigator.pop(context);
    messenger.showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _saveCalls() async {
    final messenger = ScaffoldMessenger.of(context);
    setState(() {
      widget.callConfig
        ..turnUrl = _turnUrlCtrl.text.trim()
        ..turnUsername = _turnUserCtrl.text.trim()
        ..turnCredential = _turnCredentialCtrl.text.trim();
    });
    String message = widget.callConfig.hasTurn
        ? 'TURN server saved. Media can now try a relayed ICE path.'
        : 'STUN-only calling saved. Restrictive networks may still block media.';
    try {
      await widget.callConfig.save();
    } catch (_) {
      message = 'Call settings changed in memory but could not be persisted.';
    }
    if (!context.mounted) return;
    Navigator.pop(context);
    messenger.showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
      child: SingleChildScrollView(
        child: Container(
          padding: const EdgeInsets.all(20),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  const Text('Settings',
                      style:
                          TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                  const Spacer(),
                  Container(
                    padding: const EdgeInsets.all(3),
                    decoration: BoxDecoration(
                      color: const Color(0xFFF1F5F9),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Row(
                      children: [
                        _tabButton('Relay', 0),
                        _tabButton('AI', 1),
                        _tabButton('Calls', 2),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              if (_tab == 0) ...[
                TextField(
                  controller: _numberCtrl,
                  decoration: const InputDecoration(
                      labelText: 'My 700-XXXXXXX Number'),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _relayCtrl,
                  decoration: const InputDecoration(
                      labelText: 'Relay Server (host:port)'),
                ),
                const SizedBox(height: 18),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _saveRelay,
                    child: const Text('Save & Connect'),
                  ),
                ),
              ] else if (_tab == 1) ...[
                DropdownButtonFormField<String>(
                  value: _provider,
                  decoration: const InputDecoration(labelText: 'AI provider'),
                  items: const [
                    DropdownMenuItem(value: 'ollama', child: Text('Ollama (local)')),
                    DropdownMenuItem(value: 'gemini', child: Text('Gemini (BYOK)')),
                  ],
                  onChanged: (value) =>
                      setState(() => _provider = value ?? 'ollama'),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _endpointCtrl,
                  decoration: const InputDecoration(
                      labelText: 'Ollama endpoint (host:port)'),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _modelCtrl,
                  decoration: const InputDecoration(labelText: 'Model'),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _keyCtrl,
                  obscureText: true,
                  decoration: const InputDecoration(
                    labelText: 'Gemini API key (BYOK, stored securely)',
                  ),
                ),
                const SizedBox(height: 8),
                const Text(
                  'Prompts are sent only when you press Send. Provider, model and read-aloud survive restarts; the key is kept in platform secure storage.',
                  style: TextStyle(color: Color(0xFF64748B), fontSize: 11),
                ),
                const SizedBox(height: 18),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _saveAi,
                    child: const Text('Save AI settings'),
                  ),
                ),
              ] else ...[
                TextField(
                  controller: _turnUrlCtrl,
                  decoration: const InputDecoration(
                    labelText: 'TURN URL (optional)',
                    hintText: 'turn:relay.example.com:3478?transport=udp',
                  ),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _turnUserCtrl,
                  decoration: const InputDecoration(
                      labelText: 'TURN username (optional)'),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _turnCredentialCtrl,
                  obscureText: true,
                  decoration: const InputDecoration(
                    labelText: 'TURN credential (secure storage)',
                  ),
                ),
                const SizedBox(height: 10),
                const Text(
                  'STUN is enabled by default. Without TURN, calls across symmetric NAT or strict firewalls can fail; no app can honestly promise every network. TURN credentials are stored in platform secure storage.',
                  style: TextStyle(color: Color(0xFFB45309), fontSize: 11),
                ),
                const SizedBox(height: 8),
                Text(
                  widget.callConfig.hasTurn
                      ? 'TURN is configured.'
                      : 'No TURN configured: direct/STUN path only.',
                  style: const TextStyle(
                    color: Color(0xFF64748B),
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 18),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _saveCalls,
                    child: const Text('Save call settings'),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _tabButton(String label, int value) {
    final selected = _tab == value;
    return GestureDetector(
      onTap: () => setState(() => _tab = value),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          color: selected ? Colors.white : Colors.transparent,
          borderRadius: BorderRadius.circular(8),
        ),
        child: Text(
          label,
          style: TextStyle(
            fontSize: 12,
            fontWeight: selected ? FontWeight.bold : FontWeight.w500,
            color: selected ? const Color(0xFF2563EB) : const Color(0xFF64748B),
          ),
        ),
      ),
    );
  }
}
