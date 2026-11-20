import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'dialer_screen.dart';
import 'chat_screen.dart';
import 'contacts_screen.dart';
import 'ussd_screen.dart';
import 'apps_screen.dart';
import 'agent_screen.dart';
import '../services/relay_service.dart';

class MainShell extends StatefulWidget {
  const MainShell({super.key});
  @override
  State<MainShell> createState() => _MainShellState();
}

class _MainShellState extends State<MainShell> with TickerProviderStateMixin {
  int _currentIndex = 0;
  late final RelayService _relay;
  bool _relayConnected = false;
  int _unreadMessages = 0;

  final List<_NavItem> _navItems = [
    _NavItem(icon: Icons.phone_rounded, label: 'Dialer'),
    _NavItem(icon: Icons.message_rounded, label: 'Chat', badgeKey: 'chat'),
    _NavItem(icon: Icons.contacts_rounded, label: 'Contacts'),
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
  }

  @override
  void dispose() {
    _relay.dispose();
    super.dispose();
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
            width: 36, height: 36,
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [Color(0xFF2563EB), Color(0xFF4F46E5)],
                begin: Alignment.topLeft, end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(10),
            ),
            child: const Icon(Icons.radio_tower_sharp, color: Colors.white, size: 18),
          ),
          const SizedBox(width: 10),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text('USSD MANAGER PRO',
                style: TextStyle(fontSize: 10, fontWeight: FontWeight.w800,
                    letterSpacing: 1.2, color: Color(0xFF2563EB))),
              Text(_relayConnected ? 'Connected' : 'Disconnected',
                style: TextStyle(fontSize: 11,
                    color: _relayConnected ? const Color(0xFF059669) : const Color(0xFFDC2626))),
            ],
          ),
        ],
      ),
      actions: [
        // Network quality dot
        Padding(
          padding: const EdgeInsets.only(right: 4),
          child: Center(
            child: Container(
              width: 8, height: 8,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: _relayConnected ? const Color(0xFF22C55E) : const Color(0xFFEF4444),
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
    final screens = [
      DialerScreen(relay: _relay),
      ChatScreen(relay: _relay),
      const ContactsScreen(),
      const UssdScreen(),
      const AppsScreen(),
      AgentScreen(relay: _relay),
    ];
    return IndexedStack(index: _currentIndex, children: screens);
  }

  Widget _buildBottomNav() {
    return Container(
      decoration: BoxDecoration(
        color: Theme.of(context).scaffoldBackgroundColor == const Color(0xFF0F172A)
            ? const Color(0xFF1E293B) : Colors.white,
        border: const Border(top: BorderSide(color: Color(0xFFE2E8F0))),
      ),
      child: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 6),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceAround,
            children: List.generate(_navItems.length, (i) {
              final item = _navItems[i];
              final selected = i == _currentIndex;
              final hasBadge = item.badgeKey == 'chat' && _unreadMessages > 0;
              return GestureDetector(
                onTap: () => setState(() => _currentIndex = i),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 200),
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                  decoration: BoxDecoration(
                    color: selected ? const Color(0xFF2563EB).withOpacity(0.1) : Colors.transparent,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Stack(
                    clipBehavior: Clip.none,
                    children: [
                      Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(item.icon,
                            color: selected ? const Color(0xFF2563EB) : const Color(0xFF94A3B8),
                            size: 22),
                          const SizedBox(height: 2),
                          Text(item.label,
                            style: TextStyle(
                              fontSize: 10, fontWeight: FontWeight.w600,
                              color: selected ? const Color(0xFF2563EB) : const Color(0xFF94A3B8),
                            )),
                        ],
                      ),
                      if (hasBadge)
                        Positioned(
                          top: -4, right: -6,
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                            decoration: BoxDecoration(
                              color: const Color(0xFFEF4444),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              _unreadMessages > 99 ? '99+' : '$_unreadMessages',
                              style: const TextStyle(color: Colors.white, fontSize: 9, fontWeight: FontWeight.bold),
                            ),
                          ),
                        ),
                    ],
                  ),
                ).animate(target: selected ? 1 : 0).scaleXY(end: 1.05, duration: 150.ms),
              );
            }),
          ),
        ),
      ),
    );
  }

  void _openSettings() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (ctx) => _SettingsSheet(relay: _relay),
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
  const _SettingsSheet({required this.relay});
  @override
  State<_SettingsSheet> createState() => _SettingsSheetState();
}

class _SettingsSheetState extends State<_SettingsSheet> {
  late TextEditingController _relayCtrl;
  late TextEditingController _numberCtrl;

  @override
  void initState() {
    super.initState();
    _relayCtrl = TextEditingController(text: widget.relay.serverAddress);
    _numberCtrl = TextEditingController(text: widget.relay.myNumber);
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
      child: Container(
        padding: const EdgeInsets.all(20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Settings', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
            const SizedBox(height: 20),
            TextField(controller: _numberCtrl, decoration: const InputDecoration(labelText: 'My 700-XXXXXXX Number')),
            const SizedBox(height: 12),
            TextField(controller: _relayCtrl, decoration: const InputDecoration(labelText: 'Relay Server (host:port)')),
            const SizedBox(height: 20),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: () {
                  widget.relay.configure(_numberCtrl.text.trim(), _relayCtrl.text.trim());
                  Navigator.pop(context);
                },
                child: const Text('Save & Connect'),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
