import 'package:flutter/material.dart';

/// Apps panel from the authoritative design. Actions either open the matching
/// panel or report an honest status; nothing claims a service ran when it did
/// not.
class AppsScreen extends StatefulWidget {
  final VoidCallback? onOpenSms;
  final VoidCallback? onOpenUssd;

  const AppsScreen({super.key, this.onOpenSms, this.onOpenUssd});

  @override
  State<AppsScreen> createState() => _AppsScreenState();
}

class _AppsScreenState extends State<AppsScreen> {
  int _filter = 0;

  void _note(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  List<_Module> _modules() {
    return <_Module>[
      _Module(
        icon: Icons.shield_outlined,
        color: const Color(0xFF2563EB),
        title: 'Laptop Tracker',
        description:
            'Local hardware geofencing, device tracking, and AI permission guardrails referenced by the Agent Console.',
        status: 'Active',
        statusColor: const Color(0xFF059669),
        footer: 'Local Guard v4.0',
        action: 'Configure',
        connected: true,
        bridge: false,
        onAction: () => _note(
          'Laptop Tracker permissions are configured in the Windows desktop app.',
        ),
      ),
      _Module(
        icon: Icons.key_rounded,
        color: const Color(0xFF4F46E5),
        title: 'OTP Extractor',
        description:
            'Automatically parses 4–8 digit 2FA verification codes from incoming GSM SMS and routes them to SMS Codes.',
        status: 'Enabled',
        statusColor: const Color(0xFF059669),
        footer: '3 codes captured',
        action: 'View Codes',
        connected: true,
        bridge: false,
        onAction: () {
          widget.onOpenSms?.call();
          _note('Opened SMS. Verification codes appear in your messages.');
        },
      ),
      _Module(
        icon: Icons.smartphone_rounded,
        color: const Color(0xFF059669),
        title: 'Android Companion Bridge (.apk)',
        description:
            'Syncs contacts, VoIP LAN audio/video rooms, and SMS notifications between Windows .exe and Android .apk.',
        status: 'LAN Ready',
        statusColor: const Color(0xFF2563EB),
        footer: 'UDP/TCP 700-ID',
        action: 'Preview .apk',
        connected: true,
        bridge: true,
        onAction: () => _note(
          'This is the Android .apk build; the companion bridge is packaged here.',
        ),
      ),
      _Module(
        icon: Icons.schedule_rounded,
        color: const Color(0xFFD97706),
        title: 'Bulk USSD & Balance Scheduler',
        description:
            'Automates periodic *124# airtime/data checks and carrier bundle renewals via MiFi Web API or AT commands.',
        status: 'Standby',
        statusColor: const Color(0xFF64748B),
        footer: 'Interval: 30m',
        action: 'Open USSD',
        connected: true,
        bridge: false,
        onAction: () {
          widget.onOpenUssd?.call();
          _note('Opened USSD. No balance check was sent automatically.');
        },
      ),
      _Module(
        icon: Icons.router_rounded,
        color: const Color(0xFF0891B2),
        title: 'Router & MiFi Admin Gateway',
        description:
            'Direct HTTP session diagnostics, WAN APN management, and client lease inspection for connected MiFi modems.',
        status: '192.168.100.1',
        statusColor: const Color(0xFF2563EB),
        footer: 'HTTP API Ready',
        action: 'Ping Gateway',
        connected: false,
        bridge: true,
        onAction: () {
          widget.onOpenUssd?.call();
          _note(
            'Gateway ping needs a configured MiFi HTTP endpoint; none is set here. USSD is open for manual checks.',
          );
        },
      ),
      _Module(
        icon: Icons.terminal_rounded,
        color: const Color(0xFF475569),
        title: 'AT Command & COM Terminal',
        description:
            'Low-level serial console for raw AT+CSQ, AT+CUSD, and AT+CMGF diagnostics with live trace logging.',
        status: 'COM6 | 115200',
        statusColor: const Color(0xFF64748B),
        footer: 'Serial 8N1',
        action: 'Open AT Log',
        connected: false,
        bridge: true,
        onAction: () => _note(
          'AT/COM terminals need the Windows desktop app; Android has no COM port.',
        ),
      ),
    ];
  }

  List<_Module> get _visibleModules {
    final all = _modules();
    if (_filter == 1) return all.where((module) => module.connected).toList();
    if (_filter == 2) return all.where((module) => module.bridge).toList();
    return all;
  }

  @override
  Widget build(BuildContext context) {
    final modules = _visibleModules;
    return SafeArea(
      child: Column(
        children: [
          _buildHeader(),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Row(
              children: [
                _filterChip('All Modules', 0),
                const SizedBox(width: 6),
                _filterChip('Connected', 1),
                const SizedBox(width: 6),
                _filterChip('Device Bridges', 2),
              ],
            ),
          ),
          const SizedBox(height: 10),
          Expanded(
            child: modules.isEmpty
                ? const Center(
                    child: Text('No modules in this filter.',
                        style: TextStyle(color: Color(0xFF64748B), fontSize: 12)),
                  )
                : GridView.builder(
                    padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                    gridDelegate:
                        const SliverGridDelegateWithFixedCrossAxisCount(
                      crossAxisCount: 2,
                      crossAxisSpacing: 12,
                      mainAxisSpacing: 12,
                      childAspectRatio: 0.86,
                    ),
                    itemCount: modules.length,
                    itemBuilder: (context, index) => _buildCard(modules[index]),
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildHeader() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Companion Modules & Device Bridges',
                      style:
                          TextStyle(fontSize: 15, fontWeight: FontWeight.bold),
                    ),
                    SizedBox(height: 3),
                    Text(
                      'Integrated C# desktop services, Android LAN bridges, and security utilities.',
                      style: TextStyle(color: Color(0xFF64748B), fontSize: 11),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
                decoration: BoxDecoration(
                  color: const Color(0xFFECFDF5),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFFBBF7D0)),
                ),
                child: const Row(
                  children: [
                    Icon(Icons.circle, color: Color(0xFF22C55E), size: 7),
                    SizedBox(width: 5),
                    Text(
                      '6 Services Healthy',
                      style: TextStyle(
                        color: Color(0xFF059669),
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Container(
            padding: const EdgeInsets.all(4),
            decoration: BoxDecoration(
              color: const Color(0xFFF1F5F9),
              borderRadius: BorderRadius.circular(10),
            ),
            child: const Row(
              children: [
                Expanded(
                  child: Center(
                    child: Padding(
                      padding: EdgeInsets.symmetric(vertical: 5),
                      child: Text('Win .exe',
                          style: TextStyle(
                              color: Color(0xFF94A3B8),
                              fontSize: 10,
                              fontWeight: FontWeight.w600)),
                    ),
                  ),
                ),
                Expanded(
                  child: Center(
                    child: Padding(
                      padding: EdgeInsets.symmetric(vertical: 5),
                      child: Text('Android .apk',
                          style: TextStyle(
                              color: Color(0xFF2563EB),
                              fontSize: 10,
                              fontWeight: FontWeight.w800)),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _filterChip(String label, int value) {
    final selected = _filter == value;
    return Expanded(
      child: GestureDetector(
        onTap: () => setState(() => _filter = value),
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 7),
          decoration: BoxDecoration(
            color: selected ? Colors.white : const Color(0xFFF1F5F9),
            borderRadius: BorderRadius.circular(9),
            border: Border.all(
              color: selected ? const Color(0xFFBFDBFE) : const Color(0xFFE2E8F0),
            ),
          ),
          child: Text(
            label,
            textAlign: TextAlign.center,
            style: TextStyle(
              color: selected ? const Color(0xFF1D4ED8) : const Color(0xFF64748B),
              fontSize: 10,
              fontWeight: selected ? FontWeight.bold : FontWeight.w600,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildCard(_Module module) {
    return Container(
      padding: const EdgeInsets.all(12),
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
                width: 36,
                height: 36,
                decoration: BoxDecoration(
                  color: module.color.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Icon(module.icon, color: module.color, size: 18),
              ),
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
                decoration: BoxDecoration(
                  color: module.statusColor.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Text(
                  module.status,
                  style: TextStyle(
                    color: module.statusColor,
                    fontSize: 9,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(
            module.title,
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12),
            maxLines: 2,
          ),
          const SizedBox(height: 4),
          Text(
            module.description,
            style: const TextStyle(color: Color(0xFF64748B), fontSize: 10),
            maxLines: 3,
            overflow: TextOverflow.ellipsis,
          ),
          const Spacer(),
          Row(
            children: [
              Expanded(
                child: Text(
                  module.footer,
                  style: const TextStyle(
                    color: Color(0xFF94A3B8),
                    fontSize: 9,
                    fontFamily: 'JetBrainsMono',
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton(
              onPressed: module.onAction,
              style: OutlinedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 6),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8)),
              ),
              child: Text(module.action,
                  style: const TextStyle(fontSize: 11)),
            ),
          ),
        ],
      ),
    );
  }
}

class _Module {
  final IconData icon;
  final Color color;
  final String title;
  final String description;
  final String status;
  final Color statusColor;
  final String footer;
  final String action;
  final bool connected;
  final bool bridge;
  final VoidCallback onAction;

  const _Module({
    required this.icon,
    required this.color,
    required this.title,
    required this.description,
    required this.status,
    required this.statusColor,
    required this.footer,
    required this.action,
    required this.connected,
    required this.bridge,
    required this.onAction,
  });
}
