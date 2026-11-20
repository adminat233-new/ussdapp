import 'package:flutter/material.dart';

class AppsScreen extends StatelessWidget {
  const AppsScreen({super.key});

  static const _modules = [
    {'icon': Icons.shield_outlined, 'color': 0xFF2563EB, 'title': 'Laptop Tracker', 'desc': 'Device tracking, geofencing & lost mode', 'status': 'Active', 'statusColor': 0xFF059669},
    {'icon': Icons.key_rounded, 'color': 0xFF4F46E5, 'title': 'OTP Extractor', 'desc': 'Auto-parse 2FA codes from incoming SMS', 'status': 'Enabled', 'statusColor': 0xFF059669},
    {'icon': Icons.smartphone_rounded, 'color': 0xFF059669, 'title': 'Desktop Bridge', 'desc': 'Sync with Windows .exe via LAN relay', 'status': 'LAN Ready', 'statusColor': 0xFF2563EB},
    {'icon': Icons.schedule_rounded, 'color': 0xFFD97706, 'title': 'USSD Scheduler', 'desc': 'Automated *124# balance & bundle checks', 'status': 'Standby', 'statusColor': 0xFF64748B},
    {'icon': Icons.router_rounded, 'color': 0xFF7C3AED, 'title': 'MiFi Gateway', 'desc': 'Direct router admin over LAN', 'status': 'Available', 'statusColor': 0xFF64748B},
    {'icon': Icons.smart_toy_rounded, 'color': 0xFF0EA5E9, 'title': 'AI Agent', 'desc': 'Local & cloud AI assistant for USSD/SMS', 'status': 'AI', 'statusColor': 0xFF2563EB},
  ];

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                const Expanded(child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Companion Modules', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                    Text('Integrated services & device bridges', style: TextStyle(color: Color(0xFF64748B), fontSize: 12)),
                  ],
                )),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                  decoration: BoxDecoration(color: const Color(0xFFECFDF5), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFFBBF7D0))),
                  child: const Row(
                    children: [
                      Icon(Icons.circle, color: Color(0xFF22C55E), size: 8),
                      SizedBox(width: 6),
                      Text('6 Healthy', style: TextStyle(color: Color(0xFF059669), fontSize: 11, fontWeight: FontWeight.w600)),
                    ],
                  ),
                ),
              ],
            ),
          ),
          Expanded(
            child: GridView.builder(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(crossAxisCount: 2, crossAxisSpacing: 12, mainAxisSpacing: 12, childAspectRatio: 0.9),
              itemCount: _modules.length,
              itemBuilder: (ctx, i) => _buildCard(ctx, _modules[i]),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCard(BuildContext ctx, Map m) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xFFE2E8F0)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 40, height: 40,
                decoration: BoxDecoration(color: Color(m['color'] as int).withOpacity(0.1), borderRadius: BorderRadius.circular(10)),
                child: Icon(m['icon'] as IconData, color: Color(m['color'] as int), size: 20),
              ),
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(color: Color(m['statusColor'] as int).withOpacity(0.1), borderRadius: BorderRadius.circular(20)),
                child: Text(m['status'] as String, style: TextStyle(color: Color(m['statusColor'] as int), fontSize: 10, fontWeight: FontWeight.bold)),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(m['title'] as String, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
          const SizedBox(height: 4),
          Text(m['desc'] as String, style: const TextStyle(color: Color(0xFF64748B), fontSize: 11), maxLines: 2, overflow: TextOverflow.ellipsis),
          const Spacer(),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton(
              onPressed: () {},
              style: OutlinedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 8),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
              ),
              child: const Text('Configure', style: TextStyle(fontSize: 12)),
            ),
          ),
        ],
      ),
    );
  }
}
