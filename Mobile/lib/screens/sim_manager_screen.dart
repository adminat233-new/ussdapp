import 'package:flutter/material.dart';

import '../services/device_telemetry_service.dart';

/// SIM Manager panel from the authoritative design. Real device identity is
/// read when the native host exposes it; modem-only fields that mobile OSes
/// deny to ordinary apps stay explicitly unavailable. The toggle is a clearly
/// labelled simulation, never a claim that a modem was contacted.
class SimManagerScreen extends StatefulWidget {
  const SimManagerScreen({super.key});

  @override
  State<SimManagerScreen> createState() => _SimManagerScreenState();
}

class _SimManagerScreenState extends State<SimManagerScreen> {
  final DeviceTelemetryService _telemetry = DeviceTelemetryService();
  bool _simulatedConnected = false;
  bool _loading = true;
  DeviceTelemetry? _reading;
  String _status = 'Reading available device information...';

  static const List<_Metric> _metrics = <_Metric>[
    _Metric('SIM Status', 'Ready (Active)', 'Not Inserted', true),
    _Metric('Operator', 'Telecel Ghana', '—', false),
    _Metric('Signal', '-67 dBm (4G LTE)', '—', true),
    _Metric('Network Reg', 'Registered (Home)', 'Unregistered', false),
    _Metric('Battery', '94% (AC Powered)', '—', false),
    _Metric('Phonebook', '142 SIM entries', '0 entries', false),
    _Metric('ICCID', '8923301000048291042', '—', false),
    _Metric('IMSI', '620020194827163', '—', false),
    _Metric('IMEI', '358942109482710', '—', false),
    _Metric('SIM Type', 'USIM 4G', '—', false),
    _Metric('Carrier', 'Telecel GH', '—', false),
    _Metric('SIM Slot', 'Slot 1 (Primary)', 'Slot 1 (Primary)', false),
    _Metric('Device', 'Simulation device', '—', false),
    _Metric('OS', 'Simulation OS', '—', false),
  ];

  @override
  void initState() {
    super.initState();
    _loadTelemetry();
  }

  Future<void> _loadTelemetry() async {
    if (mounted) setState(() => _loading = true);
    final reading = await _telemetry.read();
    if (!mounted) return;
    setState(() {
      _reading = reading;
      _loading = false;
      _status = reading.live
          ? 'Native telemetry is available; modem-only fields may still be denied.'
          : 'Device info only: no native SIM telemetry bridge in this build.';
    });
  }

  void _note(String message) {
    if (!mounted) return;
    setState(() => _status = message);
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _buildHeader(),
          const SizedBox(height: 14),
          _buildTelemetryGrid(),
          const SizedBox(height: 14),
          _buildAutoConfigBanner(),
        ],
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).cardColor,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xFFE2E8F0)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'SIM / MODEM INFORMATION',
            style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 4),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
            decoration: BoxDecoration(
              color: const Color(0xFFEFF6FF),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(color: const Color(0xFFBFDBFE)),
            ),
            child: const Text(
              'auto-detected & auto-configured on connect',
              style: TextStyle(
                color: Color(0xFF1D4ED8),
                fontSize: 10,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          const SizedBox(height: 6),
          const Text(
            'Real-time hardware identity, carrier registration, and SIM slot diagnostics.',
            style: TextStyle(color: Color(0xFF64748B), fontSize: 12),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: () {
                    setState(() {
                      _simulatedConnected = !_simulatedConnected;
                      _status = _simulatedConnected
                          ? 'Simulation on: example values are shown. No modem was connected.'
                          : 'Simulation off: no live modem is attached to this build.';
                    });
                  },
                  icon: const Icon(Icons.bolt_rounded, size: 16),
                  label: Text(
                    _simulatedConnected ? 'Stop Simulation' : 'Simulate Connected SIM',
                    style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
                  ),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFFECFDF5),
                    foregroundColor: const Color(0xFF047857),
                    elevation: 0,
                    padding: const EdgeInsets.symmetric(vertical: 8),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: _loadTelemetry,
                  icon: const Icon(Icons.refresh_rounded, size: 16),
                  label: const Text('Refresh Now', style: TextStyle(fontSize: 11)),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => _note(
                    'AT init (ATE0, AT+CMGF=1, AT+CNMI, AT+CLIP) runs on a connected Windows modem, not on this build.',
                  ),
                  icon: const Icon(Icons.tune_rounded, size: 16),
                  label: const Text('Reconfigure Modem',
                      style: TextStyle(fontSize: 11)),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(
            _status,
            style: const TextStyle(color: Color(0xFF64748B), fontSize: 11),
          ),
          const SizedBox(height: 4),
          Text(
            _loading
                ? 'Reading device information...'
                : 'Source: ${_reading?.source ?? 'none'}'
                    '${_simulatedConnected ? ' (displaying SIMULATION values)' : ''}',
            style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 10),
          ),
        ],
      ),
    );
  }

  Widget _buildTelemetryGrid() {
    return LayoutBuilder(
      builder: (context, constraints) {
        final columns = constraints.maxWidth >= 620 ? 3 : 2;
        return GridView.builder(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: columns,
            crossAxisSpacing: 10,
            mainAxisSpacing: 10,
            childAspectRatio: 2.1,
          ),
          itemCount: _metrics.length,
          itemBuilder: (context, index) => _metricCard(_metrics[index]),
        );
      },
    );
  }

  Widget _metricCard(_Metric metric) {
    final reported = _reading?.values[metric.label];
    final value = _simulatedConnected
        ? metric.connected
        : (_loading
            ? 'Reading...'
            : reported ?? 'Unavailable on this platform');
    final isLive = !_simulatedConnected &&
        reported != null &&
        !reported.startsWith('Unavailable') &&
        !reported.startsWith('Not exposed');
    final highlight = (_simulatedConnected && metric.highlight) || isLive
        ? const Color(0xFF059669)
        : const Color(0xFF0F172A);
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: Theme.of(context).cardColor,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0xFFE2E8F0)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(
            metric.label.toUpperCase(),
            style: const TextStyle(
              color: Color(0xFF94A3B8),
              fontSize: 9,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.7,
            ),
          ),
          const SizedBox(height: 5),
          Text(
            value,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: highlight,
              fontFamily: 'JetBrainsMono',
              fontSize: 12,
              fontWeight: FontWeight.bold,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildAutoConfigBanner() {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFFEFF6FF),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xFFBFDBFE)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 34,
            height: 34,
            decoration: BoxDecoration(
              color: const Color(0xFF2563EB),
              borderRadius: BorderRadius.circular(10),
            ),
            child: const Icon(Icons.shield_rounded, color: Colors.white, size: 18),
          ),
          const SizedBox(width: 10),
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Where modem control really runs',
                  style: TextStyle(
                    color: Color(0xFF1E3A8A),
                    fontSize: 13,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                SizedBox(height: 5),
                Text(
                  'AT init (echo off, text SMS mode, SMS notifications, caller ID) and recurring SIM identity checks run in the Windows desktop app with a physical modem. This mobile build only displays device information the OS exposes; it does not initialize a modem or read SIM/IMEI secrets.',
                  style: TextStyle(color: Color(0xFF1E40AF), fontSize: 11, height: 1.5),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _Metric {
  final String label;
  final String connected;
  final String disconnected;
  final bool highlight;

  const _Metric(this.label, this.connected, this.disconnected, this.highlight);
}
