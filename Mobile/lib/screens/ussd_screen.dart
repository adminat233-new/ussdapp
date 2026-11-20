import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

class UssdScreen extends StatefulWidget {
  const UssdScreen({super.key});
  @override
  State<UssdScreen> createState() => _UssdScreenState();
}

class _UssdScreenState extends State<UssdScreen> {
  final _codeCtrl = TextEditingController(text: '*124#');
  final _mifiCtrl = TextEditingController(text: 'http://192.168.100.1');
  String _response = 'Ready. Enter a USSD code (e.g. *124#) or select a Quick Code above.';
  bool _loading = false;
  String _method = 'mifi';

  static const _quickCodes = [
    {'label': 'Balance', 'code': '*124#'},
    {'label': 'Registration', 'code': '*404#'},
    {'label': 'Verify', 'code': '*400#'},
    {'label': 'IMEI', 'code': '*#06#'},
    {'label': 'Customer care', 'code': '100'},
  ];

  Future<void> _send() async {
    final code = _codeCtrl.text.trim();
    if (code.isEmpty) return;
    setState(() { _loading = true; _response = 'Sending $code ...'; });
    try {
      if (_method == 'mifi') {
        final base = _mifiCtrl.text.trim().replaceAll(RegExp(r'/$'), '');
        final res = await http.post(
          Uri.parse('$base/api/ussd'),
          headers: {'Content-Type': 'application/json'},
          body: '{"code":"$code"}',
        ).timeout(const Duration(seconds: 15));
        setState(() { _response = res.statusCode == 200 ? res.body : 'HTTP ${res.statusCode}: ${res.body}'; });
      } else {
        setState(() { _response = 'USB AT mode: connect via serial port in desktop app.'; });
      }
    } catch (e) {
      setState(() { _response = 'Error: $e'; });
    } finally {
      setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Connection method
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(16), border: Border.all(color: const Color(0xFFE2E8F0))),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Connection Method', style: TextStyle(color: Color(0xFF2563EB), fontWeight: FontWeight.bold)),
                  const SizedBox(height: 10),
                  RadioListTile(value: 'mifi', groupValue: _method, onChanged: (v) => setState(() => _method = v!),
                    title: const Text('MiFi Web API (HTTP)', style: TextStyle(fontSize: 13)),
                    subtitle: const Text('Direct gateway over LAN Wi-Fi', style: TextStyle(fontSize: 11)),
                    contentPadding: EdgeInsets.zero,
                  ),
                  RadioListTile(value: 'usb', groupValue: _method, onChanged: (v) => setState(() => _method = v!),
                    title: const Text('USB Modem AT Commands', style: TextStyle(fontSize: 13)),
                    subtitle: const Text('Requires desktop app relay', style: TextStyle(fontSize: 11)),
                    contentPadding: EdgeInsets.zero,
                  ),
                  if (_method == 'mifi') TextField(controller: _mifiCtrl, decoration: const InputDecoration(labelText: 'MiFi IP', hintText: 'http://192.168.100.1')),
                ],
              ),
            ),
            const SizedBox(height: 16),
            // Quick codes
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(16), border: Border.all(color: const Color(0xFFE2E8F0))),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Quick Codes', style: TextStyle(color: Color(0xFF2563EB), fontWeight: FontWeight.bold)),
                  const SizedBox(height: 10),
                  Wrap(
                    spacing: 8, runSpacing: 8,
                    children: _quickCodes.map((qc) => GestureDetector(
                      onTap: () { _codeCtrl.text = qc['code']!; _send(); },
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                        decoration: BoxDecoration(
                          color: const Color(0xFFF8FAFC),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: const Color(0xFFE2E8F0)),
                        ),
                        child: RichText(text: TextSpan(
                          children: [
                            TextSpan(text: '${qc["label"]} ', style: const TextStyle(color: Color(0xFF374151), fontSize: 12)),
                            TextSpan(text: qc['code'], style: const TextStyle(color: Color(0xFF2563EB), fontFamily: 'JetBrainsMono', fontSize: 12)),
                          ],
                        )),
                      ),
                    )).toList(),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            // Send
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(16), border: Border.all(color: const Color(0xFFE2E8F0))),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Send USSD', style: TextStyle(color: Color(0xFF2563EB), fontWeight: FontWeight.bold)),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      Expanded(child: TextField(
                        controller: _codeCtrl,
                        style: const TextStyle(fontFamily: 'JetBrainsMono', fontWeight: FontWeight.bold, fontSize: 16),
                        decoration: const InputDecoration(hintText: '*124#'),
                        onSubmitted: (_) => _send(),
                      )),
                      const SizedBox(width: 10),
                      ElevatedButton(
                        onPressed: _loading ? null : _send,
                        child: _loading ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2)) : const Text('SEND'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 14),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(color: const Color(0xFF0F172A), borderRadius: BorderRadius.circular(12)),
                    child: Text(_response, style: const TextStyle(color: Color(0xFF4ADE80), fontFamily: 'JetBrainsMono', fontSize: 12)),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
