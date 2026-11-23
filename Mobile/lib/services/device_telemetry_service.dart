import 'dart:io';

import 'package:device_info_plus/device_info_plus.dart';
import 'package:flutter/services.dart';

/// A single telemetry reading. `live` describes the source, not the values:
/// most phone OSes deny ICCID/IMSI/IMEI to ordinary apps, so those fields are
/// explicitly marked unavailable rather than filled with invented numbers.
class DeviceTelemetry {
  final Map<String, String> values;
  final String source;
  final bool live;

  const DeviceTelemetry({
    required this.values,
    required this.source,
    required this.live,
  });

  String value(String key, String fallback) => values[key] ?? fallback;
}

class DeviceTelemetryService {
  static const MethodChannel _channel =
      MethodChannel('com.ussdapp.mobile/telemetry');

  static const List<String> keys = <String>[
    'SIM Status',
    'Operator',
    'Signal',
    'Network Reg',
    'Battery',
    'Phonebook',
    'ICCID',
    'IMSI',
    'IMEI',
    'SIM Type',
    'Carrier',
    'SIM Slot',
  ];

  Future<DeviceTelemetry> read() async {
    final values = <String, String>{};
    for (final key in keys) {
      values[key] = 'Unavailable on this platform';
    }
    final sources = <String>[];

    try {
      final info = DeviceInfoPlugin();
      if (Platform.isAndroid) {
        final android = await info.androidInfo;
        values['IMEI'] = 'Not exposed to normal Android apps';
        values['Device'] = '${android.brand} ${android.model}';
        values['OS'] = 'Android ${android.version.release}';
        sources.add('device_info_plus');
      } else if (Platform.isIOS) {
        final ios = await info.iosInfo;
        values['IMEI'] = 'Not exposed to iOS apps';
        values['Device'] = ios.model;
        values['OS'] = 'iOS ${ios.systemVersion}';
        sources.add('device_info_plus');
      }
    } catch (_) {
      // The native telemetry channel may still supply real values.
    }

    try {
      final native = await _channel.invokeMethod<Map<dynamic, dynamic>>(
        'getTelemetry',
      );
      if (native != null) {
        native.forEach((key, value) {
          final name = key.toString();
          if (values.containsKey(name) || keys.contains(name)) {
            values[name] = value?.toString() ?? 'Unavailable';
          }
        });
        sources.add('native');
      }
    } on MissingPluginException {
      sources.add('device info only');
    } on PlatformException catch (e) {
      sources.add('native denied: ${e.code}');
    }

    return DeviceTelemetry(
      values: values,
      source: sources.join(' + '),
      live: sources.contains('native'),
    );
  }
}
