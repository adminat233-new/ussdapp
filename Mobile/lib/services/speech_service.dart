import 'package:flutter/services.dart';

/// Text-to-speech bridge for the Agent panel.
///
/// The Dart side never claims speech happened: it reports the native result.
/// A host without the channel (or with the speech engine disabled) returns
/// false and the UI says so plainly.
class SpeechService {
  static const MethodChannel _channel =
      MethodChannel('com.ussdapp.mobile/speech');

  static Future<bool> speak(String text) async {
    final value = text.trim();
    if (value.isEmpty) return false;
    try {
      final result = await _channel.invokeMethod<bool>('speak', <String, dynamic>{
        'text': value,
      });
      return result ?? false;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  static Future<void> stop() async {
    try {
      await _channel.invokeMethod<void>('stop');
    } on MissingPluginException {
      // No native engine attached; nothing to stop.
    } on PlatformException {
      // Same: an unavailable engine is not an app error.
    }
  }
}
