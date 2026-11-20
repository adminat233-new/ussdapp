import 'package:flutter_local_notifications/flutter_local_notifications.dart';

class NotificationService {
  static final _plugin = FlutterLocalNotificationsPlugin();

  static Future<void> initialize() async {
    const android = AndroidInitializationSettings('@mipmap/ic_launcher');
    const ios = DarwinInitializationSettings(requestSoundPermission: true, requestBadgePermission: true, requestAlertPermission: true);
    await _plugin.initialize(const InitializationSettings(android: android, iOS: ios));
  }

  static Future<void> showMessage(String from, String body) async {
    const details = NotificationDetails(
      android: AndroidNotificationDetails('messages', 'Messages', channelDescription: 'Incoming messages', importance: Importance.high, priority: Priority.high),
      iOS: DarwinNotificationDetails(),
    );
    await _plugin.show(from.hashCode, 'Message from #$from', body, details);
  }

  static Future<void> showIncomingCall(String from, bool video) async {
    const details = NotificationDetails(
      android: AndroidNotificationDetails('calls', 'Calls', channelDescription: 'Incoming calls', importance: Importance.max, priority: Priority.max),
      iOS: DarwinNotificationDetails(),
    );
    await _plugin.show(from.hashCode + 1000, '${video ? "Video" : "Voice"} call from #$from', 'Tap to answer', details);
  }
}
