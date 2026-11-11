// Everything the app asks of the encryption core and the browser.
//
// The real implementation (web_backend.dart) talks to Rust compiled to
// WebAssembly through `window.messengerWeb`. Tests use a fake.

import 'models.dart';

class BackendException implements Exception {
  BackendException(this.kind, this.message);

  /// `Offline`, `Invalid`, `Relay`, `Storage`, `Busy`, `IdentityChanged`,
  /// `NotAMember`, `NotFound`, `Untrusted`, `Crypto`, `WrongPin`,
  /// `Unsupported`, `Denied`, `Locked` or `Error`.
  final String kind;
  final String message;

  @override
  String toString() => message;
}

/// Something that happened while the app was open.
sealed class LiveUpdate {}

/// The result of a sync: new messages, receipts, member changes, …
class EventsUpdate extends LiveUpdate {
  EventsUpdate(this.events);
  final List<Map<String, dynamic>> events;
}

class TypingUpdate extends LiveUpdate {
  TypingUpdate(this.chatId, this.who);
  final String chatId;

  /// `username/device`.
  final String who;
}

class ConnectionUpdate extends LiveUpdate {
  ConnectionUpdate(this.online);
  final bool online;
}

class SyncErrorUpdate extends LiveUpdate {
  SyncErrorUpdate(this.kind, this.message);
  final String kind;
  final String message;
}

LiveUpdate? parseLiveUpdate(Map<String, dynamic> j) {
  switch (j['type']) {
    case 'events':
      return EventsUpdate(
          (j['events'] as List<dynamic>? ?? const []).map((e) => e as Map<String, dynamic>).toList());
    case 'typing':
      return TypingUpdate(j['chat_id'] as String? ?? '', j['who'] as String? ?? '');
    case 'connection':
      return ConnectionUpdate(j['online'] as bool? ?? false);
    case 'sync_error':
      return SyncErrorUpdate(j['kind'] as String? ?? 'Error', j['message'] as String? ?? '');
  }
  return null;
}

abstract class Backend {
  /// Loads the core and any saved account.
  Future<StartInfo> start();

  Future<void> register({required String relay, required String invite, required String username});
  Future<void> unlock(String pin);

  /// Receives live updates for as long as the app runs.
  void listen(void Function(LiveUpdate update) onUpdate);

  Future<Me> whoami();
  Future<List<ChatSummary>> chatList();
  Future<List<ChatMessage>> history(String chatId);
  Future<List<String>> members(String chatId);
  Future<List<Contact>> contacts();
  Future<String> safetyNumber(String username);

  /// A one-time invite code for a friend.
  Future<String> invite();

  /// Starts a chat; returns its id.
  Future<String> createChat(List<String> usernames);
  Future<void> addMembers(String chatId, List<String> usernames);
  Future<void> removeMembers(String chatId, List<String> usernames);
  Future<void> removeDevices(String chatId, List<String> deviceIds);
  Future<void> rotateKeys(String chatId);
  Future<void> forgetChat(String chatId);

  Future<ChatMessage> sendText(String chatId, String text);

  /// Opens the photo picker and sends what was picked. Call it straight from
  /// a tap. Null if cancelled.
  Future<ChatMessage?> sendPhoto(String chatId);

  /// A URL the app can show the decrypted photo from.
  Future<String> photoUrl(Attachment attachment);
  Future<void> markRead(String chatId);

  void sendTyping(String chatId);
  void syncNow();

  Future<void> setDisplayName(String name);
  Future<void> setReadReceipts(bool on);

  Future<VerifyResult> verifyCode(String code);
  Future<void> markVerified(String username);
  Future<void> resetVerification(String username);

  /// Opens the camera to read a QR code. Null if cancelled.
  Future<String?> scanQr();

  Future<PushStatus> pushStatus();

  /// Asks for permission to notify (call it straight from a tap).
  Future<void> enablePush();

  Future<bool> hasPin();

  /// Sets or changes the app PIN, or removes it with null.
  Future<void> setPin(String? pin);

  /// The system share sheet, or the clipboard. Returns `shared`, `copied`
  /// or `cancelled`.
  Future<String> share(String text);

  /// The number on the Home Screen icon.
  void setBadge(int count);

  /// Deletes this account's data from this device.
  Future<void> wipe();
}
