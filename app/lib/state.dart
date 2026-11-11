// The app's state: who I am, my chats, open chat histories, who's typing.
// Screens read it through AppScope and call its methods; it calls the
// backend and tells the screens when anything changed.

import 'dart:async';

import 'package:flutter/widgets.dart';

import 'backend.dart';
import 'models.dart';

enum Phase { loading, setup, locked, ready, busy, unsupported, failed }

class AppState extends ChangeNotifier with WidgetsBindingObserver {
  AppState(this.backend) {
    WidgetsBinding.instance.addObserver(this);
  }

  final Backend backend;

  Phase phase = Phase.loading;
  StartInfo? startInfo;
  String? startupError;
  Me? me;
  List<ChatSummary> chats = const [];
  Map<String, Contact> contacts = const {};
  bool online = true;

  /// The chat on screen, if any: its new messages are marked read.
  String? openChatId;

  final Map<String, List<ChatMessage>> _histories = {};
  final Map<String, Map<String, DateTime>> _typing = {};
  final Map<String, Future<String>> _photoUrls = {};
  final _alerts = StreamController<String>.broadcast();
  Timer? _typingTimer;
  bool _listening = false;
  bool _foreground = true;
  bool _disposed = false;

  /// Things to tell the person right away, such as a changed security code.
  Stream<String> get alerts => _alerts.stream;

  void _changed() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    WidgetsBinding.instance.removeObserver(this);
    _typingTimer?.cancel();
    _alerts.close();
    super.dispose();
  }

  // ---------------------------------------------------------------------
  // Starting up
  // ---------------------------------------------------------------------

  Future<void> start() async {
    try {
      final info = await backend.start();
      startInfo = info;
      switch (info.state) {
        case 'ready':
          await _enter();
        case 'locked':
          phase = Phase.locked;
        case 'busy':
          phase = Phase.busy;
        case 'unsupported':
          phase = Phase.unsupported;
        default:
          phase = Phase.setup;
      }
    } catch (e) {
      startupError = e.toString();
      phase = Phase.failed;
    }
    _changed();
  }

  Future<void> register({
    required String relay,
    required String invite,
    required String username,
    String? displayName,
  }) async {
    await backend.register(relay: relay, invite: invite, username: username);
    final name = displayName?.trim() ?? '';
    if (name.isNotEmpty) {
      try {
        await backend.setDisplayName(name);
      } catch (_) {
        // They can set it again in Settings.
      }
    }
    await _enter();
    _changed();
  }

  Future<void> unlock(String pin) async {
    await backend.unlock(pin);
    await _enter();
    _changed();
  }

  Future<void> _enter() async {
    if (!_listening) {
      backend.listen(_onUpdate);
      _listening = true;
    }
    me = await backend.whoami();
    await _refreshLists();
    phase = Phase.ready;
  }

  /// Deletes this account from this device and goes back to sign-up.
  Future<void> wipe() async {
    await backend.wipe();
    me = null;
    chats = const [];
    contacts = const {};
    _histories.clear();
    _photoUrls.clear();
    openChatId = null;
    phase = Phase.setup;
    _changed();
  }

  // ---------------------------------------------------------------------
  // Keeping up to date
  // ---------------------------------------------------------------------

  Future<void> _refreshLists() async {
    final results = await Future.wait<Object>([backend.chatList(), backend.contacts()]);
    chats = results[0] as List<ChatSummary>;
    contacts = {for (final c in results[1] as List<Contact>) c.username: c};
    backend.setBadge(chats.fold<int>(0, (n, c) => n + c.unread));
  }

  Future<void> refresh() async {
    await _refreshLists();
    _changed();
  }

  void _onUpdate(LiveUpdate update) {
    switch (update) {
      case EventsUpdate(:final events):
        _onEvents(events);
      case TypingUpdate(:final chatId, :final who):
        _onTyping(chatId, who);
      case ConnectionUpdate(online: final isOnline):
        online = isOnline;
        _changed();
      case SyncErrorUpdate():
        break;
    }
  }

  Future<void> _onEvents(List<Map<String, dynamic>> events) async {
    for (final e in events) {
      switch (e['type']) {
        case 'identity_changed':
          final who = nameOf(e['username'] as String? ?? 'Someone');
          _alerts.add(e['was_verified'] == true
              ? "$who's security code changed. You had verified them, so check with them before trusting it."
              : "$who's security code changed.");
        case 'not_your_device':
          _alerts.add('A device using your name, but not your keys, is in one of your chats. '
              'Open the chat to remove it.');
        case 'message':
          // Their message arrived, so they've stopped typing.
          _typing[e['chat_id']]?.remove(e['sender']);
      }
    }
    try {
      await _refreshLists();
      final open = openChatId;
      if (open != null && events.any((e) => e['chat_id'] == open)) {
        _histories[open] = await backend.history(open);
        if (_foreground && events.any((e) => e['type'] == 'message' && e['chat_id'] == open)) {
          await backend.markRead(open);
          await _refreshLists();
        }
      }
    } catch (_) {
      // The next update will try again.
    }
    _changed();
  }

  void _onTyping(String chatId, String who) {
    _typing.putIfAbsent(chatId, () => {})[who] = DateTime.now().add(const Duration(seconds: 6));
    _typingTimer ??= Timer.periodic(const Duration(seconds: 1), (_) => _expireTyping());
    _changed();
  }

  void _expireTyping() {
    final now = DateTime.now();
    var changed = false;
    for (final people in _typing.values) {
      final before = people.length;
      people.removeWhere((_, until) => until.isBefore(now));
      changed |= people.length != before;
    }
    _typing.removeWhere((_, people) => people.isEmpty);
    if (_typing.isEmpty) {
      _typingTimer?.cancel();
      _typingTimer = null;
    }
    if (changed) _changed();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState lifecycle) {
    _foreground = lifecycle == AppLifecycleState.resumed;
    if (!_foreground || phase != Phase.ready) return;
    backend.syncNow();
    final open = openChatId;
    if (open != null) _markReadIfNeeded(open);
  }

  // ---------------------------------------------------------------------
  // Reading
  // ---------------------------------------------------------------------

  ChatSummary? chatById(String chatId) {
    for (final c in chats) {
      if (c.chatId == chatId) return c;
    }
    return null;
  }

  List<ChatMessage>? historyOf(String chatId) => _histories[chatId];

  /// Usernames typing in a chat right now.
  List<String> typingIn(String chatId) => (_typing[chatId]?.keys ?? const <String>[]).map(usernameOf).toSet().toList();

  /// What to call someone: their chosen name, else their username.
  String nameOf(String username) {
    final m = me;
    if (m != null && username == m.username) return m.name;
    return contacts[username]?.name ?? username;
  }

  bool isVerified(String username) => contacts[username]?.verified ?? false;

  int get unreadTotal => chats.fold<int>(0, (n, c) => n + c.unread);

  /// A URL showing the decrypted photo; fetched once per app session.
  Future<String> photoUrl(Attachment attachment) {
    final cached = _photoUrls[attachment.blobId];
    if (cached != null) return cached;
    final url = backend.photoUrl(attachment);
    _photoUrls[attachment.blobId] = url;
    url.catchError((Object _) {
      _photoUrls.remove(attachment.blobId);
      return '';
    });
    return url;
  }

  // ---------------------------------------------------------------------
  // Chats
  // ---------------------------------------------------------------------

  Future<void> openChat(String chatId) async {
    openChatId = chatId;
    _histories[chatId] = await backend.history(chatId);
    _changed();
    await _markReadIfNeeded(chatId);
  }

  void closeChat(String chatId) {
    if (openChatId == chatId) openChatId = null;
  }

  Future<void> _markReadIfNeeded(String chatId) async {
    final chat = chatById(chatId);
    if (chat == null || chat.unread == 0) return;
    try {
      await backend.markRead(chatId);
      await _refreshLists();
      _changed();
    } catch (_) {
      // Try again next time.
    }
  }

  void _append(String chatId, ChatMessage message) {
    _histories[chatId] = [...?_histories[chatId], message];
    _changed();
  }

  Future<void> sendText(String chatId, String text) async {
    final message = await backend.sendText(chatId, text);
    _append(chatId, message);
    await refresh();
  }

  /// Call straight from a tap: it opens the photo picker.
  Future<void> sendPhoto(String chatId) async {
    final message = await backend.sendPhoto(chatId);
    if (message == null) return;
    _append(chatId, message);
    await refresh();
  }

  void typing(String chatId) => backend.sendTyping(chatId);

  Future<String> createChat(List<String> usernames) async {
    final chatId = await backend.createChat(usernames);
    await refresh();
    return chatId;
  }

  Future<void> _reload(String chatId) async {
    _histories[chatId] = await backend.history(chatId);
    await refresh();
  }

  Future<void> addMembers(String chatId, List<String> usernames) async {
    await backend.addMembers(chatId, usernames);
    await _reload(chatId);
  }

  Future<void> removeMember(String chatId, String username) async {
    await backend.removeMembers(chatId, [username]);
    await _reload(chatId);
  }

  Future<void> removeDevice(String chatId, String deviceId) async {
    await backend.removeDevices(chatId, [deviceId]);
    await _reload(chatId);
  }

  Future<void> rotateKeys(String chatId) async {
    await backend.rotateKeys(chatId);
    await _reload(chatId);
  }

  Future<void> forgetChat(String chatId) async {
    await backend.forgetChat(chatId);
    _histories.remove(chatId);
    closeChat(chatId);
    await refresh();
  }

  // ---------------------------------------------------------------------
  // Me, verification, settings
  // ---------------------------------------------------------------------

  Future<void> setDisplayName(String name) async {
    await backend.setDisplayName(name);
    me = await backend.whoami();
    await refresh();
  }

  Future<void> setReadReceipts(bool on) async {
    await backend.setReadReceipts(on);
    me = await backend.whoami();
    _changed();
  }

  Future<VerifyResult> verifyCode(String code) async {
    final result = await backend.verifyCode(code);
    await refresh();
    return result;
  }

  Future<void> markVerified(String username) async {
    await backend.markVerified(username);
    await refresh();
  }

  Future<void> resetVerification(String username) async {
    await backend.resetVerification(username);
    await refresh();
  }
}
