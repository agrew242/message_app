// The real backend: `window.messengerWeb` (web/messenger/messenger_web.js),
// which runs the Rust core compiled to WebAssembly. Every call resolves to a
// JSON envelope: {ok: true, value} or {ok: false, kind, message}.

import 'dart:convert';
import 'dart:js_interop';

import 'backend.dart';
import 'models.dart';

@JS('messengerLoading')
external JSPromise<JSAny?>? get _loading;

@JS('messengerLoadError')
external JSString? get _loadError;

@JS('messengerWeb')
external _Glue? get _glue;

extension type _Glue._(JSObject _) implements JSObject {
  external JSPromise<JSString> start();
  external JSPromise<JSString> register(JSString relay, JSString invite, JSString username);
  external JSPromise<JSString> unlock(JSString pin);
  external JSPromise<JSString> invoke(JSString method, JSString argsJson);
  external void listen(JSFunction callback);
  external void sendTyping(JSString chatId);
  external void syncNow();
  external JSPromise<JSString> sendPhoto(JSString chatId);
  external JSPromise<JSString> photoUrl(JSString attachmentJson);
  external JSPromise<JSString> scanQr();
  external JSPromise<JSString> pushStatus();
  external JSPromise<JSString> enablePush();
  external JSPromise<JSString> hasPin();
  external JSPromise<JSString> setPin(JSString? pin);
  external JSPromise<JSString> share(JSString text);
  external void setBadge(JSNumber count);
  external JSPromise<JSString> wipe();
}

Backend createBackend() => WebBackend();

class WebBackend implements Backend {
  _Glue? _g;

  _Glue get _glueOrThrow {
    final g = _g;
    if (g == null) throw BackendException('Unsupported', "The app didn't finish loading");
    return g;
  }

  /// Unwraps an envelope: the value, or a [BackendException].
  Future<Object?> _unwrap(JSPromise<JSString> promise) async {
    final String text;
    try {
      text = (await promise.toDart).toDart;
    } catch (e) {
      throw BackendException('Error', 'Something went wrong: $e');
    }
    final env = jsonDecode(text) as Map<String, dynamic>;
    if (env['ok'] == true) return env['value'];
    throw BackendException(env['kind'] as String? ?? 'Error', env['message'] as String? ?? 'Something went wrong');
  }

  /// Calls a session method; wasm results are strings (often JSON).
  Future<Object?> _invoke(String method, [List<Object?> args = const []]) =>
      _unwrap(_glueOrThrow.invoke(method.toJS, jsonEncode(args).toJS));

  Future<dynamic> _invokeJson(String method, [List<Object?> args = const []]) async =>
      jsonDecode(await _invoke(method, args) as String);

  @override
  Future<StartInfo> start() async {
    final loading = _loading;
    if (loading != null) await loading.toDart;
    final glue = _glue;
    if (glue == null) {
      throw BackendException('Unsupported', "The app couldn't load: ${_loadError?.toDart ?? 'unknown error'}");
    }
    _g = glue;
    final value = await _unwrap(glue.start());
    return StartInfo.fromJson(value as Map<String, dynamic>);
  }

  @override
  Future<void> register({required String relay, required String invite, required String username}) =>
      _unwrap(_glueOrThrow.register(relay.toJS, invite.toJS, username.toJS));

  @override
  Future<void> unlock(String pin) => _unwrap(_glueOrThrow.unlock(pin.toJS));

  @override
  void listen(void Function(LiveUpdate update) onUpdate) {
    void handle(JSString text) {
      final update = parseLiveUpdate(jsonDecode(text.toDart) as Map<String, dynamic>);
      if (update != null) onUpdate(update);
    }

    _glueOrThrow.listen(handle.toJS);
  }

  @override
  Future<Me> whoami() async => Me.fromJson(await _invokeJson('whoami') as Map<String, dynamic>);

  @override
  Future<List<ChatSummary>> chatList() async => (await _invokeJson('chatList') as List<dynamic>)
      .map((e) => ChatSummary.fromJson(e as Map<String, dynamic>))
      .toList();

  @override
  Future<List<ChatMessage>> history(String chatId) async => (await _invokeJson('history', [chatId]) as List<dynamic>)
      .map((e) => ChatMessage.fromJson(e as Map<String, dynamic>))
      .toList();

  @override
  Future<List<String>> members(String chatId) async =>
      (await _invokeJson('members', [chatId]) as List<dynamic>).map((e) => e.toString()).toList();

  @override
  Future<List<Contact>> contacts() async => (await _invokeJson('contacts') as List<dynamic>)
      .map((e) => Contact.fromJson(e as Map<String, dynamic>))
      .toList();

  @override
  Future<String> safetyNumber(String username) async => await _invoke('safetyNumber', [username]) as String;

  @override
  Future<String> invite() async => await _invoke('invite') as String;

  @override
  Future<String> createChat(List<String> usernames) async =>
      await _invoke('createChat', [jsonEncode(usernames)]) as String;

  @override
  Future<void> addMembers(String chatId, List<String> usernames) =>
      _invoke('addMembers', [chatId, jsonEncode(usernames)]);

  @override
  Future<void> removeMembers(String chatId, List<String> usernames) =>
      _invoke('removeMembers', [chatId, jsonEncode(usernames)]);

  @override
  Future<void> removeDevices(String chatId, List<String> deviceIds) =>
      _invoke('removeDevices', [chatId, jsonEncode(deviceIds)]);

  @override
  Future<void> rotateKeys(String chatId) => _invoke('rotateKeys', [chatId]);

  @override
  Future<void> forgetChat(String chatId) => _invoke('forgetChat', [chatId]);

  @override
  Future<ChatMessage> sendText(String chatId, String text) async =>
      ChatMessage.fromJson(await _invokeJson('sendText', [chatId, text]) as Map<String, dynamic>);

  @override
  Future<ChatMessage?> sendPhoto(String chatId) async {
    final value = await _unwrap(_glueOrThrow.sendPhoto(chatId.toJS));
    return value == null ? null : ChatMessage.fromJson(value as Map<String, dynamic>);
  }

  @override
  Future<String> photoUrl(Attachment attachment) async =>
      await _unwrap(_glueOrThrow.photoUrl(jsonEncode(attachment.json).toJS)) as String;

  @override
  Future<void> markRead(String chatId) => _invoke('markRead', [chatId]);

  @override
  void sendTyping(String chatId) => _g?.sendTyping(chatId.toJS);

  @override
  void syncNow() => _g?.syncNow();

  @override
  Future<void> setDisplayName(String name) => _invoke('setDisplayName', [name]);

  @override
  Future<void> setReadReceipts(bool on) => _invoke('setReadReceipts', [on]);

  @override
  Future<VerifyResult> verifyCode(String code) async =>
      await _invoke('verifyCode', [code]) == 'verified' ? VerifyResult.verified : VerifyResult.mismatch;

  @override
  Future<void> markVerified(String username) => _invoke('markVerified', [username]);

  @override
  Future<void> resetVerification(String username) => _invoke('resetVerification', [username]);

  @override
  Future<String?> scanQr() async => await _unwrap(_glueOrThrow.scanQr()) as String?;

  @override
  Future<PushStatus> pushStatus() async =>
      PushStatus.fromJson(await _unwrap(_glueOrThrow.pushStatus()) as Map<String, dynamic>);

  @override
  Future<void> enablePush() => _unwrap(_glueOrThrow.enablePush());

  @override
  Future<bool> hasPin() async => await _unwrap(_glueOrThrow.hasPin()) == true;

  @override
  Future<void> setPin(String? pin) => _unwrap(_glueOrThrow.setPin(pin?.toJS));

  @override
  Future<String> share(String text) async => await _unwrap(_glueOrThrow.share(text.toJS)) as String;

  @override
  void setBadge(int count) => _g?.setBadge(count.toJS);

  @override
  Future<void> wipe() => _unwrap(_glueOrThrow.wipe());
}
