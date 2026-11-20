// Screen-level tests against an in-memory fake of the encryption core.

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:messenger/app.dart';
import 'package:messenger/backend.dart';
import 'package:messenger/models.dart';

const _bob = 'bob/b0b';
const _alice = 'alice/a11ce';

ChatMessage _msg(String id, String text, {bool outgoing = false, int minutesAgo = 5, Map<String, dynamic>? notice}) {
  return ChatMessage.fromJson({
    'id': id,
    'chat_id': 'c1',
    'sender': outgoing ? _alice : _bob,
    'body': text,
    'sent_at_ms': DateTime.now().subtract(Duration(minutes: minutesAgo)).millisecondsSinceEpoch,
    'outgoing': outgoing,
    'delivered_to': outgoing ? [_bob] : <String>[],
    'read_by': <String>[],
    'read': outgoing,
    if (notice != null) 'notice': notice,
  });
}

class FakeBackend implements Backend {
  FakeBackend({this.state = 'ready', this.pin});

  String state;
  final String? pin;
  void Function(LiveUpdate update)? listener;
  final calls = <String>[];
  final messages = <ChatMessage>[];
  bool registered = false;
  int unread = 0;

  void emit(LiveUpdate update) => listener?.call(update);

  @override
  Future<StartInfo> start() async =>
      StartInfo(state: state, relay: 'https://relay.test', ios: false, standalone: false, pushSupported: true);

  @override
  Future<void> register({required String relay, required String invite, required String username}) async {
    calls.add('register $username $invite $relay');
    registered = true;
  }

  @override
  Future<void> unlock(String pin) async {
    if (pin != this.pin) throw BackendException('WrongPin', "That PIN isn't right");
  }

  @override
  void listen(void Function(LiveUpdate update) onUpdate) => listener = onUpdate;

  @override
  Future<Me> whoami() async => Me(
        username: 'alice',
        identity: _alice,
        displayName: 'Alice',
        verificationCode: 'msgr1:alice:AAAA',
        relayUrl: 'https://relay.test',
        readReceipts: true,
      );

  @override
  Future<List<ChatSummary>> chatList() async => messages.isEmpty
      ? []
      : [
          ChatSummary(
            chatId: 'c1',
            active: true,
            members: [_alice, _bob],
            title: 'Bobby',
            last: messages.last,
            unread: unread,
          ),
        ];

  @override
  Future<List<ChatMessage>> history(String chatId) async => List.of(messages);

  @override
  Future<List<String>> members(String chatId) async => [_alice, _bob];

  @override
  Future<List<Contact>> contacts() async => [Contact(username: 'bob', verified: false, displayName: 'Bobby')];

  @override
  Future<String> safetyNumber(String username) async => List.filled(12, '12345').join(' ');

  @override
  Future<String> invite() async => 'INVITE-123';

  @override
  Future<String> createChat(List<String> usernames) async => 'c1';

  @override
  Future<void> addMembers(String chatId, List<String> usernames) async {}

  @override
  Future<void> removeMembers(String chatId, List<String> usernames) async {}

  @override
  Future<void> removeDevices(String chatId, List<String> deviceIds) async {}

  @override
  Future<void> rotateKeys(String chatId) async {}

  @override
  Future<void> forgetChat(String chatId) async => messages.clear();

  @override
  Future<ChatMessage> sendText(String chatId, String text) async {
    calls.add('send $text');
    final m = _msg('m${messages.length}', text, outgoing: true, minutesAgo: 0);
    messages.add(m);
    return m;
  }

  @override
  Future<ChatMessage?> sendPhoto(String chatId) async => null;

  @override
  Future<String> photoUrl(Attachment attachment) => Completer<String>().future;

  @override
  Future<void> markRead(String chatId) async {
    calls.add('read $chatId');
    unread = 0;
  }

  @override
  void sendTyping(String chatId) => calls.add('typing');

  @override
  void syncNow() {}

  @override
  Future<void> setDisplayName(String name) async => calls.add('name $name');

  @override
  Future<void> setReadReceipts(bool on) async {}

  @override
  Future<VerifyResult> verifyCode(String code) async => VerifyResult.verified;

  @override
  Future<void> markVerified(String username) async {}

  @override
  Future<void> resetVerification(String username) async {}

  @override
  Future<String?> scanQr() async => null;

  @override
  Future<PushStatus> pushStatus() async =>
      PushStatus(supported: true, permission: 'default', standalone: false, ios: false);

  @override
  Future<void> enablePush() async {}

  @override
  Future<bool> hasPin() async => pin != null;

  @override
  Future<void> setPin(String? pin) async {}

  @override
  Future<String> share(String text) async => 'copied';

  @override
  void setBadge(int count) {}

  @override
  Future<void> wipe() async {}
}

/// An iPhone-sized screen (390 x 844 points).
void _phone(WidgetTester tester) {
  tester.view.physicalSize = const Size(1170, 2532);
  tester.view.devicePixelRatio = 3.0;
  addTearDown(tester.view.reset);
}

Future<void> _tap(WidgetTester tester, Finder finder) async {
  await tester.ensureVisible(finder);
  await tester.pumpAndSettle();
  await tester.tap(finder);
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('signing up lands on an empty chat list', (tester) async {
    _phone(tester);
    final backend = FakeBackend(state: 'new');
    await tester.pumpWidget(MessengerApp(backend: backend));
    await tester.pumpAndSettle();
    expect(find.text('Welcome to Messenger'), findsOneWidget);

    await tester.enterText(find.widgetWithText(TextField, 'Your name'), 'Alice');
    await tester.enterText(find.widgetWithText(TextField, 'Username'), 'Alice');
    await tester.enterText(find.widgetWithText(TextField, 'Invite code'), ' CODE1 ');
    await _tap(tester, find.text('Create account'));

    expect(backend.calls, contains('register alice CODE1 https://relay.test'));
    expect(backend.calls, contains('name Alice'));
    expect(find.text('No chats yet'), findsOneWidget);
  });

  testWidgets('bad usernames are caught before anything is sent', (tester) async {
    _phone(tester);
    final backend = FakeBackend(state: 'new');
    await tester.pumpWidget(MessengerApp(backend: backend));
    await tester.pumpAndSettle();
    await tester.enterText(find.widgetWithText(TextField, 'Username'), 'no spaces allowed');
    await tester.enterText(find.widgetWithText(TextField, 'Invite code'), 'CODE1');
    await _tap(tester, find.text('Create account'));
    expect(find.textContaining('Usernames are 3 to 32'), findsOneWidget);
    expect(backend.registered, isFalse);
  });

  testWidgets('a wrong PIN is refused and the right one unlocks', (tester) async {
    _phone(tester);
    final backend = FakeBackend(state: 'locked', pin: '123456');
    await tester.pumpWidget(MessengerApp(backend: backend));
    await tester.pumpAndSettle();
    expect(find.text('Enter your PIN'), findsOneWidget);

    await tester.enterText(find.byType(TextField), '000000');
    await tester.tap(find.text('Unlock'));
    await tester.pumpAndSettle();
    expect(find.text("That PIN isn't right."), findsOneWidget);

    await tester.enterText(find.byType(TextField), '123456');
    await tester.tap(find.text('Unlock'));
    await tester.pumpAndSettle();
    expect(find.text('Chats'), findsOneWidget);
  });

  testWidgets('chats show previews, open, mark read and send', (tester) async {
    _phone(tester);
    final backend = FakeBackend()
      ..messages.addAll([
        _msg('n0', '', minutesAgo: 30, notice: {'type': 'joined', 'members': [_alice, _bob]}),
        _msg('m0', 'hi alice', minutesAgo: 10),
      ])
      ..unread = 1;
    await tester.pumpWidget(MessengerApp(backend: backend));
    await tester.pumpAndSettle();

    expect(find.text('Bobby'), findsOneWidget);
    expect(find.text('hi alice'), findsOneWidget);
    expect(find.text('1'), findsOneWidget); // unread badge

    await tester.tap(find.text('Bobby'));
    await tester.pumpAndSettle();
    expect(backend.calls, contains('read c1'));
    expect(find.text('Bobby added you'), findsOneWidget);
    expect(find.text('hi alice'), findsOneWidget);

    await tester.enterText(find.widgetWithText(TextField, 'Message'), 'hey bob');
    await tester.pump(); // the Send button wakes up once there's text
    expect(backend.calls, contains('typing'));
    await _tap(tester, find.byTooltip('Send'));
    expect(backend.calls, contains('send hey bob'));
    expect(find.text('hey bob'), findsOneWidget);
    expect(find.text('Delivered'), findsOneWidget);

    // Bob starts typing.
    backend.emit(TypingUpdate('c1', _bob));
    await tester.pump();
    expect(find.text('typing…'), findsOneWidget);
    expect(find.text('•••'), findsOneWidget);
  });

  testWidgets('a changed security code is announced', (tester) async {
    _phone(tester);
    final backend = FakeBackend()..messages.add(_msg('m0', 'hello'));
    await tester.pumpWidget(MessengerApp(backend: backend));
    await tester.pumpAndSettle();
    backend.emit(EventsUpdate([
      {'type': 'identity_changed', 'chat_id': 'c1', 'username': 'bob', 'was_verified': true},
    ]));
    await tester.pumpAndSettle();
    expect(find.textContaining("Bobby's security code changed"), findsOneWidget);
  });

  testWidgets('the verify screen shows a code and the safety number', (tester) async {
    _phone(tester);
    final backend = FakeBackend()..messages.add(_msg('m0', 'hello'));
    await tester.pumpWidget(MessengerApp(backend: backend));
    await tester.pumpAndSettle();
    await _tap(tester, find.text('Bobby'));
    await _tap(tester, find.byTooltip('Chat details'));
    await _tap(tester, find.text('@bob · not verified'));
    expect(find.text('Verify Bobby'), findsOneWidget);
    final matchButton = find.text('We compared: the numbers match');
    await tester.scrollUntilVisible(matchButton, 200, scrollable: find.byType(Scrollable).first);
    expect(find.textContaining('12345  12345  12345  12345'), findsOneWidget);
    expect(matchButton, findsOneWidget);
  });
}
