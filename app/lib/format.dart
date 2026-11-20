// Small presentation helpers: times, names, avatars, notice wording.

import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'models.dart';

const messengerBlue = Color(0xFF0084FF);

const _weekdays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const _months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

bool _sameDay(DateTime a, DateTime b) => a.year == b.year && a.month == b.month && a.day == b.day;

String clock(BuildContext context, DateTime t) => MaterialLocalizations.of(context).formatTimeOfDay(
      TimeOfDay.fromDateTime(t),
      alwaysUse24HourFormat: MediaQuery.alwaysUse24HourFormatOf(context),
    );

/// For the chat list: "10:42", "Tue", "Nov 3", "Nov 3, 2025".
String shortTime(BuildContext context, DateTime t, {DateTime? now}) {
  final n = now ?? DateTime.now();
  if (_sameDay(t, n)) return clock(context, t);
  final days = DateTime(n.year, n.month, n.day).difference(DateTime(t.year, t.month, t.day)).inDays;
  if (days > 0 && days < 7) return _weekdays[t.weekday - 1];
  final date = '${_months[t.month - 1]} ${t.day}';
  return t.year == n.year ? date : '$date, ${t.year}';
}

/// Between messages: "10:42", "Tue 10:42", "Nov 3, 10:42".
String separatorTime(BuildContext context, DateTime t, {DateTime? now}) {
  final n = now ?? DateTime.now();
  final time = clock(context, t);
  if (_sameDay(t, n)) return time;
  final days = DateTime(n.year, n.month, n.day).difference(DateTime(t.year, t.month, t.day)).inDays;
  if (days > 0 && days < 7) return '${_weekdays[t.weekday - 1]} $time';
  final year = t.year == n.year ? '' : ' ${t.year}';
  return '${_months[t.month - 1]} ${t.day}$year, $time';
}

String initials(String name) {
  final words = name.trim().split(RegExp(r'[\s._-]+')).where((w) => w.isNotEmpty).toList();
  if (words.isEmpty) return '?';
  final first = words.first.characters.first;
  final second = words.length > 1 ? words[1].characters.first : '';
  return (first + second).toUpperCase();
}

const _avatarColors = [
  Color(0xFF0084FF),
  Color(0xFF44BEC7),
  Color(0xFFFFC300),
  Color(0xFFFA3C4C),
  Color(0xFFD696BB),
  Color(0xFF7646FF),
  Color(0xFF20CEF5),
  Color(0xFF13CF13),
  Color(0xFFFF7E29),
];

Color avatarColor(String seed) {
  var h = 0;
  for (final c in seed.codeUnits) {
    h = (h * 31 + c) & 0x7fffffff;
  }
  return _avatarColors[h % _avatarColors.length];
}

/// "Bob", "Bob and Carol", "Bob, Carol and 2 others".
String peopleList(List<String> names) {
  if (names.isEmpty) return 'no one';
  if (names.length == 1) return names.first;
  if (names.length == 2) return '${names[0]} and ${names[1]}';
  if (names.length == 3) return '${names[0]}, ${names[1]} and ${names[2]}';
  return '${names[0]}, ${names[1]} and ${names.length - 2} others';
}

/// The grey line for a notice. `nameOf` turns usernames into names.
String noticeText(ChatMessage m, String me, String Function(String username) nameOf) {
  final notice = m.notice!;
  final actor = m.senderUsername == me ? 'You' : nameOf(m.senderUsername);
  List<String> people(String key) {
    final usernames = notice.list(key).map(usernameOf).toSet().toList();
    return usernames.map((u) => u == me ? 'you' : nameOf(u)).toList();
  }

  switch (notice.type) {
    case 'joined':
      return '$actor added you';
    case 'members_changed':
      final added = people('added'), removed = people('removed');
      final parts = [
        if (added.isNotEmpty) 'added ${peopleList(added)}',
        if (removed.isNotEmpty) 'removed ${peopleList(removed)}',
      ];
      return '$actor ${parts.isEmpty ? 'changed the chat' : parts.join(' and ')}';
    case 'removed':
      return '$actor removed you from this chat';
    case 'identity_changed':
      final who = nameOf(notice.text('username'));
      return notice.flag('was_verified')
          ? "$who's security code changed. You had verified them: check with them before trusting it."
          : "$who's security code changed. Tap to verify them.";
    case 'not_your_device':
      return 'A device using your name but not your keys is in this chat';
    case 'undecryptable':
      return "A message couldn't be decrypted";
  }
  return '';
}

/// One line for the chat list.
String preview(ChatMessage? last, String me, String Function(String username) nameOf, {required bool group}) {
  if (last == null) return 'No messages yet';
  if (last.isNotice) return noticeText(last, me, nameOf);
  final who = last.outgoing ? 'You: ' : (group ? '${nameOf(last.senderUsername)}: ' : '');
  if (last.attachment != null) return '${who}sent a photo';
  return '$who${last.body.replaceAll('\n', ' ')}';
}

/// 60 digits as three lines of four groups.
String formatSafetyNumber(String number) {
  final groups = number.split(' ').where((g) => g.isNotEmpty).toList();
  final lines = <String>[];
  for (var i = 0; i < groups.length; i += 4) {
    lines.add(groups.sublist(i, math.min(i + 4, groups.length)).join('  '));
  }
  return lines.join('\n');
}

/// The username inside a verification code (`msgr1:<username>:<key>`).
String? usernameInCode(String code) {
  final parts = code.trim().split(':');
  return parts.length == 3 && parts[0] == 'msgr1' ? parts[1] : null;
}
