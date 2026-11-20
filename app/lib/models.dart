// What the app shows, parsed from the encryption core's JSON.

/// `alice/1f2e…` → `alice`
String usernameOf(String identity) {
  final i = identity.indexOf('/');
  return i < 0 ? identity : identity.substring(0, i);
}

/// `alice/1f2e…` → `1f2e…`
String deviceOf(String identity) {
  final i = identity.indexOf('/');
  return i < 0 ? identity : identity.substring(i + 1);
}

List<String> _strings(Object? value) =>
    (value as List<dynamic>? ?? const []).map((e) => e.toString()).toList();

int _int(Object? value) => (value as num?)?.toInt() ?? 0;

/// How the app found things when it started.
class StartInfo {
  StartInfo({
    required this.state,
    required this.relay,
    required this.ios,
    required this.standalone,
    required this.pushSupported,
  });

  /// `new`, `locked`, `ready`, `busy` (open in another tab) or `unsupported`.
  final String state;

  /// The relay's address from the site's config, if any.
  final String relay;
  final bool ios;

  /// Running from the Home Screen rather than in a browser tab.
  final bool standalone;
  final bool pushSupported;

  factory StartInfo.fromJson(Map<String, dynamic> j) => StartInfo(
        state: j['state'] as String? ?? 'new',
        relay: j['relay'] as String? ?? '',
        ios: j['ios'] as bool? ?? false,
        standalone: j['standalone'] as bool? ?? false,
        pushSupported: j['push'] as bool? ?? false,
      );
}

class Me {
  Me({
    required this.username,
    required this.identity,
    required this.displayName,
    required this.verificationCode,
    required this.relayUrl,
    required this.readReceipts,
  });

  final String username;
  final String identity;
  final String? displayName;

  /// What this person's QR code says.
  final String verificationCode;
  final String relayUrl;
  final bool readReceipts;

  String get name => displayName ?? username;

  factory Me.fromJson(Map<String, dynamic> j) => Me(
        username: j['username'] as String,
        identity: j['identity'] as String,
        displayName: j['display_name'] as String?,
        verificationCode: j['verification_code'] as String,
        relayUrl: j['relay_url'] as String? ?? '',
        readReceipts: (j['settings'] as Map<String, dynamic>?)?['read_receipts'] as bool? ?? true,
      );
}

/// An encrypted photo on the relay. The raw JSON goes back to the core to
/// download and decrypt it.
class Attachment {
  Attachment(this.json);
  final Map<String, dynamic> json;

  String get blobId => json['blob_id'] as String? ?? '';
  String get mime => json['mime'] as String? ?? 'image/jpeg';
  int get size => _int(json['size']);
  int? get width => (json['width'] as num?)?.toInt();
  int? get height => (json['height'] as num?)?.toInt();

  /// A tiny preview, as a `data:` URL.
  String? get thumbnail => json['thumbnail'] as String?;

  double get aspectRatio {
    final w = width, h = height;
    if (w == null || h == null || w <= 0 || h <= 0) return 4 / 3;
    final ratio = w / h;
    return ratio < 0.5 ? 0.5 : (ratio > 2.0 ? 2.0 : ratio);
  }
}

/// A grey line in a chat: someone joined, a key changed, …
class Notice {
  Notice(this.json);
  final Map<String, dynamic> json;

  /// `joined`, `members_changed`, `removed`, `identity_changed`,
  /// `not_your_device` or `undecryptable`.
  String get type => json['type'] as String? ?? '';
  List<String> list(String key) => _strings(json[key]);
  String text(String key) => json[key] as String? ?? '';
  bool flag(String key) => json[key] as bool? ?? false;
}

class ChatMessage {
  ChatMessage({
    required this.id,
    required this.chatId,
    required this.sender,
    required this.body,
    required this.attachment,
    required this.sentAtMs,
    required this.outgoing,
    required this.deliveredTo,
    required this.readBy,
    required this.read,
    required this.notice,
  });

  final String id;
  final String chatId;

  /// `username/device` of who sent it (or caused it, for notices).
  final String sender;

  /// The text, or a photo's caption.
  final String body;
  final Attachment? attachment;
  final int sentAtMs;
  final bool outgoing;
  final List<String> deliveredTo;
  final List<String> readBy;
  final bool read;
  final Notice? notice;

  DateTime get time => DateTime.fromMillisecondsSinceEpoch(sentAtMs);
  String get senderUsername => usernameOf(sender);
  bool get isNotice => notice != null;

  factory ChatMessage.fromJson(Map<String, dynamic> j) => ChatMessage(
        id: j['id'] as String,
        chatId: j['chat_id'] as String,
        sender: j['sender'] as String? ?? '',
        body: j['body'] as String? ?? '',
        attachment: j['attachment'] == null ? null : Attachment(j['attachment'] as Map<String, dynamic>),
        sentAtMs: _int(j['sent_at_ms']),
        outgoing: j['outgoing'] as bool? ?? false,
        deliveredTo: _strings(j['delivered_to']),
        readBy: _strings(j['read_by']),
        read: j['read'] as bool? ?? true,
        notice: j['notice'] == null ? null : Notice(j['notice'] as Map<String, dynamic>),
      );
}

class ChatSummary {
  ChatSummary({
    required this.chatId,
    required this.active,
    required this.members,
    required this.title,
    required this.last,
    required this.unread,
  });

  final String chatId;

  /// False once you've been removed.
  final bool active;

  /// Everyone in it, as `username/device`.
  final List<String> members;
  final String title;
  final ChatMessage? last;
  final int unread;

  /// Distinct usernames other than `me`.
  List<String> others(String me) => members.map(usernameOf).where((u) => u != me).toSet().toList();

  factory ChatSummary.fromJson(Map<String, dynamic> j) => ChatSummary(
        chatId: j['chat_id'] as String,
        active: j['active'] as bool? ?? true,
        members: _strings(j['members']),
        title: j['title'] as String? ?? '',
        last: j['last'] == null ? null : ChatMessage.fromJson(j['last'] as Map<String, dynamic>),
        unread: _int(j['unread']),
      );
}

class Contact {
  Contact({required this.username, required this.verified, required this.displayName});

  final String username;

  /// Confirmed in person (or by comparing safety numbers).
  final bool verified;
  final String? displayName;

  String get name => displayName ?? username;

  factory Contact.fromJson(Map<String, dynamic> j) => Contact(
        username: j['username'] as String,
        verified: j['verified'] as bool? ?? false,
        displayName: j['display_name'] as String?,
      );
}

enum VerifyResult { verified, mismatch }

class PushStatus {
  PushStatus({required this.supported, required this.permission, required this.standalone, required this.ios});

  final bool supported;

  /// `default`, `granted`, `denied` or `unsupported`.
  final String permission;
  final bool standalone;
  final bool ios;

  bool get on => permission == 'granted';

  factory PushStatus.fromJson(Map<String, dynamic> j) => PushStatus(
        supported: j['supported'] as bool? ?? false,
        permission: j['permission'] as String? ?? 'unsupported',
        standalone: j['standalone'] as bool? ?? false,
        ios: j['ios'] as bool? ?? false,
      );
}
