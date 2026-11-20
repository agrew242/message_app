// A conversation: bubbles, photos, grey notices, typing dots, and the
// composer.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../app.dart';
import '../backend.dart';
import '../format.dart';
import '../models.dart';
import '../state.dart';
import '../widgets.dart';
import 'chat_info.dart';
import 'verify.dart';

class ChatScreen extends StatefulWidget {
  const ChatScreen({super.key, required this.chatId});

  final String chatId;

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _text = TextEditingController();
  final _focus = FocusNode();
  AppState? _state;
  bool _sending = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_state == null) {
      _state = AppScope.read(context);
      _state!.openChat(widget.chatId);
    }
  }

  @override
  void dispose() {
    _state?.closeChat(widget.chatId);
    _text.dispose();
    _focus.dispose();
    super.dispose();
  }

  Future<void> _send() async {
    final text = _text.text;
    if (text.trim().isEmpty || _sending) return;
    setState(() => _sending = true);
    _text.clear();
    try {
      await _state!.sendText(widget.chatId, text);
    } catch (e) {
      _text.text = text;
      if (mounted) showError(context, e);
    } finally {
      if (mounted) {
        setState(() => _sending = false);
        _focus.requestFocus();
      }
    }
  }

  /// Runs straight from the tap: the browser only opens pickers then.
  void _sendPhoto() {
    final sending = _state!.sendPhoto(widget.chatId);
    sending.catchError((Object e) {
      if (mounted) showError(context, e);
    });
  }

  void _openInfo() {
    Navigator.push(context, MaterialPageRoute<void>(builder: (_) => ChatInfoScreen(chatId: widget.chatId)));
  }

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final me = state.me!;
    final chat = state.chatById(widget.chatId);
    final history = state.historyOf(widget.chatId);
    final others = chat?.others(me.username) ?? const <String>[];
    final group = others.length > 1;
    final typing = state.typingIn(widget.chatId);
    final theme = Theme.of(context);

    String subtitle;
    if (typing.isNotEmpty) {
      subtitle = group ? '${peopleList(typing.map(state.nameOf).toList())} typing…' : 'typing…';
    } else if (group) {
      subtitle = '${others.length + 1} people';
    } else if (others.length == 1 && state.isVerified(others.first)) {
      subtitle = 'Verified';
    } else {
      subtitle = 'End-to-end encrypted';
    }

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: InkWell(
          onTap: _openInfo,
          child: Row(
            children: [
              Avatar(
                name: chat?.title ?? '',
                seed: others.isEmpty ? me.username : others.join(','),
                size: 36,
                verified: !group && others.length == 1 && state.isVerified(others.first),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(chat?.title ?? '', maxLines: 1, overflow: TextOverflow.ellipsis),
                    Text(
                      subtitle,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        actions: [
          IconButton(tooltip: 'Chat details', icon: const Icon(Icons.info_outline), onPressed: _openInfo),
        ],
      ),
      body: Column(
        children: [
          if (!state.online) const ConnectingBanner(),
          Expanded(
            child: history == null
                ? const Center(child: CircularProgressIndicator())
                : _MessageList(chatId: widget.chatId, history: history, group: group, typing: typing),
          ),
          if (chat == null || chat.active)
            _Composer(
              controller: _text,
              focus: _focus,
              sending: _sending,
              onSend: _send,
              onPhoto: _sendPhoto,
              onTyping: () => state.typing(widget.chatId),
            )
          else
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              color: theme.colorScheme.surfaceContainerHighest,
              child: const SafeArea(
                top: false,
                child: Text("You're no longer in this chat.", textAlign: TextAlign.center),
              ),
            ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// The message list
// ---------------------------------------------------------------------------

sealed class _Row {}

class _TimeRow extends _Row {
  _TimeRow(this.time);
  final DateTime time;
}

class _NoticeRow extends _Row {
  _NoticeRow(this.message);
  final ChatMessage message;
}

class _MessageRow extends _Row {
  _MessageRow(this.message, {required this.first, required this.last, required this.status});
  final ChatMessage message;

  /// First and last of a run from the same sender: shapes the corners.
  final bool first;
  final bool last;

  /// Sent / Delivered / Seen, under our newest message.
  final String? status;
}

class _TypingRow extends _Row {}

const _gap = Duration(minutes: 15);

List<_Row> _rows(List<ChatMessage> history, String Function(String) nameOf, {required bool group}) {
  var lastOutgoing = -1;
  for (var i = history.length - 1; i >= 0; i--) {
    if (history[i].outgoing && !history[i].isNotice) {
      lastOutgoing = i;
      break;
    }
  }
  bool sameRun(ChatMessage a, ChatMessage? b) =>
      b != null && !b.isNotice && b.sender == a.sender && b.time.difference(a.time).abs() < _gap;

  final rows = <_Row>[];
  ChatMessage? prev;
  for (var i = 0; i < history.length; i++) {
    final m = history[i];
    if (prev == null || m.time.difference(prev.time) >= _gap) rows.add(_TimeRow(m.time));
    if (m.isNotice) {
      rows.add(_NoticeRow(m));
    } else {
      final next = i + 1 < history.length ? history[i + 1] : null;
      String? status;
      if (i == lastOutgoing) {
        if (m.readBy.isNotEmpty) {
          status = group ? 'Seen by ${peopleList(m.readBy.map(usernameOf).toSet().map(nameOf).toList())}' : 'Seen';
        } else {
          status = m.deliveredTo.isNotEmpty ? 'Delivered' : 'Sent';
        }
      }
      rows.add(_MessageRow(m, first: !sameRun(m, prev), last: !sameRun(m, next), status: status));
    }
    prev = m;
  }
  return rows;
}

class _MessageList extends StatelessWidget {
  const _MessageList({required this.chatId, required this.history, required this.group, required this.typing});

  final String chatId;
  final List<ChatMessage> history;
  final bool group;
  final List<String> typing;

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final rows = _rows(history, state.nameOf, group: group);
    if (typing.isNotEmpty) rows.add(_TypingRow());
    if (rows.isEmpty) {
      return const Center(child: Text('Say hi! Messages here are end-to-end encrypted.'));
    }
    return ListView.builder(
      reverse: true,
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 12),
      itemCount: rows.length,
      itemBuilder: (context, i) {
        final row = rows[rows.length - 1 - i];
        if (row is _TimeRow) return _TimeLabel(time: row.time);
        if (row is _NoticeRow) return _NoticeLine(chatId: chatId, message: row.message);
        if (row is _MessageRow) return _Bubble(row: row, group: group);
        return _TypingBubble(who: typing.first);
      },
    );
  }
}

class _TimeLabel extends StatelessWidget {
  const _TimeLabel({required this.time});

  final DateTime time;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 12),
      child: Text(
        separatorTime(context, time),
        textAlign: TextAlign.center,
        style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
      ),
    );
  }
}

class _NoticeLine extends StatelessWidget {
  const _NoticeLine({required this.chatId, required this.message});

  final String chatId;
  final ChatMessage message;

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final theme = Theme.of(context);
    final notice = message.notice!;
    final warning = notice.type == 'identity_changed' || notice.type == 'not_your_device';
    Widget? action;
    if (notice.type == 'identity_changed') {
      final username = notice.text('username');
      action = TextButton(
        onPressed: () =>
            Navigator.push(context, MaterialPageRoute<void>(builder: (_) => VerifyScreen(username: username))),
        child: const Text('Verify'),
      );
    } else if (notice.type == 'not_your_device') {
      final member = notice.text('member');
      final stillThere = state.chatById(chatId)?.members.contains(member) ?? false;
      if (stillThere) {
        action = TextButton(
          onPressed: () async {
            try {
              await state.removeDevice(chatId, deviceOf(member));
            } catch (e) {
              if (context.mounted) showError(context, e);
            }
          },
          child: const Text('Remove it'),
        );
      }
    }
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 24),
      child: Column(
        children: [
          Text(
            noticeText(message, state.me!.username, state.nameOf),
            textAlign: TextAlign.center,
            style: theme.textTheme.bodySmall?.copyWith(
              color: warning ? theme.colorScheme.error : theme.colorScheme.onSurfaceVariant,
            ),
          ),
          if (action != null) action,
        ],
      ),
    );
  }
}

class _Bubble extends StatelessWidget {
  const _Bubble({required this.row, required this.group});

  final _MessageRow row;
  final bool group;

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final theme = Theme.of(context);
    final m = row.message;
    final out = m.outgoing;
    final dark = theme.brightness == Brightness.dark;
    final background = out ? messengerBlue : (dark ? const Color(0xFF3A3B3C) : const Color(0xFFF0F2F5));
    final foreground = out ? Colors.white : theme.colorScheme.onSurface;
    const big = Radius.circular(18), small = Radius.circular(4);
    final radius = BorderRadius.only(
      topLeft: !out && !row.first ? small : big,
      bottomLeft: !out && !row.last ? small : big,
      topRight: out && !row.first ? small : big,
      bottomRight: out && !row.last ? small : big,
    );
    final maxWidth = MediaQuery.sizeOf(context).width * 0.72;
    final name = state.nameOf(m.senderUsername);

    Widget content;
    final attachment = m.attachment;
    if (attachment != null) {
      content = _Photo(attachment: attachment, caption: m.body, radius: radius, outgoing: out);
    } else {
      content = Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(color: background, borderRadius: radius),
        child: Text(m.body, style: TextStyle(color: foreground, fontSize: 16)),
      );
    }

    return Padding(
      padding: EdgeInsets.only(top: row.first ? 6 : 1, bottom: row.status != null ? 0 : 1),
      child: Column(
        crossAxisAlignment: out ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          if (group && !out && row.first)
            Padding(
              padding: const EdgeInsets.only(left: 48, bottom: 2),
              child: Text(name, style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant)),
            ),
          Row(
            mainAxisAlignment: out ? MainAxisAlignment.end : MainAxisAlignment.start,
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              if (!out) ...[
                SizedBox(width: 30, child: row.last ? Avatar(name: name, seed: m.senderUsername, size: 30) : null),
                const SizedBox(width: 8),
              ],
              ConstrainedBox(
                constraints: BoxConstraints(maxWidth: maxWidth),
                child: Tooltip(message: clock(context, m.time), child: content),
              ),
            ],
          ),
          if (row.status != null)
            Padding(
              padding: const EdgeInsets.only(top: 2, right: 4),
              child: Text(
                row.status!,
                style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
              ),
            ),
        ],
      ),
    );
  }
}

Uint8List? _decodeThumbnail(String? dataUrl) {
  if (dataUrl == null) return null;
  try {
    return base64Decode(dataUrl.substring(dataUrl.indexOf(',') + 1));
  } catch (_) {
    return null;
  }
}

class _Photo extends StatelessWidget {
  const _Photo({required this.attachment, required this.caption, required this.radius, required this.outgoing});

  final Attachment attachment;
  final String caption;
  final BorderRadius radius;
  final bool outgoing;

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final theme = Theme.of(context);
    final thumbnail = _decodeThumbnail(attachment.thumbnail);
    final picture = ClipRRect(
      borderRadius: radius,
      child: SizedBox(
        width: 240,
        child: AspectRatio(
          aspectRatio: attachment.aspectRatio,
          child: FutureBuilder<String>(
            future: state.photoUrl(attachment),
            builder: (context, snapshot) {
              final url = snapshot.data;
              if (url != null && url.isNotEmpty) {
                return GestureDetector(
                  onTap: () => Navigator.push(
                    context,
                    MaterialPageRoute<void>(builder: (_) => _FullPhoto(url: url)),
                  ),
                  child: Image.network(url, fit: BoxFit.cover, gaplessPlayback: true),
                );
              }
              return Stack(
                fit: StackFit.expand,
                children: [
                  if (thumbnail != null)
                    Image.memory(thumbnail, fit: BoxFit.cover, gaplessPlayback: true)
                  else
                    ColoredBox(color: theme.colorScheme.surfaceContainerHighest),
                  Center(
                    child: snapshot.hasError
                        ? Tooltip(
                            message: snapshot.error is BackendException
                                ? (snapshot.error as BackendException).message
                                : "Couldn't load this photo",
                            child: const Icon(Icons.broken_image_outlined, color: Colors.white, size: 36),
                          )
                        : const SizedBox(
                            width: 28,
                            height: 28,
                            child: CircularProgressIndicator(strokeWidth: 2.5, color: Colors.white),
                          ),
                  ),
                ],
              );
            },
          ),
        ),
      ),
    );
    if (caption.isEmpty) return picture;
    return Column(
      crossAxisAlignment: outgoing ? CrossAxisAlignment.end : CrossAxisAlignment.start,
      children: [
        picture,
        Padding(padding: const EdgeInsets.only(top: 4, left: 4, right: 4), child: Text(caption)),
      ],
    );
  }
}

class _FullPhoto extends StatelessWidget {
  const _FullPhoto({required this.url});

  final String url;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(backgroundColor: Colors.black, foregroundColor: Colors.white),
      body: Center(child: InteractiveViewer(maxScale: 5, child: Image.network(url))),
    );
  }
}

class _TypingBubble extends StatelessWidget {
  const _TypingBubble({required this.who});

  final String who;

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final theme = Theme.of(context);
    final dark = theme.brightness == Brightness.dark;
    return Padding(
      padding: const EdgeInsets.only(top: 6),
      child: Row(
        children: [
          Avatar(name: state.nameOf(who), seed: who, size: 30),
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
            decoration: BoxDecoration(
              color: dark ? const Color(0xFF3A3B3C) : const Color(0xFFF0F2F5),
              borderRadius: BorderRadius.circular(18),
            ),
            child: Text('•••', style: TextStyle(color: theme.colorScheme.onSurfaceVariant, letterSpacing: 2)),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// The composer
// ---------------------------------------------------------------------------

class _Composer extends StatelessWidget {
  const _Composer({
    required this.controller,
    required this.focus,
    required this.sending,
    required this.onSend,
    required this.onPhoto,
    required this.onTyping,
  });

  final TextEditingController controller;
  final FocusNode focus;
  final bool sending;
  final VoidCallback onSend;
  final VoidCallback onPhoto;
  final VoidCallback onTyping;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return SafeArea(
      top: false,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(4, 6, 4, 8),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            IconButton(
              tooltip: 'Send a photo',
              icon: const Icon(Icons.photo_outlined, color: messengerBlue),
              onPressed: sending ? null : onPhoto,
            ),
            Expanded(
              child: TextField(
                controller: controller,
                focusNode: focus,
                minLines: 1,
                maxLines: 5,
                textCapitalization: TextCapitalization.sentences,
                textInputAction: TextInputAction.send,
                onChanged: (_) => onTyping(),
                onSubmitted: (_) => onSend(),
                decoration: InputDecoration(
                  hintText: 'Message',
                  isDense: true,
                  filled: true,
                  fillColor: theme.colorScheme.surfaceContainerHighest,
                  contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                  border: OutlineInputBorder(borderRadius: BorderRadius.circular(22), borderSide: BorderSide.none),
                ),
              ),
            ),
            ListenableBuilder(
              listenable: controller,
              builder: (context, _) => IconButton(
                tooltip: 'Send',
                icon: const Icon(Icons.send_rounded),
                color: messengerBlue,
                onPressed: sending || controller.text.trim().isEmpty ? null : onSend,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
