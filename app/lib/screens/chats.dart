// The chat list.

import 'package:flutter/material.dart';

import '../app.dart';
import '../format.dart';
import '../models.dart';
import '../widgets.dart';
import 'chat.dart';
import 'new_chat.dart';
import 'settings.dart';

class ChatListScreen extends StatefulWidget {
  const ChatListScreen({super.key});

  @override
  State<ChatListScreen> createState() => _ChatListScreenState();
}

class _ChatListScreenState extends State<ChatListScreen> {
  bool _hideInstallTip = false;

  void _open(String chatId) {
    Navigator.push(context, MaterialPageRoute<void>(builder: (_) => ChatScreen(chatId: chatId)));
  }

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final me = state.me!;
    final info = state.startInfo;
    final showInstallTip = !_hideInstallTip && info != null && info.ios && !info.standalone;
    return Scaffold(
      appBar: AppBar(
        leading: Padding(
          padding: const EdgeInsets.all(8),
          child: InkWell(
            customBorder: const CircleBorder(),
            onTap: () => Navigator.push(context, MaterialPageRoute<void>(builder: (_) => const SettingsScreen())),
            child: Tooltip(message: 'Settings', child: Avatar(name: me.name, seed: me.username)),
          ),
        ),
        title: const Text('Chats', style: TextStyle(fontWeight: FontWeight.bold)),
        actions: [
          IconButton(
            tooltip: 'Invite a friend',
            icon: const Icon(Icons.person_add_alt_1_outlined),
            onPressed: () => showInviteDialog(context),
          ),
          IconButton(
            tooltip: 'New chat',
            icon: const Icon(Icons.edit_outlined),
            onPressed: () async {
              final chatId = await Navigator.push<String>(
                context,
                MaterialPageRoute(builder: (_) => const NewChatScreen()),
              );
              if (chatId != null && context.mounted) _open(chatId);
            },
          ),
        ],
      ),
      body: Column(
        children: [
          if (!state.online) const ConnectingBanner(),
          if (showInstallTip)
            MaterialBanner(
              content: const Text(
                'Add Messenger to your Home Screen (Share, then "Add to Home Screen") to get notifications.',
              ),
              leading: const Icon(Icons.ios_share),
              actions: [TextButton(onPressed: () => setState(() => _hideInstallTip = true), child: const Text('OK'))],
            ),
          Expanded(
            child: state.chats.isEmpty
                ? const _Empty()
                : RefreshIndicator(
                    onRefresh: () async {
                      state.backend.syncNow();
                      await state.refresh();
                    },
                    child: ListView.builder(
                      itemCount: state.chats.length,
                      itemBuilder: (context, i) {
                        final chat = state.chats[i];
                        return _ChatTile(chat: chat, onTap: () => _open(chat.chatId));
                      },
                    ),
                  ),
          ),
        ],
      ),
    );
  }
}

class _ChatTile extends StatelessWidget {
  const _ChatTile({required this.chat, required this.onTap});

  final ChatSummary chat;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final me = state.me!.username;
    final others = chat.others(me);
    final unread = chat.unread > 0;
    final theme = Theme.of(context);
    final typing = state.typingIn(chat.chatId);
    final subtitle = typing.isNotEmpty
        ? (others.length > 1 ? '${state.nameOf(typing.first)} is typing…' : 'typing…')
        : preview(chat.last, me, state.nameOf, group: others.length > 1);
    final last = chat.last;
    return ListTile(
      onTap: onTap,
      leading: Avatar(
        name: chat.title,
        seed: others.isEmpty ? me : others.join(','),
        size: 52,
        verified: others.length == 1 && state.isVerified(others.first),
      ),
      title: Text(
        chat.title,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(fontWeight: unread ? FontWeight.bold : FontWeight.w500),
      ),
      subtitle: Text(
        chat.active ? subtitle : "You're no longer in this chat",
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(
          fontWeight: unread ? FontWeight.w600 : FontWeight.normal,
          color: unread ? theme.colorScheme.onSurface : theme.colorScheme.onSurfaceVariant,
          fontStyle: typing.isNotEmpty ? FontStyle.italic : FontStyle.normal,
        ),
      ),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          if (last != null)
            Text(shortTime(context, last.time), style: theme.textTheme.bodySmall?.copyWith(
                  color: unread ? messengerBlue : theme.colorScheme.onSurfaceVariant,
                )),
          if (unread) ...[
            const SizedBox(height: 4),
            Badge(label: Text('${chat.unread}'), backgroundColor: messengerBlue),
          ],
        ],
      ),
    );
  }
}

class _Empty extends StatelessWidget {
  const _Empty();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.forum_outlined, size: 64, color: theme.colorScheme.outline),
            const SizedBox(height: 16),
            Text('No chats yet', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            const Text(
              'Invite a friend with the button above, then start a chat with them.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              icon: const Icon(Icons.person_add_alt_1_outlined),
              label: const Text('Invite a friend'),
              onPressed: () => showInviteDialog(context),
            ),
          ],
        ),
      ),
    );
  }
}
