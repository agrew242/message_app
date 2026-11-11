// Chat details: who's in it, adding and removing people, verifying them,
// changing keys, deleting the chat from this device.

import 'package:flutter/material.dart';

import '../app.dart';
import '../models.dart';
import '../widgets.dart';
import 'verify.dart';

class ChatInfoScreen extends StatelessWidget {
  const ChatInfoScreen({super.key, required this.chatId});

  final String chatId;

  Future<void> _run(BuildContext context, Future<void> Function() action, {String? done}) async {
    try {
      await action();
      if (done != null && context.mounted) showInfo(context, done);
    } catch (e) {
      if (context.mounted) showError(context, e);
    }
  }

  Future<void> _addPeople(BuildContext context) async {
    final state = AppScope.read(context);
    final text = await askText(
      context,
      title: 'Add people',
      label: 'Usernames',
      action: 'Add',
      helper: 'Separate several with commas. Everyone in the chat will see them join.',
    );
    if (text == null || !context.mounted) return;
    final names = text.split(RegExp(r'[\s,]+')).map((n) => n.trim().toLowerCase()).where((n) => n.isNotEmpty).toList();
    if (names.isEmpty) return;
    await _run(context, () => state.addMembers(chatId, names), done: 'Added');
  }

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final chat = state.chatById(chatId);
    final me = state.me!;
    if (chat == null) {
      return Scaffold(appBar: AppBar(), body: const Center(child: Text('This chat is gone.')));
    }
    final others = chat.others(me.username);
    final strangers = chat.members
        .where((m) => usernameOf(m) == me.username && m != me.identity)
        .toList(); // devices using my name that aren't this one
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(title: const Text('Chat details')),
      body: ListView(
        children: [
          const SizedBox(height: 16),
          Center(
            child: Avatar(
              name: chat.title,
              seed: others.isEmpty ? me.username : others.join(','),
              size: 80,
              verified: others.length == 1 && state.isVerified(others.first),
            ),
          ),
          const SizedBox(height: 12),
          Text(chat.title, textAlign: TextAlign.center, style: theme.textTheme.titleLarge),
          const SizedBox(height: 4),
          Text(
            'Messages and photos here are end-to-end encrypted.',
            textAlign: TextAlign.center,
            style: theme.textTheme.bodySmall?.copyWith(color: theme.colorScheme.onSurfaceVariant),
          ),
          const SizedBox(height: 16),
          if (chat.active)
            ListTile(
              leading: const Icon(Icons.person_add_alt_1_outlined),
              title: const Text('Add people'),
              onTap: () => _addPeople(context),
            ),
          const Divider(),
          const _Header('People'),
          for (final username in others)
            ListTile(
              leading: Avatar(name: state.nameOf(username), seed: username, verified: state.isVerified(username)),
              title: Text(state.nameOf(username)),
              subtitle: Text(state.isVerified(username) ? '@$username · verified' : '@$username · not verified'),
              onTap: () =>
                  Navigator.push(context, MaterialPageRoute<void>(builder: (_) => VerifyScreen(username: username))),
              trailing: chat.active
                  ? PopupMenuButton<String>(
                      onSelected: (choice) async {
                        if (choice == 'verify') {
                          Navigator.push(
                            context,
                            MaterialPageRoute<void>(builder: (_) => VerifyScreen(username: username)),
                          );
                        } else if (choice == 'remove') {
                          final ok = await confirm(
                            context,
                            title: 'Remove ${state.nameOf(username)}?',
                            body: "They won't be able to read anything sent here from now on.",
                            action: 'Remove',
                            destructive: true,
                          );
                          if (ok && context.mounted) {
                            await _run(context, () => state.removeMember(chatId, username), done: 'Removed');
                          }
                        }
                      },
                      itemBuilder: (_) => const [
                        PopupMenuItem(value: 'verify', child: Text('Verify')),
                        PopupMenuItem(value: 'remove', child: Text('Remove from chat')),
                      ],
                    )
                  : null,
            ),
          ListTile(
            leading: Avatar(name: me.name, seed: me.username),
            title: Text('${me.name} (you)'),
            subtitle: Text('@${me.username}'),
          ),
          for (final stranger in strangers)
            ListTile(
              leading: Icon(Icons.warning_amber_rounded, color: theme.colorScheme.error),
              title: const Text('A device using your name'),
              subtitle: const Text("It doesn't have your keys. Remove it unless it's an old install of yours."),
              trailing: chat.active
                  ? TextButton(
                      onPressed: () => _run(context, () => state.removeDevice(chatId, deviceOf(stranger)), done: 'Removed'),
                      child: const Text('Remove'),
                    )
                  : null,
            ),
          const Divider(),
          if (chat.active)
            ListTile(
              leading: const Icon(Icons.key_outlined),
              title: const Text('Change encryption keys'),
              subtitle: const Text('Worth doing if you think one of your devices was lost or looked at.'),
              onTap: () => _run(context, () => state.rotateKeys(chatId), done: 'New keys in place'),
            ),
          ListTile(
            leading: Icon(Icons.delete_outline, color: theme.colorScheme.error),
            title: Text('Delete chat from this device', style: TextStyle(color: theme.colorScheme.error)),
            onTap: () async {
              final ok = await confirm(
                context,
                title: 'Delete this chat?',
                body: chat.active
                    ? "Its messages are deleted from this device. You'll stay in the chat until someone removes you, "
                        "but this device won't be able to read it."
                    : 'Its messages are deleted from this device.',
                action: 'Delete',
                destructive: true,
              );
              if (!ok || !context.mounted) return;
              final navigator = Navigator.of(context);
              try {
                await state.forgetChat(chatId);
                navigator.popUntil((route) => route.isFirst);
              } catch (e) {
                if (context.mounted) showError(context, e);
              }
            },
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

class _Header extends StatelessWidget {
  const _Header(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
      child: Text(text, style: theme.textTheme.titleSmall?.copyWith(color: theme.colorScheme.primary)),
    );
  }
}
