// Starting a chat with one or more people.

import 'package:flutter/material.dart';

import '../app.dart';
import '../backend.dart';
import '../widgets.dart';

class NewChatScreen extends StatefulWidget {
  const NewChatScreen({super.key});

  @override
  State<NewChatScreen> createState() => _NewChatScreenState();
}

class _NewChatScreenState extends State<NewChatScreen> {
  final _names = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _names.dispose();
    super.dispose();
  }

  List<String> get _usernames =>
      _names.text.split(RegExp(r'[\s,]+')).map((n) => n.trim().toLowerCase()).where((n) => n.isNotEmpty).toList();

  void _add(String username) {
    final names = _usernames;
    if (names.contains(username)) return;
    _names.text = [...names, username].join(', ');
    setState(() {});
  }

  Future<void> _start() async {
    final names = _usernames;
    if (names.isEmpty) {
      setState(() => _error = 'Type at least one username.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final chatId = await AppScope.read(context).createChat(names);
      if (mounted) Navigator.pop(context, chatId);
    } on BackendException catch (e) {
      if (mounted) setState(() => _error = e.message);
    } catch (e) {
      if (mounted) showError(context, e);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final theme = Theme.of(context);
    final chosen = _usernames.toSet();
    final suggestions = state.contacts.keys.where((u) => !chosen.contains(u)).toList()..sort();
    return Scaffold(
      appBar: AppBar(title: const Text('New chat')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          TextField(
            controller: _names,
            autofocus: true,
            autocorrect: false,
            onChanged: (_) => setState(() {}),
            onSubmitted: (_) => _start(),
            decoration: const InputDecoration(
              labelText: 'Usernames',
              helperText: 'Add several, separated by commas, for a group chat',
            ),
          ),
          if (suggestions.isNotEmpty) ...[
            const SizedBox(height: 16),
            Text('People you know', style: theme.textTheme.titleSmall),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                for (final u in suggestions)
                  ActionChip(
                    avatar: Avatar(name: state.nameOf(u), seed: u, size: 24),
                    label: Text(state.nameOf(u)),
                    onPressed: () => _add(u),
                  ),
              ],
            ),
          ],
          if (_error != null) ...[
            const SizedBox(height: 16),
            Text(_error!, style: TextStyle(color: theme.colorScheme.error)),
          ],
          const SizedBox(height: 24),
          FilledButton(
            onPressed: _busy ? null : _start,
            style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(48)),
            child: _busy
                ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                : const Text('Start chat'),
          ),
        ],
      ),
    );
  }
}
