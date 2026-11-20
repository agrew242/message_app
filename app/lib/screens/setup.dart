// Sign-up: an invite code from a friend, a username, and a name.

import 'package:flutter/material.dart';

import '../app.dart';
import '../backend.dart';
import '../format.dart';

final _usernamePattern = RegExp(r'^[a-z0-9_.-]{3,32}$');

class SetupScreen extends StatefulWidget {
  const SetupScreen({super.key});

  @override
  State<SetupScreen> createState() => _SetupScreenState();
}

class _SetupScreenState extends State<SetupScreen> {
  final _name = TextEditingController();
  final _username = TextEditingController();
  final _invite = TextEditingController(text: Uri.base.queryParameters['invite'] ?? '');
  late final TextEditingController _relay;
  bool _showRelay = false;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    final configured = AppScope.read(context).startInfo?.relay ?? '';
    _relay = TextEditingController(text: configured);
    _showRelay = configured.isEmpty;
  }

  @override
  void dispose() {
    for (final c in [_name, _username, _invite, _relay]) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> _submit() async {
    final username = _username.text.trim().toLowerCase();
    final invite = _invite.text.trim();
    final relay = _relay.text.trim();
    String? problem;
    if (!_usernamePattern.hasMatch(username)) {
      problem = 'Usernames are 3 to 32 lowercase letters, digits, dots, dashes or underscores.';
    } else if (invite.isEmpty) {
      problem = 'Ask a friend who already uses Messenger for an invite code.';
    } else if (!relay.startsWith('https://') && !relay.startsWith('http://')) {
      problem = 'The server address starts with https://';
      _showRelay = true;
    }
    if (problem != null) {
      setState(() => _error = problem);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await AppScope.read(context).register(relay: relay, invite: invite, username: username, displayName: _name.text);
    } on BackendException catch (e) {
      if (mounted) setState(() => _error = e.message);
    } catch (e) {
      if (mounted) setState(() => _error = 'Something went wrong: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final info = AppScope.of(context).startInfo;
    final theme = Theme.of(context);
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: AutofillGroup(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const Center(
                      child: CircleAvatar(
                        radius: 36,
                        backgroundColor: messengerBlue,
                        child: Icon(Icons.lock_rounded, color: Colors.white, size: 36),
                      ),
                    ),
                    const SizedBox(height: 20),
                    Text('Welcome to Messenger', textAlign: TextAlign.center, style: theme.textTheme.headlineSmall),
                    const SizedBox(height: 8),
                    Text(
                      'Everything you send here is end-to-end encrypted: only the people in a chat can read it. '
                      'Not even the server can.',
                      textAlign: TextAlign.center,
                      style: theme.textTheme.bodyMedium?.copyWith(color: theme.colorScheme.onSurfaceVariant),
                    ),
                    if (info != null && info.ios && !info.standalone) ...[
                      const SizedBox(height: 20),
                      const _InstallTip(),
                    ],
                    const SizedBox(height: 24),
                    TextField(
                      controller: _name,
                      textCapitalization: TextCapitalization.words,
                      autofillHints: const [AutofillHints.name],
                      decoration: const InputDecoration(labelText: 'Your name', helperText: 'What your friends see'),
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      controller: _username,
                      autocorrect: false,
                      autofillHints: const [AutofillHints.newUsername],
                      decoration: const InputDecoration(
                        labelText: 'Username',
                        helperText: 'How friends find you, e.g. alex_k',
                      ),
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      controller: _invite,
                      autocorrect: false,
                      decoration: const InputDecoration(labelText: 'Invite code', helperText: 'From a friend'),
                    ),
                    if (_showRelay) ...[
                      const SizedBox(height: 16),
                      TextField(
                        controller: _relay,
                        autocorrect: false,
                        keyboardType: TextInputType.url,
                        decoration: const InputDecoration(
                          labelText: 'Server address',
                          hintText: 'https://relay.example.com',
                        ),
                      ),
                    ],
                    if (_error != null) ...[
                      const SizedBox(height: 16),
                      Text(_error!, style: TextStyle(color: theme.colorScheme.error)),
                    ],
                    const SizedBox(height: 24),
                    FilledButton(
                      onPressed: _busy ? null : _submit,
                      style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(48)),
                      child: _busy
                          ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                          : const Text('Create account'),
                    ),
                    if (!_showRelay)
                      TextButton(
                        onPressed: () => setState(() => _showRelay = true),
                        child: const Text('Use a different server'),
                      ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _InstallTip extends StatelessWidget {
  const _InstallTip();

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(color: scheme.secondaryContainer, borderRadius: BorderRadius.circular(12)),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.ios_share, color: scheme.onSecondaryContainer),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              'On iPhone, first tap Share, then "Add to Home Screen", and open Messenger from your Home Screen. '
              'Your account lives in whichever one you sign up in, and only the Home Screen app can notify you.',
              style: TextStyle(color: scheme.onSecondaryContainer),
            ),
          ),
        ],
      ),
    );
  }
}
