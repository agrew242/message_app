// Settings: name, invites, notifications, read receipts, the app PIN.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../app.dart';
import '../models.dart';
import '../widgets.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  Future<PushStatus>? _push;
  Future<bool>? _hasPin;

  void _reload() {
    final backend = AppScope.read(context).backend;
    setState(() {
      _push = backend.pushStatus();
      _hasPin = backend.hasPin();
    });
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_push == null) {
      final backend = AppScope.read(context).backend;
      _push = backend.pushStatus();
      _hasPin = backend.hasPin();
    }
  }

  Future<void> _editName() async {
    final state = AppScope.read(context);
    final name = await askText(context, title: 'Your name', label: 'Name', initial: state.me!.name);
    if (name == null || name.trim().isEmpty || !mounted) return;
    try {
      await state.setDisplayName(name);
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }

  /// Runs straight from the tap: browsers only ask for permission then.
  void _enablePush() {
    final state = AppScope.read(context);
    state.backend.enablePush().then((_) {
      if (mounted) {
        showInfo(context, 'Notifications are on');
        _reload();
      }
    }, onError: (Object e) {
      if (mounted) {
        showError(context, e);
        _reload();
      }
    });
  }

  Future<void> _pin(bool hasPin) async {
    final backend = AppScope.read(context).backend;
    if (hasPin) {
      final choice = await showDialog<String>(
        context: context,
        builder: (context) => SimpleDialog(
          title: const Text('App PIN'),
          children: [
            SimpleDialogOption(onPressed: () => Navigator.pop(context, 'change'), child: const Text('Change PIN')),
            SimpleDialogOption(onPressed: () => Navigator.pop(context, 'remove'), child: const Text('Turn off PIN')),
          ],
        ),
      );
      if (choice == null || !mounted) return;
      if (choice == 'remove') {
        try {
          await backend.setPin(null);
          if (mounted) showInfo(context, 'PIN turned off');
        } catch (e) {
          if (mounted) showError(context, e);
        }
        _reload();
        return;
      }
    }
    if (!mounted) return;
    final pin = await showDialog<String>(context: context, builder: (_) => const _NewPinDialog());
    if (pin == null || !mounted) return;
    try {
      await backend.setPin(pin);
      if (mounted) showInfo(context, 'PIN set. You\'ll need it each time the app starts.');
    } catch (e) {
      if (mounted) showError(context, e);
    }
    _reload();
  }

  Future<void> _wipe() async {
    final state = AppScope.read(context);
    final ok = await confirm(
      context,
      title: 'Delete your account from this device?',
      body: 'Your messages and keys on this device are erased. Your friends keep their copies. '
          "To use Messenger here again you'll need a new invite.",
      action: 'Delete',
      destructive: true,
    );
    if (!ok || !mounted) return;
    final navigator = Navigator.of(context);
    try {
      await state.wipe();
      navigator.popUntil((route) => route.isFirst);
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final me = state.me;
    final theme = Theme.of(context);
    if (me == null) return const Scaffold();
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          const SizedBox(height: 16),
          Center(child: Avatar(name: me.name, seed: me.username, size: 80)),
          const SizedBox(height: 12),
          Text(me.name, textAlign: TextAlign.center, style: theme.textTheme.titleLarge),
          Text('@${me.username}', textAlign: TextAlign.center, style: theme.textTheme.bodyMedium),
          const SizedBox(height: 16),
          ListTile(
            leading: const Icon(Icons.badge_outlined),
            title: const Text('Name'),
            subtitle: Text(me.name),
            onTap: _editName,
          ),
          ListTile(
            leading: const Icon(Icons.person_add_alt_1_outlined),
            title: const Text('Invite a friend'),
            onTap: () => showInviteDialog(context),
          ),
          ListTile(
            leading: const Icon(Icons.qr_code_2),
            title: const Text('Your verification code'),
            subtitle: const Text('Friends scan it to make sure they reach the real you'),
            onTap: () => Navigator.push(context, MaterialPageRoute<void>(builder: (_) => const _MyCodeScreen())),
          ),
          const Divider(),
          FutureBuilder<PushStatus>(
            future: _push,
            builder: (context, snapshot) {
              final push = snapshot.data;
              String subtitle;
              Widget? trailing;
              if (push == null) {
                subtitle = '…';
              } else if (push.on) {
                subtitle = 'On. A notification says only that something arrived, never who or what.';
              } else if (push.ios && !push.standalone) {
                subtitle = 'Add Messenger to your Home Screen to turn these on.';
              } else if (!push.supported) {
                subtitle = "This browser can't show notifications.";
              } else if (push.permission == 'denied') {
                subtitle = 'Blocked. Allow notifications for this app in your settings.';
              } else {
                subtitle = 'Off';
                trailing = FilledButton.tonal(onPressed: _enablePush, child: const Text('Turn on'));
              }
              return ListTile(
                leading: const Icon(Icons.notifications_outlined),
                title: const Text('Notifications'),
                subtitle: Text(subtitle),
                trailing: trailing,
              );
            },
          ),
          SwitchListTile(
            secondary: const Icon(Icons.done_all),
            title: const Text('Read receipts'),
            subtitle: const Text("Let people see when you've read their messages"),
            value: me.readReceipts,
            onChanged: (on) async {
              try {
                await state.setReadReceipts(on);
              } catch (e) {
                if (context.mounted) showError(context, e);
              }
            },
          ),
          FutureBuilder<bool>(
            future: _hasPin,
            builder: (context, snapshot) {
              final hasPin = snapshot.data;
              return ListTile(
                leading: const Icon(Icons.pin_outlined),
                title: const Text('App PIN'),
                subtitle: Text(hasPin == null
                    ? '…'
                    : hasPin
                        ? 'On: needed each time the app starts'
                        : 'Off. With a PIN, the data on this device is unreadable without it.'),
                onTap: hasPin == null ? null : () => _pin(hasPin),
              );
            },
          ),
          const Divider(),
          ListTile(
            leading: const Icon(Icons.dns_outlined),
            title: const Text('Server'),
            subtitle: Text(me.relayUrl),
          ),
          ListTile(
            leading: const Icon(Icons.smartphone),
            title: const Text('This device'),
            subtitle: Text(me.identity),
            onLongPress: () => Clipboard.setData(ClipboardData(text: me.identity)),
          ),
          ListTile(
            leading: Icon(Icons.delete_forever_outlined, color: theme.colorScheme.error),
            title: Text('Delete account from this device', style: TextStyle(color: theme.colorScheme.error)),
            onTap: _wipe,
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

class _NewPinDialog extends StatefulWidget {
  const _NewPinDialog();

  @override
  State<_NewPinDialog> createState() => _NewPinDialogState();
}

class _NewPinDialogState extends State<_NewPinDialog> {
  final _first = TextEditingController();
  final _second = TextEditingController();
  String? _error;

  @override
  void dispose() {
    _first.dispose();
    _second.dispose();
    super.dispose();
  }

  void _done() {
    if (_first.text.length < 6) {
      setState(() => _error = 'Use at least 6 digits.');
    } else if (_first.text != _second.text) {
      setState(() => _error = "The PINs don't match.");
    } else {
      Navigator.pop(context, _first.text);
    }
  }

  @override
  Widget build(BuildContext context) {
    InputDecoration field(String label) => InputDecoration(labelText: label);
    final digits = [FilteringTextInputFormatter.digitsOnly];
    return AlertDialog(
      title: const Text('New PIN'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text("If you forget it, the messages on this device can't be recovered."),
          const SizedBox(height: 16),
          TextField(
            controller: _first,
            autofocus: true,
            obscureText: true,
            keyboardType: TextInputType.number,
            inputFormatters: digits,
            decoration: field('PIN (6 or more digits)'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _second,
            obscureText: true,
            keyboardType: TextInputType.number,
            inputFormatters: digits,
            decoration: field('Same PIN again'),
            onSubmitted: (_) => _done(),
          ),
          if (_error != null) ...[
            const SizedBox(height: 12),
            Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
          ],
        ],
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        FilledButton(onPressed: _done, child: const Text('Set PIN')),
      ],
    );
  }
}

class _MyCodeScreen extends StatelessWidget {
  const _MyCodeScreen();

  @override
  Widget build(BuildContext context) {
    final me = AppScope.of(context).me!;
    return Scaffold(
      appBar: AppBar(title: const Text('Your verification code')),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          const Text(
            "When you're with a friend, let them scan this from their chat with you "
            '(tap their name, then Verify). It proves the keys in your chats are really yours.',
          ),
          const SizedBox(height: 24),
          Center(
            child: Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(16)),
              child: QrImageView(data: me.verificationCode, size: 240, backgroundColor: Colors.white),
            ),
          ),
          const SizedBox(height: 16),
          Text('@${me.username}', textAlign: TextAlign.center, style: Theme.of(context).textTheme.titleMedium),
        ],
      ),
    );
  }
}
