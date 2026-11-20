// The app PIN prompt. The PIN unlocks the key that decrypts everything
// stored on this device; without it the stored data is unreadable.

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app.dart';
import '../backend.dart';
import '../widgets.dart';

class UnlockScreen extends StatefulWidget {
  const UnlockScreen({super.key});

  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen> {
  final _pin = TextEditingController();
  bool _busy = false;
  String? _error;
  int _failures = 0;
  DateTime? _waitUntil;
  Timer? _tick;

  @override
  void dispose() {
    _pin.dispose();
    _tick?.cancel();
    super.dispose();
  }

  bool get _waiting => _waitUntil != null && DateTime.now().isBefore(_waitUntil!);

  Future<void> _unlock() async {
    if (_busy || _waiting || _pin.text.isEmpty) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await AppScope.read(context).unlock(_pin.text);
    } on BackendException catch (e) {
      if (!mounted) return;
      _pin.clear();
      _failures++;
      setState(() => _error = e.kind == 'WrongPin' ? "That PIN isn't right." : e.message);
      if (_failures >= 5) {
        // Slow down guessing a little (the real protection is the slow key
        // derivation behind the PIN).
        _waitUntil = DateTime.now().add(Duration(seconds: 30 * (_failures - 4)));
        _tick?.cancel();
        _tick = Timer.periodic(const Duration(seconds: 1), (t) {
          if (!_waiting) t.cancel();
          if (mounted) setState(() {});
        });
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final wait = _waiting ? _waitUntil!.difference(DateTime.now()).inSeconds + 1 : 0;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 320),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Icon(Icons.lock_outline, size: 48, color: theme.colorScheme.primary),
                  const SizedBox(height: 16),
                  Text('Enter your PIN', textAlign: TextAlign.center, style: theme.textTheme.titleLarge),
                  const SizedBox(height: 24),
                  TextField(
                    controller: _pin,
                    autofocus: true,
                    obscureText: true,
                    textAlign: TextAlign.center,
                    keyboardType: TextInputType.number,
                    inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                    style: const TextStyle(fontSize: 24, letterSpacing: 8),
                    onSubmitted: (_) => _unlock(),
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 12),
                    Text(_error!, textAlign: TextAlign.center, style: TextStyle(color: theme.colorScheme.error)),
                  ],
                  if (wait > 0) ...[
                    const SizedBox(height: 8),
                    Text('Try again in $wait s', textAlign: TextAlign.center),
                  ],
                  const SizedBox(height: 24),
                  FilledButton(
                    onPressed: _busy || wait > 0 ? null : _unlock,
                    style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(48)),
                    child: _busy
                        ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                        : const Text('Unlock'),
                  ),
                  const SizedBox(height: 32),
                  TextButton(
                    onPressed: () async {
                      final state = AppScope.read(context);
                      final ok = await confirm(
                        context,
                        title: 'Forgot your PIN?',
                        body: 'Without it, the messages on this device can\'t be decrypted. You can delete them and '
                            'sign up again with a new invite, but your old chats will be gone from this device.',
                        action: 'Delete and start over',
                        destructive: true,
                      );
                      if (ok) await state.wipe();
                    },
                    child: const Text('Forgot PIN?'),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
