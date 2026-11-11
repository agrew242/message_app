// Verifying a friend: scan each other's QR codes in person, or compare the
// safety number on a call. Either proves nobody is sitting in the middle.

import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../app.dart';
import '../format.dart';
import '../models.dart';
import '../widgets.dart';

class VerifyScreen extends StatefulWidget {
  const VerifyScreen({super.key, required this.username});

  final String username;

  @override
  State<VerifyScreen> createState() => _VerifyScreenState();
}

class _VerifyScreenState extends State<VerifyScreen> {
  Future<String>? _safetyNumber;

  Future<void> _scan() async {
    final state = AppScope.read(context);
    try {
      final code = await state.backend.scanQr();
      if (code == null || !mounted) return;
      final whose = usernameInCode(code);
      if (whose == null) {
        showInfo(context, "That isn't a Messenger code.");
        return;
      }
      final result = await state.verifyCode(code);
      if (!mounted) return;
      final name = state.nameOf(whose);
      await showDialog<void>(
        context: context,
        builder: (context) => AlertDialog(
          icon: Icon(
            result == VerifyResult.verified ? Icons.verified_user : Icons.warning_amber_rounded,
            color: result == VerifyResult.verified ? Colors.green.shade600 : Theme.of(context).colorScheme.error,
            size: 40,
          ),
          title: Text(result == VerifyResult.verified ? '$name is verified' : "The codes don't match"),
          content: Text(
            result == VerifyResult.verified
                ? 'Messages between you can only be read by the two of you.'
                : "The code on $name's phone isn't the one your chats use. Someone may be intercepting. "
                    "Don't share anything sensitive until you've worked out why (if they reinstalled the app, "
                    'they need to be added to your chats again).',
          ),
          actions: [FilledButton(onPressed: () => Navigator.pop(context), child: const Text('OK'))],
        ),
      );
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }

  Future<void> _numbersMatch() async {
    final state = AppScope.read(context);
    final name = state.nameOf(widget.username);
    final ok = await confirm(
      context,
      title: 'Mark $name as verified?',
      body: 'Only if you compared all 60 digits with $name over a call or in person, and they all match.',
      action: 'They match',
    );
    if (!ok || !mounted) return;
    try {
      await state.markVerified(widget.username);
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    final me = state.me!;
    final theme = Theme.of(context);
    final name = state.nameOf(widget.username);
    final verified = state.isVerified(widget.username);
    final known = state.contacts.containsKey(widget.username);
    if (known) _safetyNumber ??= state.backend.safetyNumber(widget.username);

    return Scaffold(
      appBar: AppBar(title: Text('Verify $name')),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          if (verified)
            Container(
              padding: const EdgeInsets.all(12),
              margin: const EdgeInsets.only(bottom: 16),
              decoration: BoxDecoration(color: Colors.green.withValues(alpha: 0.12), borderRadius: BorderRadius.circular(12)),
              child: Row(
                children: [
                  Icon(Icons.verified_user, color: Colors.green.shade600),
                  const SizedBox(width: 12),
                  Expanded(child: Text('You verified $name.')),
                ],
              ),
            ),
          Text(
            "To be sure you're really talking to $name, scan each other's codes when you're together, "
            'or read the safety number below to each other on a call.',
            style: theme.textTheme.bodyMedium,
          ),
          const SizedBox(height: 24),
          Center(
            child: Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(16)),
              child: QrImageView(data: me.verificationCode, size: 220, backgroundColor: Colors.white),
            ),
          ),
          const SizedBox(height: 8),
          Text('Your code', textAlign: TextAlign.center, style: theme.textTheme.bodySmall),
          const SizedBox(height: 16),
          FilledButton.icon(
            icon: const Icon(Icons.qr_code_scanner),
            label: Text("Scan $name's code"),
            onPressed: _scan,
          ),
          const SizedBox(height: 32),
          Text('Safety number', style: theme.textTheme.titleMedium),
          const SizedBox(height: 8),
          if (!known)
            Text("You'll see it once you're in a chat with $name.")
          else
            FutureBuilder<String>(
              future: _safetyNumber,
              builder: (context, snapshot) {
                if (snapshot.hasError) return Text('${snapshot.error}');
                if (!snapshot.hasData) return const LinearProgressIndicator();
                return SelectableText(
                  formatSafetyNumber(snapshot.data!),
                  textAlign: TextAlign.center,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 18, height: 1.6, letterSpacing: 1),
                );
              },
            ),
          if (known && !verified) ...[
            const SizedBox(height: 16),
            OutlinedButton(onPressed: _numbersMatch, child: const Text('We compared: the numbers match')),
          ],
        ],
      ),
    );
  }
}
