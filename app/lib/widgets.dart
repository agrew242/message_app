// Small shared widgets.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'app.dart';
import 'backend.dart';
import 'format.dart';

class Avatar extends StatelessWidget {
  const Avatar({super.key, required this.name, required this.seed, this.size = 40, this.verified = false});

  final String name;

  /// Picks the color, so it stays put when someone renames themselves.
  final String seed;
  final double size;
  final bool verified;

  @override
  Widget build(BuildContext context) {
    final circle = Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(color: avatarColor(seed), shape: BoxShape.circle),
      child: Text(
        initials(name),
        style: TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: size * 0.38),
      ),
    );
    if (!verified) return circle;
    return Stack(
      clipBehavior: Clip.none,
      children: [
        circle,
        Positioned(
          right: -2,
          bottom: -2,
          child: Container(
            padding: const EdgeInsets.all(1.5),
            decoration: BoxDecoration(color: Theme.of(context).colorScheme.surface, shape: BoxShape.circle),
            child: Icon(Icons.verified_user, size: size * 0.36, color: Colors.green.shade600),
          ),
        ),
      ],
    );
  }
}

/// A slim banner at the top while the live connection is down.
class ConnectingBanner extends StatelessWidget {
  const ConnectingBanner({super.key});

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      width: double.infinity,
      color: scheme.surfaceContainerHighest,
      padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 16),
      child: Text('Connecting…', textAlign: TextAlign.center, style: TextStyle(color: scheme.onSurfaceVariant)),
    );
  }
}

void showError(BuildContext context, Object error) {
  final text = error is BackendException ? error.message : 'Something went wrong: $error';
  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
}

void showInfo(BuildContext context, String text) {
  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
}

/// Asks a yes/no question. True if they confirmed.
Future<bool> confirm(
  BuildContext context, {
  required String title,
  required String body,
  required String action,
  bool destructive = false,
}) async {
  final answer = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: Text(title),
      content: Text(body),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
        FilledButton(
          style: destructive ? FilledButton.styleFrom(backgroundColor: Theme.of(context).colorScheme.error) : null,
          onPressed: () => Navigator.pop(context, true),
          child: Text(action),
        ),
      ],
    ),
  );
  return answer ?? false;
}

/// Asks for one line of text. Null if cancelled.
Future<String?> askText(
  BuildContext context, {
  required String title,
  required String label,
  String initial = '',
  String action = 'Save',
  String? helper,
}) {
  final controller = TextEditingController(text: initial);
  return showDialog<String>(
    context: context,
    builder: (context) => AlertDialog(
      title: Text(title),
      content: TextField(
        controller: controller,
        autofocus: true,
        decoration: InputDecoration(labelText: label, helperText: helper, helperMaxLines: 3),
        onSubmitted: (value) => Navigator.pop(context, value),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(context, controller.text), child: Text(action)),
      ],
    ),
  );
}

/// Makes an invite code and shows it, ready to share.
Future<void> showInviteDialog(BuildContext context) async {
  final state = AppScope.read(context);
  final String code;
  try {
    code = await state.backend.invite();
  } catch (e) {
    if (context.mounted) showError(context, e);
    return;
  }
  if (!context.mounted) return;
  final link = Uri.base.removeFragment().replace(queryParameters: {'invite': code}).toString();
  final message = 'Join me on Messenger, where our messages are end-to-end encrypted: $link\n'
      'Invite code: $code (it works once, within 7 days).';
  await showDialog<void>(
    context: context,
    builder: (dialogContext) => AlertDialog(
      title: const Text('Invite a friend'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Send this to a friend. The code works once, within 7 days.'),
          const SizedBox(height: 16),
          SelectableText(
            code,
            style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w600, letterSpacing: 1.5, fontFamily: 'monospace'),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () async {
            await Clipboard.setData(ClipboardData(text: message));
            if (dialogContext.mounted) Navigator.pop(dialogContext);
            if (context.mounted) showInfo(context, 'Invite copied');
          },
          child: const Text('Copy'),
        ),
        FilledButton.icon(
          icon: const Icon(Icons.ios_share),
          label: const Text('Share'),
          onPressed: () async {
            try {
              final how = await state.backend.share(message);
              if (dialogContext.mounted) Navigator.pop(dialogContext);
              if (how == 'copied' && context.mounted) showInfo(context, 'Invite copied');
            } catch (e) {
              if (context.mounted) showError(context, e);
            }
          },
        ),
      ],
    ),
  );
}
