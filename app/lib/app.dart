// The app shell: state, theme, and which screen to show.

import 'dart:async';

import 'package:flutter/material.dart';

import 'backend.dart';
import 'format.dart';
import 'screens/chats.dart';
import 'screens/setup.dart';
import 'screens/unlock.dart';
import 'state.dart';

class MessengerApp extends StatefulWidget {
  const MessengerApp({super.key, required this.backend});

  final Backend backend;

  @override
  State<MessengerApp> createState() => _MessengerAppState();
}

class _MessengerAppState extends State<MessengerApp> {
  final _messengerKey = GlobalKey<ScaffoldMessengerState>();
  late final AppState _state;
  StreamSubscription<String>? _alerts;

  @override
  void initState() {
    super.initState();
    _state = AppState(widget.backend);
    _alerts = _state.alerts.listen((text) {
      _messengerKey.currentState?.showSnackBar(
        SnackBar(content: Text(text), duration: const Duration(seconds: 8), showCloseIcon: true),
      );
    });
    _state.start();
  }

  @override
  void dispose() {
    _alerts?.cancel();
    _state.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AppScope(
      state: _state,
      child: MaterialApp(
        title: 'Messenger',
        debugShowCheckedModeBanner: false,
        scaffoldMessengerKey: _messengerKey,
        theme: buildTheme(Brightness.light),
        darkTheme: buildTheme(Brightness.dark),
        home: const Root(),
      ),
    );
  }
}

/// Gives every screen the app state.
class AppScope extends InheritedNotifier<AppState> {
  const AppScope({super.key, required AppState state, required super.child}) : super(notifier: state);

  /// The state, rebuilding the caller when it changes.
  static AppState of(BuildContext context) => context.dependOnInheritedWidgetOfExactType<AppScope>()!.notifier!;

  /// The state, without rebuilding (for callbacks).
  static AppState read(BuildContext context) => context.getInheritedWidgetOfExactType<AppScope>()!.notifier!;
}

ThemeData buildTheme(Brightness brightness) {
  final scheme = ColorScheme.fromSeed(seedColor: messengerBlue, brightness: brightness);
  return ThemeData(
    colorScheme: scheme,
    useMaterial3: true,
    appBarTheme: const AppBarTheme(centerTitle: false, scrolledUnderElevation: 0.5),
    inputDecorationTheme: const InputDecorationTheme(border: OutlineInputBorder()),
  );
}

/// Shows sign-up, the PIN prompt, or the chats, depending on where we are.
class Root extends StatelessWidget {
  const Root({super.key});

  @override
  Widget build(BuildContext context) {
    final state = AppScope.of(context);
    switch (state.phase) {
      case Phase.loading:
        return const Scaffold(body: Center(child: CircularProgressIndicator()));
      case Phase.setup:
        return const SetupScreen();
      case Phase.locked:
        return const UnlockScreen();
      case Phase.ready:
        return const ChatListScreen();
      case Phase.busy:
        return const _Message(
          icon: Icons.tab,
          title: 'Open in another tab',
          body: 'Messenger is already open in another tab or window. Use that one, or close it and reload this page.',
        );
      case Phase.unsupported:
        return const _Message(
          icon: Icons.browser_not_supported,
          title: "This browser can't run Messenger",
          body: 'Try a recent version of Safari, Chrome, Firefox or Edge.',
        );
      case Phase.failed:
        return _Message(
          icon: Icons.error_outline,
          title: "Messenger couldn't start",
          body: '${state.startupError ?? 'Unknown error'}\n\nTry reloading the page.',
        );
    }
  }
}

class _Message extends StatelessWidget {
  const _Message({required this.icon, required this.title, required this.body});

  final IconData icon;
  final String title;
  final String body;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 420),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(icon, size: 48, color: Theme.of(context).colorScheme.primary),
                const SizedBox(height: 16),
                Text(title, style: Theme.of(context).textTheme.titleLarge, textAlign: TextAlign.center),
                const SizedBox(height: 8),
                Text(body, textAlign: TextAlign.center),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
