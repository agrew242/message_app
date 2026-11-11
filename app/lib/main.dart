// Messenger: private, end-to-end encrypted chats for friends.
//
// The encryption, the relay protocol and the saved state all live in Rust
// (crates/), compiled to WebAssembly and reached through
// web/messenger/messenger_web.js. This Flutter app is the interface.

import 'package:flutter/semantics.dart';
import 'package:flutter/widgets.dart';

import 'app.dart';
import 'web_backend_stub.dart' if (dart.library.js_interop) 'web_backend.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  // Test builds keep the accessibility tree on, so a browser test can use
  // the app the way a screen reader does.
  if (const bool.fromEnvironment('MESSENGER_SEMANTICS')) {
    SemanticsBinding.instance.ensureSemantics();
  }
  runApp(MessengerApp(backend: createBackend()));
}
