// Messenger: private, end-to-end encrypted chats for friends.
//
// The encryption, the relay protocol and the saved state all live in Rust
// (crates/), compiled to WebAssembly and reached through
// web/messenger/messenger_web.js. This Flutter app is the interface.

import 'package:flutter/widgets.dart';

import 'app.dart';
import 'web_backend_stub.dart' if (dart.library.js_interop) 'web_backend.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(MessengerApp(backend: createBackend()));
}
