// Used off the web (in widget tests); tests pass their own fake backend.

import 'backend.dart';

Backend createBackend() => throw UnsupportedError('This app runs in a web browser.');
