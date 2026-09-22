import 'package:flutter/material.dart';

void main() => runApp(const Protocol7App());

/// A non-functional placeholder while the security architecture is designed.
class Protocol7App extends StatelessWidget {
  const Protocol7App({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Protocol 7',
    home: Scaffold(
      appBar: AppBar(title: const Text('Protocol 7')),
      body: const Center(
        child: Text('Architecture scaffold — messaging is not available.'),
      ),
    ),
  );
}
