import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('domain layer does not import implementation layers or plugins', () {
    _expectNoImports(
      Directory('lib/domain'),
      const <String>[
        '/application/',
        '/infrastructure/',
        '/presentation/',
        '/protocol/',
        '/security/',
        'package:flutter',
        'package:sodium',
        'package:flutter_secure_storage',
      ],
    );
  });

  test('application layer does not import infrastructure or plugins', () {
    _expectNoImports(
      Directory('lib/application'),
      const <String>[
        '/infrastructure/',
        '/presentation/',
        'package:flutter',
        'package:sodium',
        'package:flutter_secure_storage',
      ],
    );
  });
}

void _expectNoImports(Directory directory, List<String> forbidden) {
  final violations = <String>[];
  for (final entity in directory.listSync(recursive: true)) {
    if (entity is! File || !entity.path.endsWith('.dart')) continue;
    for (final line in entity.readAsLinesSync()) {
      final normalized = line.replaceAll('..', '/');
      if (line.trimLeft().startsWith('import ') &&
          forbidden.any(normalized.contains)) {
        violations.add('${entity.path}: $line');
      }
    }
  }
  expect(violations, isEmpty, reason: violations.join('\n'));
}
