import 'package:flutter_test/flutter_test.dart';
import 'package:protocol7/main.dart';

void main() {
  testWidgets('identifies the scaffold as non-functional', (tester) async {
    await tester.pumpWidget(const Protocol7App());
    expect(find.text('Protocol 7'), findsOneWidget);
    expect(
      find.text('Architecture scaffold — messaging is not available.'),
      findsOneWidget,
    );
  });
}
