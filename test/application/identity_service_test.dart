import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:protocol7/application/identity_service.dart';
import 'package:protocol7/infrastructure/storage/flutter_secure_key_storage.dart';
import 'package:protocol7/security/sodium_crypto_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late SodiumCryptoService cryptoService;
  late FlutterSecureKeyStorage keyStorage;
  late IdentityService identityService;

  setUpAll(() async {
    cryptoService = await SodiumCryptoService.create();
  });

  setUp(() {
    FlutterSecureStorage.setMockInitialValues(<String, String>{});
    keyStorage = FlutterSecureKeyStorage();
    identityService = IdentityService(
      cryptoService: cryptoService,
      keyStorage: keyStorage,
    );
  });

  test('creates, stores, and reloads a valid identity', () async {
    final created = await identityService.createIdentity();
    addTearDown(created.destroy);

    expect(await keyStorage.hasIdentity(), isTrue);
    expect(created.identityId, isNot(contains('@')));
    expect(created.fingerprint, matches(RegExp(r'^[0-9A-F]{4}( [0-9A-F]{4}){7}$')));

    final loaded = await identityService.loadIdentity();
    addTearDown(loaded.destroy);
    expect(loaded.identityId, created.identityId);
    expect(loaded.fingerprint, created.fingerprint);
    expect(await cryptoService.validateIdentity(loaded), isTrue);
    expect(loaded.toString(), isNot(contains('privateKey')));
  });

  test('does not overwrite an existing identity', () async {
    final identity = await identityService.createIdentity();
    addTearDown(identity.destroy);

    await expectLater(
      identityService.createIdentity(),
      throwsA(isA<StateError>()),
    );
  });

  test('deletes only the Protocol 7 identity', () async {
    final identity = await identityService.createIdentity();
    identity.destroy();
    await keyStorage.deletePrivateIdentity();

    expect(await keyStorage.hasIdentity(), isFalse);
    await expectLater(
      identityService.loadIdentity(),
      throwsA(isA<StateError>()),
    );
  });

  test('rejects a completed but incomplete secure-storage record', () async {
    FlutterSecureStorage.setMockInitialValues(<String, String>{
      'protocol7.identity.v1.complete': '1',
    });

    await expectLater(
      keyStorage.loadPrivateIdentity(),
      throwsA(isA<CorruptIdentityStorageException>()),
    );
  });
}
