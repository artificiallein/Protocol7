import 'dart:typed_data';

/// Public identity material. An email address is deliberately not part of it.
final class PublicIdentity {
  PublicIdentity({
    required this.identityId,
    required List<int> signingPublicKey,
    required List<int> encryptionPublicKey,
    required this.fingerprint,
    required this.createdAt,
    required this.cryptoVersion,
  }) : _signingPublicKey = Uint8List.fromList(signingPublicKey),
       _encryptionPublicKey = Uint8List.fromList(encryptionPublicKey);

  final String identityId;
  final String fingerprint;
  final DateTime createdAt;
  final int cryptoVersion;
  final Uint8List _signingPublicKey;
  final Uint8List _encryptionPublicKey;

  Uint8List get signingPublicKey => Uint8List.fromList(_signingPublicKey);
  Uint8List get encryptionPublicKey => Uint8List.fromList(_encryptionPublicKey);

  @override
  String toString() =>
      'PublicIdentity(identityId: $identityId, fingerprint: $fingerprint)';
}

/// A local identity whose secret bytes must only be persisted by SecureKeyStorage.
final class UserIdentity {
  UserIdentity({
    required this.publicIdentity,
    required List<int> signingPrivateKey,
    required List<int> encryptionPrivateKey,
  }) : _signingPrivateKey = Uint8List.fromList(signingPrivateKey),
       _encryptionPrivateKey = Uint8List.fromList(encryptionPrivateKey);

  final PublicIdentity publicIdentity;
  final Uint8List _signingPrivateKey;
  final Uint8List _encryptionPrivateKey;
  bool _destroyed = false;

  String get identityId => publicIdentity.identityId;
  String get fingerprint => publicIdentity.fingerprint;
  DateTime get createdAt => publicIdentity.createdAt;
  int get cryptoVersion => publicIdentity.cryptoVersion;

  Uint8List get signingPrivateKey {
    _checkNotDestroyed();
    return Uint8List.fromList(_signingPrivateKey);
  }

  Uint8List get encryptionPrivateKey {
    _checkNotDestroyed();
    return Uint8List.fromList(_encryptionPrivateKey);
  }

  bool get isDestroyed => _destroyed;

  void destroy() {
    if (_destroyed) return;
    _signingPrivateKey.fillRange(0, _signingPrivateKey.length, 0);
    _encryptionPrivateKey.fillRange(0, _encryptionPrivateKey.length, 0);
    _destroyed = true;
  }

  void _checkNotDestroyed() {
    if (_destroyed) {
      throw StateError('Identity private material has been destroyed.');
    }
  }

  @override
  String toString() =>
      'UserIdentity(identityId: $identityId, secretMaterial: <redacted>)';
}
