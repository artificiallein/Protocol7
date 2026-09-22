import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../../core/protocol_constants.dart';
import '../../domain/model/identity.dart';
import '../../domain/ports/secure_key_storage.dart';

/// Stores every field as a separate OS-protected value; private keys are never
/// serialized as JSON. The completion marker is written last.
final class FlutterSecureKeyStorage implements SecureKeyStorage {
  FlutterSecureKeyStorage({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;

  static const _prefix = 'protocol7.identity.v1.';
  static const _complete = '${_prefix}complete';
  static const _identityId = '${_prefix}identity_id';
  static const _createdAt = '${_prefix}created_at';
  static const _cryptoVersion = '${_prefix}crypto_version';
  static const _fingerprint = '${_prefix}fingerprint';
  static const _signingPublic = '${_prefix}signing_public';
  static const _signingPrivate = '${_prefix}signing_private';
  static const _encryptionPublic = '${_prefix}encryption_public';
  static const _encryptionPrivate = '${_prefix}encryption_private';

  static const _allKeys = <String>[
    _complete,
    _identityId,
    _createdAt,
    _cryptoVersion,
    _fingerprint,
    _signingPublic,
    _signingPrivate,
    _encryptionPublic,
    _encryptionPrivate,
  ];

  @override
  Future<void> storePrivateIdentity(UserIdentity identity) async {
    await _storage.delete(key: _complete);
    try {
      await _write(_identityId, identity.identityId);
      await _write(_createdAt, identity.createdAt.toUtc().toIso8601String());
      await _write(_cryptoVersion, identity.cryptoVersion.toString());
      await _write(_fingerprint, identity.fingerprint);
      await _write(
        _signingPublic,
        base64Url.encode(identity.publicIdentity.signingPublicKey),
      );
      await _write(
        _signingPrivate,
        base64Url.encode(identity.signingPrivateKey),
      );
      await _write(
        _encryptionPublic,
        base64Url.encode(identity.publicIdentity.encryptionPublicKey),
      );
      await _write(
        _encryptionPrivate,
        base64Url.encode(identity.encryptionPrivateKey),
      );
      await _write(_complete, '1');
    } catch (_) {
      await deletePrivateIdentity();
      rethrow;
    }
  }

  @override
  Future<UserIdentity?> loadPrivateIdentity() async {
    if (!await hasIdentity()) return null;
    try {
      final identityId = await _required(_identityId);
      final createdAt = DateTime.parse(await _required(_createdAt)).toUtc();
      final cryptoVersion = int.parse(await _required(_cryptoVersion));
      final fingerprint = await _required(_fingerprint);
      final signingPublic = base64Url.decode(await _required(_signingPublic));
      final signingPrivate = base64Url.decode(await _required(_signingPrivate));
      final encryptionPublic = base64Url.decode(
        await _required(_encryptionPublic),
      );
      final encryptionPrivate = base64Url.decode(
        await _required(_encryptionPrivate),
      );
      if (signingPublic.length != ProtocolConstants.signingPublicKeyBytes ||
          signingPrivate.length != ProtocolConstants.signingPrivateKeyBytes ||
          encryptionPublic.length !=
              ProtocolConstants.encryptionPublicKeyBytes ||
          encryptionPrivate.length !=
              ProtocolConstants.encryptionPrivateKeyBytes) {
        throw StateError('Invalid secure identity key length.');
      }

      return UserIdentity(
        publicIdentity: PublicIdentity(
          identityId: identityId,
          signingPublicKey: signingPublic,
          encryptionPublicKey: encryptionPublic,
          fingerprint: fingerprint,
          createdAt: createdAt,
          cryptoVersion: cryptoVersion,
        ),
        signingPrivateKey: signingPrivate,
        encryptionPrivateKey: encryptionPrivate,
      );
    } on Object catch (error) {
      throw CorruptIdentityStorageException(error);
    }
  }

  @override
  Future<void> deletePrivateIdentity() async {
    for (final key in _allKeys) {
      await _storage.delete(key: key);
    }
  }

  @override
  Future<bool> hasIdentity() async =>
      await _storage.read(key: _complete) == '1';

  Future<void> _write(String key, String value) =>
      _storage.write(key: key, value: value);

  Future<String> _required(String key) async {
    final value = await _storage.read(key: key);
    if (value == null) throw StateError('Missing secure identity component.');
    return value;
  }
}

final class CorruptIdentityStorageException implements Exception {
  const CorruptIdentityStorageException(this.cause);

  final Object cause;

  @override
  String toString() => 'Secure identity storage is incomplete or corrupt.';
}
