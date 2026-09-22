import '../../domain/model/entities.dart';
import '../../domain/ports/contact_repository.dart';

/// Deterministic storage for tests and development.
///
/// Production composition must replace this with a durable repository so TOFU
/// state survives restarts.
final class InMemoryTrustStore
    implements ContactRepository, KnownKeyRepository, SecurityEventRepository {
  final Map<String, Contact> _contacts = <String, Contact>{};
  final Map<String, Map<String, KnownKey>> _knownKeys =
      <String, Map<String, KnownKey>>{};
  final List<SecurityEvent> _events = <SecurityEvent>[];

  @override
  Future<Contact?> findContact(String contactId) async => _contacts[contactId];

  @override
  Future<void> saveContact(Contact contact) async {
    _contacts[contact.id] = contact;
  }

  @override
  Future<KnownKey?> findKnownKey(
    String contactId,
    String fingerprint,
  ) async => _knownKeys[contactId]?[fingerprint];

  @override
  Future<List<KnownKey>> listKnownKeys(String contactId) async =>
      List<KnownKey>.unmodifiable(
        (_knownKeys[contactId]?.values ?? const <KnownKey>[]).toList()
          ..sort((left, right) => left.firstSeenAt.compareTo(right.firstSeenAt)),
      );

  @override
  Future<void> saveKnownKey(KnownKey knownKey) async {
    (_knownKeys[knownKey.contactId] ??= <String, KnownKey>{})[
            knownKey.publicIdentity.fingerprint] =
        knownKey;
  }

  @override
  Future<void> addSecurityEvent(SecurityEvent event) async {
    _events.add(event);
  }

  @override
  Future<List<SecurityEvent>> listSecurityEvents({String? contactId}) async =>
      List<SecurityEvent>.unmodifiable(
        _events.where(
          (event) => contactId == null || event.contactId == contactId,
        ),
      );
}
