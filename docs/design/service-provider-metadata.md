# Service Provider Metadata

## Purpose

This note records what the package answers when an administrator needs to register a connection at its identity
provider (SSO-5.9): for a SAML connection, its service provider metadata (SAML 2.0 Metadata) as
`application/samlmetadata+xml`; for any other protocol, whatever that protocol's driver describes. It covers what the
metadata holds and leaves out, where each value comes from, how a key rotation shows in it, and the helper an
application calls to serve it. Serving it at a URL is the application's: the package builds no route.

## Invariants

- The public entry is `Connections\ServiceProviderDescriptions::describe(tenantId, connectionId)`, which answers a
  `Protocols\ServiceProviderDescription`: a document and its content type, or why the connection cannot be described.
  It is generic: it finds the connection and asks its protocol's driver (`ProtocolDriver::describe()`) through the
  `ProtocolManager`, so the OIDC driver's description needs no change to the helper. Beside it,
  `describeWithInlineKeys(tenantId, connectionId)` is an OIDC connection's description with its public keys in the
  document, and `publicKeys(connectionId)` the body of its public JWKS URL, by the connection's id alone, of any tenant,
  since the provider that fetches the URL names none; each is `connection_unavailable` for any other protocol
  (`oidc-relying-party.md`). The package adds no route for any of them.
- A connection the tenant does not have, unknown or another tenant's, is `connection_unavailable`, the same answer for
  both, so the helper never reveals that another tenant's connection exists. The tenant is matched exactly
  (`ConnectionFinder`), whatever the column's collation.
- A connection whose protocol is not available (no driver registered under it, or its feature off) is
  `protocol_unavailable`, and no driver is asked.
- A disabled connection is described, and so is one whose identity provider settings are incomplete: the metadata is
  the service provider side only, and an administrator registers it before the connection is enabled. Being described
  says nothing about being usable (SSO-2.1).
- The helper reads public data and changes nothing: it asks for no fresh authentication, writes nothing and reports no
  event. It reads the connection from the write connection (SSO-11.3).
- Every call into the SAML library is made by `Protocols\Saml2\Library\MetadataWriter`, inside the adapter's namespace
  (`saml-adapter.md`); `Saml2\ServiceProviderMetadata` reads the package's own values and hands them to it.
- The SAML metadata is one unsigned `md:EntityDescriptor` whose `entityID` is the entity id the endpoint resolver builds
  (SSO-5.5), holding one `md:SPSSODescriptor`:
  - `protocolSupportEnumeration` is SAML 2.0's protocol namespace;
  - `AuthnRequestsSigned` is `sign_authn_requests`, and `WantAssertionsSigned` is `want_assertions_signed`, each
    written `true` or `false`, defaults applied (off and on);
  - one `KeyDescriptor use="signing"` for each published `sp_signing` key, then one `KeyDescriptor use="encryption"`
    for each published `sp_encryption` key (`KeyRing::published()`: the current key, then the next one), each carrying
    the certificate's body in `ds:KeyInfo/ds:X509Data/ds:X509Certificate`;
  - on each encryption `KeyDescriptor`, an `EncryptionMethod` for each data encryption algorithm the connection allows,
    then each key transport it allows, each group in the order the connection lists them: AES-128-GCM, AES-192-GCM,
    RSA-OAEP (XML Encryption 1.1) and RSA-OAEP with MGF1 by default, AES-CBC only when listed;
  - one `NameIDFormat`, the connection's (`persistent` by default);
  - one `AssertionConsumerService`: HTTP-POST, at the connection's assertion consumer service, `index="0"`,
    `isDefault="true"`.
- AES-256-GCM is never advertised, since the library cannot decrypt it until saml2 v7 (`saml-library.md`, condition 5),
  and RSA 1.5 never is: the encryption methods come from `Saml2Options`, which keeps only the algorithms the settings
  allow, even when a stored list names others.
- No secret is ever written (SSO-5.9). The writer takes only certificates, and refuses anything that is not exactly one
  PEM certificate block, a private key included, before the library sees it. A published key with no certificate is
  left out. The metadata is not signed.
- The metadata has no `ID`, `validUntil` or `cacheDuration`, so the same connection, keys, settings and endpoints always
  give the same bytes. It changes when a key is added, made current or retired, or a setting it reflects changes.
- Every value is read afresh on each call; nothing is kept between calls, and the driver's collaborators hold no
  connection state (SSO-11.2).

## Success Path

- The application calls `ServiceProviderDescriptions::describe()` with the tenant it serves and the connection id from
  its metadata route (`sso.endpoints.paths.metadata`).
- The helper finds the tenant's connection, checks its protocol is available, and asks its driver.
- `Saml2Driver::describe()` reads the connection's options (`Saml2Options::of()`) and asks
  `ServiceProviderMetadata::describe()`, which resolves the endpoints, reads the published signing and encryption
  certificates, and has `MetadataWriter::write()` build the document with the library's metadata element classes.
- The result is `ServiceProviderDescription::document('application/samlmetadata+xml', $xml)`; the application serves
  the body with that content type.
- During a rotation (`keys.md`) the next key is published beside the current one as soon as it is added, so the
  identity provider can take it up before it is used; once it is made current, only it is published, and the replaced
  key, `retiring` and still decrypting, is no longer advertised.

## Failure / Edge Cases

- Unknown connection, another tenant's connection, an empty or overlong connection id: `connection_unavailable`.
- Protocol with no registered driver, or its feature off: `protocol_unavailable`.
- An empty or overlong tenant id is the application's mistake: an `InvalidArgumentException` from `ConnectionFinder`.
- A malformed endpoint configuration fails closed with the endpoint resolver's `InvalidArgumentException`, which the
  boot check reports first.
- A value SAML 2.0 Metadata does not allow, such as an entity id over 1,024 characters, or a certificate block the
  schema refuses, is an `InvalidArgumentException` naming the rule and quoting nothing given.
- A connection with no keys is described with no `KeyDescriptor`; one that signs its requests or requires encrypted
  assertions is still not complete until it has the current key it needs (`connections.md`), but its metadata can be
  published first.
- A database error propagates (SSO-11.4).

## Implementation Anchors

- `src/Connections/ServiceProviderDescriptions.php`: the public helper.
- `src/Protocols/Saml2/Saml2Driver.php`: `describe()`, which reads the options and delegates.
- `src/Protocols/Saml2/ServiceProviderMetadata.php`: the endpoints and published certificates, and the content type.
- `src/Protocols/Saml2/Library/MetadataWriter.php`: the only class that builds the metadata with the library.
- `src/Protocols/Saml2/Saml2Options.php`: the switches, the NameID format URI, and the allowed encryption algorithms.
- `src/Keys/KeyRing.php`: `published()`, the current key and then the next one.
- `src/Contracts/EndpointResolver.php` and `src/Endpoints/ConfiguredEndpointResolver.php`: the entity id and the
  assertion consumer service.

## Authoritative Tests

- `tests/Feature/Protocols/Saml2/Library/MetadataWriterTest.php`: every element and attribute as the whole document,
  valid against the metadata schema through `HardenedParser`; the defaults; the encryption methods and their order;
  anything but one PEM certificate refused; the entity id limit at 1,024 and 1,025 characters; the same bytes for the
  same input.
- `tests/Feature/Protocols/Saml2/ServiceProviderMetadataTest.php`: through the driver, the whole document; current and
  next certificates during a rotation with `KeyService::addNext()`, and only the current after `makeCurrent()` and
  `retire()`; the allow-list, never AES-256-GCM or RSA 1.5; the flags and NameID format following the settings; an
  incomplete connection described; a key with no certificate left out; no private key, ciphertext or secret; the same
  bytes for the same state.
- `tests/Feature/Connections/ServiceProviderDescriptionsTest.php`: unknown and other-tenant connections refused
  identically; a disabled or incomplete connection described; `protocol_unavailable`; any protocol's driver asked; no
  freshness asked and nothing written.
- `tests/Unit/Architecture/SamlLibraryBoundaryTest.php`: only the adapter's namespace names the library.

## Change Triggers

- saml2 v7, or `xml-security` fixing the AES-256-GCM URI (`saml-library.md`): AES-256-GCM may be allowed and advertised.
- A second assertion consumer service or binding, single logout, or requested attributes: each adds an element here
  and a test of it.
- Signed metadata, an `ID`, `validUntil` or `cacheDuration`: the determinism invariant and its test change with it.
- A new NameID format, switch or encryption algorithm in the SAML settings: the metadata reflects it.
- The endpoint resolver contract or the key ring's `published()` order changes.
