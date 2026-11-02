# SAML Adapter

## Purpose

This note records the package's SAML adapter: the one place the package calls `simplesamlphp/saml2` and
`simplesamlphp/xml-security`, how it parses, verifies and decrypts a posted `SAMLResponse`, and what it answers the
SAML driver (SSO-6.1 to SSO-6.3, SSO-6.7, SSO-6.8, SSO-6.11). It holds the conditions `saml-library.md` set on the
choice of library. What the driver then checks of the response it is given (correlation, audience, times, subject,
replay) is the driver's, not the adapter's.

## Invariants

- Every call into either library is made inside `Protocols\Saml2\Library`, and nothing outside that namespace names
  either library. `Library\SamlAdapter` is the namespace's entry for responses; the `AuthnRequest` writer
  (`saml-requests.md`), the metadata reader (`metadata-refresh.md`) and the service provider metadata writer
  (`service-provider-metadata.md`) live in the same namespace, under the same rules. An architecture test holds this.
- Only the low-level API is used: `DOMDocumentFactory::fromString()`, `Response::schemaValidate()` with the absolute
  path of the schema for the kind of message (`Library\Enums\MessageKind`), `fromXML()`, `verify()` and `decrypt()`.
  `Response\Processor` and `Signature\Validator` are never named; the architecture test forbids both.
- `verify()` is called only by `Library\PinnedVerifier`, and always with a verifier built from the certificates the
  connection trusts for the use (`idp_signing` for messages, `metadata_signing` for metadata). The architecture test
  forbids a call without a verifier, and any call outside the pinned verifier.
- Every message is capped before it is decoded (`sso.saml2.max_response_bytes`), its decoded XML capped before it is
  parsed (`max_xml_bytes`), and a decrypted assertion capped before it is parsed (`max_decrypted_bytes`). Base64 is
  decoded strictly, and HTTP-POST is never inflated.
- Parsing refuses a document type declaration and every entity, and never reaches the network. Schema validation
  loads only the library's own schema files: the external entity loader is restricted to them while it runs. A
  repeated `ID`, `Id`, `id` or `xml:id` anywhere in the document is refused.
- A comment or processing instruction cannot change a value: values are read from the verified object or, for what the
  library does not model (other statements and conditions, `Advice`), from the element
  `PinnedVerifier::verifiedElement()` answers, parsed from exactly the bytes the signature digested into a document of
  its own, as text content, never by string search and never from the posted document. A decrypted assertion covered
  only by the response's signature is read from its plaintext; metadata is read from the bytes the innermost signature
  on the entity's path digested.
- Structure is checked by absolute path before any signature is verified or anything decrypted: the root is a
  `samlp:Response`; every `ds:Signature` is a child of the root or of `/samlp:Response/saml:Assertion`; every
  `Assertion` or `EncryptedAssertion` is a child of the root, and there is at most one.
- A signed assertion is copied into a document of its own before `verify()` (the re-rooting upstream PR #424 makes),
  and every value is read from the object `verify()` returns and the element parsed from the bytes it digested.
- The package owns the SSO-6.7 policy on the parsed `SignedInfo`: the `SignatureMethod` in the connection's allow-list
  (RSA-SHA256, RSA-SHA384 or RSA-SHA512), the `DigestMethod` SHA-256, SHA-384 or SHA-512, exactly one `Reference` to
  the signed element, and only the enveloped-signature and exclusive canonicalisation transforms.
- Decryption is RSA-OAEP key transport only, with exactly one `EncryptedKey`; the `EncryptionMethod` is checked against
  the connection's allow-list before `decrypt()`. AES-128-GCM and AES-192-GCM are allowed; AES-CBC only when the
  connection lists it and the response carries a verified signature. AES-256-GCM is out until the PHP floor moves to 8.5
  and saml2 v7 is stable (`saml-library.md`, condition 8). Every decryption failure is the one refusal
  `decryption_failed`, whichever key or step failed.
- An assertion that no verified signature covers, its own or the response's, is refused. An unsuccessful response reads
  no assertion, but every signature it carries must still verify.
- The response is read into the package's values (`Protocols\Saml2\Messages`). Each holds what the identity provider
  asserted in a `\SensitiveParameterValue`, redacts it from debug output and JSON, and refuses to be serialised or
  unserialised. The adapter never logs, reports or keeps what it read; a refusal's detail is the package's own word
  for the rule (`schema`, `signature_policy`, `assertion_location`), never the message.
- The library's container is set once per process to the package's own (`Library\LibraryContainer::ensure()`): no
  logger output, no clock, temporary files, redirects or blacklist. Ensuring it again is a no-op while it is the
  package's own, so it is safe under Octane and in queue workers; a container something else set first (an
  application using the library itself) is refused with a `LogicException` naming its class, never silently inherited,
  since its clock, logger, files and blacklist would apply to every SAML message the package reads. Nothing in the
  namespace keeps anything between calls (SSO-11.2).

## Success Path

- The driver reads the envelope first: `SamlAdapter::envelope()` answers every `InResponseTo` in the capped, hardened
  parse and whether the assertion is encrypted, before anything is validated, so the completion can find the request.
- `SamlAdapter::readResponse()` with the connection's `ResponsePolicy` (trusted certificates, the algorithm
  allow-lists, and the decryption keys, asked for only when an assertion is encrypted) answers a `ReadResult` holding
  a `SamlResponse`: its status, issuer, destination, `InResponseTo`, whether it was signed, and its one assertion, every
  signature verified.
- The response's profile (`Messages\Enums\ValidationProfile`) is `solicited` when an `InResponseTo` appears anywhere in
  it, the decrypted assertion included, `unsolicited` when none does, and `unsuccessful` when its status is not
  success. The driver applies the rules of the profile.

## Failure / Edge Cases

- Too large, not base64, unparseable, a DTD or entity, a schema failure, or a repeated `ID`: `response_invalid`.
- A signature in the wrong place, a wrapped, injected or second assertion, or a decrypted assertion that is not one
  `saml:Assertion`: `response_invalid`.
- A missing, unverifiable or out-of-policy signature, or an assertion no verified signature covers:
  `signature_invalid`.
- A disallowed key transport or data encryption algorithm, an AES-CBC assertion without a verified response signature,
  more than one `EncryptedKey`, or any decryption failure: `decryption_failed`.
- A response the library cannot map (an element it refuses after the schema accepted it) is refused as
  `response_invalid` with the detail `structure`, never thrown.
- An envelope that cannot be read is `null`: the completion treats it as uncorrelated.

## Implementation Anchors

- `src/Protocols/Saml2/Library/SamlAdapter.php`, `HardenedParser.php`, `ResponseReader.php`, `PinnedVerifier.php`,
  `AssertionDecryptor.php`, `AssertionMapper.php`, `LibraryContainer.php`, `ReadFailure.php`; the namespace's other
  entries, `AuthnRequestWriter.php`, `MetadataReader.php` (with `SignedDescriptor.php`, the signed descriptor it
  verifies) and `MetadataWriter.php`
- `src/Protocols/Saml2/Messages/`
- `src/Protocols/Saml2/Saml2Limits.php`
- `src/Testing/FakeSamlIdentityProvider.php` and `src/Testing/Saml/`: the fake identity provider whose responses and
  metadata the tests read, signed and encrypted with OpenSSL alone, with every wrapping variant.

## Authoritative Tests

- `tests/Unit/Architecture/SamlLibraryBoundaryTest.php`
- `tests/Feature/Protocols/Saml2/Library/AdversarialFixturesTest.php`: each of the 40 fixtures of the library
  comparison, with the outcome `tests/Fixtures/Saml/manifest.json` pins for the package, and
  `tests/Feature/Completion/SamlFixtureCompletionTest.php`: the same fixtures through the public completion path.
- `tests/Feature/Protocols/Saml2/Library/SamlAdapterTest.php`
- `tests/Feature/Protocols/Saml2/Library/LibraryInternalsTest.php`
- `tests/Feature/Protocols/Saml2/Library/AuthnRequestWriterTest.php`, `MetadataReaderTest.php`,
  `SignedDescriptorTest.php` and `MetadataWriterTest.php`
- `tests/Unit/Protocols/Saml2/Messages/MessageValuesTest.php`
- `tests/Feature/Testing/FakeSamlIdentityProviderTest.php`

## Change Triggers

- A saml2 or xml-security release: re-run the fixture set before taking it.
- The PHP floor reaches 8.5: the move to saml2 v7 rewrites this namespace on PHP's new DOM classes, and AES-256-GCM
  joins the allow-list.
- A new message kind (logout, artefact): its own schema, cap and profile, and the same boundary.
