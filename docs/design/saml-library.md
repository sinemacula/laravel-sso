# SAML Library

## Purpose

This note records the comparison behind the choice of SAML library: which maintained library parses SAML messages and
verifies their signatures (SSO-6.1). Three candidates went through the same adversarial fixture set, and then through
the remaining criteria: schema validation, whether the verified element can be reached for SSO-6.3's absolute-path
check, per-connection algorithm control (SSO-6.7), PHP 8.3 to 8.5, dependency fit with Laravel 12 and 13 (Symfony 7.4
and 8), release cadence and maintenance. The package uses `simplesamlphp/saml2` `~6.2.4` with
`simplesamlphp/xml-security` `~2.3.1`, under the conditions in the decision below. The fixtures go on to seed the
package's fake SAML identity provider.

Candidates:

- `simplesamlphp/saml2` 6.2.4, with `xml-security` 2.3.1, `xml-common` 2.8.2 and `assert` 2.0.2. The newest 6.x tag,
  6.3.0, cannot be installed (see the v6 findings).
- `simplesamlphp/saml2` 5.0.8, with `xml-security` 1.13.9 and `xml-common` 1.25.1.
- `onelogin/php-saml` 4.3.2, with `robrichards/xmlseclibs` 3.1.5.

## Method

- **Fixtures.** A generator makes throwaway RSA keys with OpenSSL: a trusted IdP key, an attacker key and an SP
  encryption key. It writes 40 SAML Responses and a manifest that gives the outcome SSO-6 requires for each one. The
  signer in the generator is a minimal test tool (exclusive c14n, enveloped signature) and is never package code. The
  validity windows are wide (2026 to 2036), so the fixtures stay reusable; time checks are left to the tests of the
  fake identity provider. The set covers:
  - baselines: response signed, assertion signed, both signed, and encrypted with RSA-OAEP plus AES-256-GCM or
    AES-128-GCM;
  - integrity: a tampered NameID, an untrusted key whose certificate is in `KeyInfo`, and no signature at all;
  - wrapping: XSW1 to XSW8 (Somorovsky et al.), and an evil assertion that reuses the signed assertion's ID, placed
    before or after it;
  - duplicate IDs: a response and an assertion sharing one ID, and two identical signed assertions;
  - truncation: a comment inside a signed NameID (the response signed, and separately the assertion signed), and a
    processing instruction inside one;
  - DTDs: an unused internal subset, an external entity (`file://`), nested entity expansion (deliberately small), an
    external DTD, and an external entity in UTF-16 so that a byte-level `<!DOCTYPE` search cannot match;
  - algorithms: RSA-SHA1 with a SHA-1 digest, RSA-SHA256 with a SHA-1 digest, RSA PKCS#1 v1.5 key transport with
    AES-CBC and with AES-GCM, and RSA-OAEP with AES-CBC;
  - structure: two signed assertions, an unsigned assertion injected beside a signed one, a response signature whose
    reference names the assertion, an assertion carrying a signature over another ID inside a signed response,
    `URI=""`, c14n `WithComments`, and assertion children in an order the schema forbids.
- **Validators.** For each candidate, a validator uses the library the way a careful integrator would. It configures
  the trusted certificate, writes no cryptography or parsing of its own, and reads the subject from the library. Only
  policy is added: the size cap, the SSO-6.7 allow-list (read from the parsed `SignedInfo` and `EncryptionMethod`) and
  the key-transport algorithm the decryptor is built for. Where a library has two layers, both were run:
  - saml2's high-level `Response\Processor`;
  - its low-level `verify()`;
  - for v6, `verify()` plus one line of glue that copies a signed assertion into a document of its own first (see v6).
- **PHP versions.** Every candidate ran on PHP 8.3.32, 8.4.23 and 8.5.8 with `error_reporting=-1`, and gave identical
  verdicts on all three versions, with no deprecation or warning output.
- **Dependency fit.** Composer dry-runs checked each candidate against `laravel/framework` ^12 and ^13 (Symfony 7.4)
  and ^13 with Symfony 8 components on a PHP 8.4 platform. A dry-run also added each candidate to this package's own
  `composer.json` and lock.

## Results

Each cell gives the verdict for one fixture:

- **ok:** the outcome SSO-6 requires.
- **LAX:** accepted, and only the legitimate subject came out. It is not exploitable, but it breaks an SSO-6 rule that
  the package must then enforce itself.
- **FALSE:** a legitimate response refused.
- **ok†:** refused, but only because of the v6 embedded-assertion defect, not by design.
- **ok‡:** refused by the integrator's allow-list, not by the library's defaults.

No candidate was exploited by any fixture: none returned the attacker's subject, a truncated subject, or the contents
of the external entity.

| Fixture                                            | Required             | v6 Processor          | v6 `verify()`  | v6 `verify()` + re-root | v5 `verify()`         | onelogin     |
|----------------------------------------------------|----------------------|-----------------------|----------------|-------------------------|-----------------------|--------------|
| 01 response signed                                 | accept               | ok                    | ok             | ok                      | ok                    | ok           |
| 02 assertion signed                                | accept               | FALSE                 | FALSE          | ok                      | ok                    | ok           |
| 03 both signed                                     | accept               | FALSE                 | FALSE          | ok                      | ok                    | ok           |
| 04 encrypted, OAEP + AES-256-GCM                   | accept               | FALSE                 | FALSE          | FALSE                   | FALSE                 | ok           |
| 05 encrypted, OAEP + AES-128-GCM                   | accept               | FALSE                 | ok             | ok                      | ok                    | ok           |
| 10 tampered NameID                                 | refuse               | ok                    | ok             | ok                      | ok                    | ok           |
| 11 untrusted key in `KeyInfo`                      | refuse               | ok                    | ok             | ok                      | ok                    | ok           |
| 12 unsigned                                        | refuse               | ok                    | ok             | ok                      | ok                    | ok           |
| 20 to 27 XSW1 to XSW8                              | refuse               | ok                    | ok             | ok                      | ok                    | ok           |
| 28, 29 evil assertion with the same ID             | refuse               | ok                    | ok             | ok                      | ok                    | ok           |
| 30 response and assertion share an ID              | refuse               | LAX                   | ok             | ok                      | ok                    | ok           |
| 31 two identical signed assertions                 | refuse               | ok†                   | ok             | ok                      | ok                    | ok           |
| 40 comment in NameID, response signed              | full value or refuse | ok (full)             | ok (full)      | ok (full)               | ok (full)             | ok (full)    |
| 41 comment in NameID, assertion signed             | full value or refuse | ok†                   | ok†            | ok (full)               | ok (full)             | ok (full)    |
| 42 processing instruction in NameID                | full value or refuse | ok                    | ok             | ok                      | ok                    | ok           |
| 50 to 54 DTD, XXE, expansion, external DTD, UTF-16 | refuse               | ok                    | ok             | ok                      | ok                    | ok           |
| 60 RSA-SHA1                                        | refuse               | LAX                   | ok‡            | ok‡                     | ok‡                   | LAX          |
| 61 SHA-1 digest                                    | refuse               | LAX                   | ok‡            | ok‡                     | ok‡                   | LAX          |
| 62 RSA 1.5 + AES-CBC                               | refuse               | ok (TypeError)        | ok             | ok                      | ok                    | LAX          |
| 63 RSA 1.5 + AES-GCM                               | refuse               | ok (TypeError)        | ok             | ok                      | ok                    | LAX          |
| 64 OAEP + AES-CBC                                  | refuse (opt-in)      | ok (TypeError)        | ok‡            | ok‡                     | ok‡                   | LAX          |
| 70 two signed assertions                           | refuse               | ok†                   | ok†            | LAX                     | LAX                   | ok           |
| 71 unsigned assertion beside a signed one          | refuse               | ok                    | ok             | ok                      | ok                    | ok           |
| 72 response signature references the assertion     | refuse               | ok                    | ok             | ok                      | ok                    | ok           |
| 73 assertion signature over another ID             | refuse               | ok                    | ok             | ok                      | ok                    | ok           |
| 74 `URI=""`                                        | refuse               | ok                    | ok             | ok                      | ok                    | LAX          |
| 75 c14n `WithComments`                             | refuse               | ok                    | ok             | ok                      | ok                    | LAX          |
| 76 schema-invalid element order                    | refuse               | LAX                   | ok             | ok                      | ok                    | ok           |
| **Totals (40 fixtures)**                           |                      | 32 ok, 4 LAX, 4 FALSE | 37 ok, 3 FALSE | 38 ok, 1 LAX, 1 FALSE   | 38 ok, 1 LAX, 1 FALSE | 33 ok, 7 LAX |

Without schema validation, v6 and v5 `verify()` still refuse every wrapping fixture: the signature layer holds on its
own. Only fixtures 30, 31, 70 and 76 become LAX, and the package's own rules refuse each of them (duplicate IDs, exactly
one assertion, schema).

## Findings: `simplesamlphp/saml2` v6

- **Strongest design for SSO-6.3.** `verify()` takes a caller-built verifier and fails on any of the following:
  - the message's `SignatureMethod` is not the verifier's algorithm;
  - the reference is not this element's own `#ID`, or is `URI=""` on an element that is not the root;
  - a with-comments canonicalisation is used with a plain reference;
  - the root carries more than one signature.

  On success it returns a new object, rebuilt by parsing the exact bytes that were digested, so every value the
  package reads comes from the verified element. `Response::fromXML()` takes assertions only from the response's
  direct children, which are their schema position. The DOM element is still available through `getXML()`, so the
  package can make its absolute-path check.
- **Hardened parsing.** `DOMDocumentFactory::fromString()` refuses `<!DOCTYPE` before parsing and checks the parsed
  tree again afterwards, which catches the UTF-16 bypass. It parses with `LIBXML_NONET` and `LIBXML_NO_XXE` and resets
  the external entity loader. Text is read with `textContent`, so a comment cannot truncate a NameID.
- **Schema validation is bundled** (`Response::schemaValidate()`, with local XSDs that import each other by relative
  path, so validation makes no network request). It also enforces `xs:ID` uniqueness, which is what refuses fixtures
  30, 31 and the same-ID wrapping. One defect: the default schema path is relative to the working directory
  (`resources/schemas/...`) and fails with `File not found` unless the caller passes the absolute path.
- **Defect 1, blocking: an assertion signature inside a Response cannot be verified.** `SignedElementTrait` digests
  the owner document's root element, and `Assertion::fromXML()` keeps the assertion element inside the Response
  document. An assertion-only signed response is a common IdP configuration, and verifying it fails with
  `NoSignatureFoundException` (fixtures 02, 03 and 41). v5 did not have this defect because `xml-common` 1.x copied
  every child into a clean document; `xml-common` 2.0 removed that.
  - Upstream fixed it in saml2 PR #424 (merged 2026-08-18) on master only, which is the v7 line and needs PHP 8.5.
    Neither `release-6.2` nor `release-6.x` has the fix.
  - The workaround is the same three lines as the upstream fix: `importNode` the signed assertion into a document of
    its own before `verify()`. With it, v6 passes 02, 03 and 41.
- **Defect 2: AES-256-GCM is unusable.** `xml-security` 2.x defines `BLOCK_ENC_AES256_GCM` as
  `http://www.w3.org/2009xmlenc11#aes256-gcm` (a slash is missing), so the real URI is refused as an unsupported
  algorithm (fixture 04). The fix is `xml-security` issue #91 and is only in 3.x (PHP 8.5). AES-128-GCM and AES-192-GCM
  work. 2.3.1 includes the GCM tag-validation fix (GHSA-r353-4845-pr5p).
- **Defect 3: dependency fit with Guzzle 8.**
  - `simplesamlphp/assert` 2.x and `xml-common` 2.8 require `guzzlehttp/psr7` `~2.8`, and Guzzle 8 requires psr7
    `^3`, so v6 installs only beside Guzzle 7. Adding v6 to a lock on Guzzle 8.3.1 resolved only by downgrading it to
    7.16.1.
  - Laravel 12 and 13 on Symfony 7.4, and Laravel 13 on Symfony 8 (PHP 8.4 platform), resolve cleanly.
  - `xml-common` needs the Composer plugin `simplesamlphp/composer-xmlprovider-installer`. A non-interactive install
    fails until the application allows it in `allow-plugins`.
- **The high-level `Response\Processor` is not usable.**
  - It builds the signature factory with an empty blacklist, so it accepts RSA-SHA1 and SHA-1 digests.
  - It throws a `TypeError` on every encrypted assertion: its `Decrypter` passes a key where `decrypt()` expects an
    algorithm.
  - It skips schema validation.
  - Its signature check returns a boolean and discards the verified object.

  The package uses the low-level API only.
- **Foot-gun.** `verify()` called with no verifier falls back to the certificate in the message's `KeyInfo`, and it
  accepted the attacker-signed fixture 11. The package must always pass a verifier built from the connection's trusted
  certificates, and an architecture test should forbid the argument-less call.
- **Algorithm control (SSO-6.7), all per call, so per connection:**
  - **Signatures:** the caller picks the algorithm. The factory's blacklist is per instance, and its default refuses
    RSA-SHA1.
  - **Digests:** the library has no control. The package checks `DigestMethod` on the parsed `SignedInfo`, which is
    covered by the signature. `validateReference()` also digests only the last `Reference`, so the package should
    require exactly one, as SSO-6.2 does anyway.
  - **Key transport:** the caller-built decryptor pins the algorithm and refuses a mismatch before decrypting.
    RSA 1.5 is blacklisted by default.
  - **Content encryption:** the library's blacklist lives in the process-wide `ContainerSingleton`, so the package
    checks `EncryptionMethod` before calling `decrypt()`.
  - **Order:** decryption happens only when the caller asks for it, so "verify the Response before decrypting
    AES-CBC" is enforceable.
- **Octane.** A process-wide `ContainerSingleton` (logger, clock, encryption blacklist) must be set once at boot with
  immutable values. All per-connection policy stays in per-call objects. No request state is kept in statics.
- **PHP.** v6 requires `^8.3` and was clean on 8.3, 8.4 and 8.5.
- **Maintenance.**
  - The project is active (last push 2026-10-26, 14 open issues). The 6.x releases came about monthly through 2026
    (6.1.0 in February to 6.2.4 on 2026-08-09), and security advisories were patched within days (GHSA-r7hw-jx6r-756g
    in 6.2.4).
  - Version 6.3.0 is a hazard. It was tagged on 2026-08-09 from the older `release-6.x` line (PHP `^8.2`). It requires
    `assert` `~1.9`, which pins `guzzlehttp/psr7` `~2.8.0`, and every 2.8.x has advisories. Composer's advisory blocking
    makes it uninstallable; with blocking off, `^6.2` would select it. The package must constrain to `~6.2.4`.
  - Upstream's own README still names 4.x as the preferred version. The v5 and v6 release notes call those versions
    "in no way a replacement" and "still no full replacement" for v4.
  - SimpleSAMLphp master still processes responses with `simplesamlphp/saml2-legacy` 4.20, so the v6 response path is
    not exercised by its flagship product, which is why defect 1 shipped.
  - v7 (RC4, 2026-10-23, PHP `^8.5`) fixes all three defects: PR #424, the GCM URI, and `assert` 3.x, which drops
    psr7.

## Findings: `simplesamlphp/saml2` v5

- `verify()` and parsing match v6 (the same design, as strings rather than value objects), and v5 verifies an embedded
  assertion signature without glue. Through `verify()` it shares v6's results, including the AES-256-GCM typo. Its
  `Response\Processor` fails on encrypted assertions (`Class "SimpleSAML\XMLSecurity\XMLSecurityKey" not found`) and is
  LAX on SHA-1, schema and duplicate IDs.
- **Eliminated on dependency fit.** `xml-common` 1.25 requires `symfony/finder` `~6.4.0`, while Laravel 12 requires
  `^7.2` and Laravel 13 requires `^7.4 || ^8.0`, so neither resolves. `assert` 1.8 also pins `webmozart/assert`
  `~1.11.0` and psr7 `~2.7`.
- 5.0.8 (2026-07-06) receives security fixes only.

## Findings: `onelogin/php-saml` 4.x

- **Fixture set.** It refuses every wrapping, duplicate-ID, comment and DTD fixture and has no false refusals, and it
  is the only candidate that decrypts AES-256-GCM. It refuses wrapping mainly through its own structural checks:
  exactly one assertion, a signature only on `Response` or `Assertion`, the reference must equal the parent's ID, and
  absolute XPath queries. Schema validation (`wantXMLValidation`) is bundled. `loadXML()` parses first and then refuses
  any DOCTYPE node; no entity was resolved.
- **No algorithm control for incoming messages.**
  - The `signatureAlgorithm` and `digestAlgorithm` settings apply only to signing. It accepted RSA-SHA1, SHA-1
    digests, RSA 1.5 key transport (the decryption key is built as `RSA_1_5` and silently upgraded to OAEP when the
    message says so), AES-CBC, `URI=""` and `WithComments`.
  - The only way to meet SSO-6.2 and SSO-6.7 would be package-written checks on XML that has not yet been verified.
- **It decrypts in the constructor,** before any signature check, so SSO-6.7's rule for AES-CBC ("verify the Response
  before decrypting") cannot be met.
- **No handle on the verified element.** Values come from its own getters, which run XPath over the document, so
  SSO-6.3 would rest on its internal queries rather than on an element the package resolved.
- **Octane.** `Response::__construct()` calls `Utils::setBaseURL()`, a process-wide static, from per-connection
  settings, and the destination check reads `$_SERVER`. Both carry state across requests and connections in a
  long-lived worker.
- **Maintenance.**
  - 4.3.2 (2026-05-07) and the last commit (2026-08-06) leave 61 open issues.
  - It pins `robrichards/xmlseclibs` `^3.1.5`. xmlseclibs published repository advisories on 2026-08-24, fixed only in
    4.0: RSA-to-HMAC key confusion, a Bleichenbacher oracle on RSA 1.5, a CBC padding oracle, and a DoS through XPath
    transforms.
  - php-saml mitigates some of them itself (its signing-algorithm check refuses HMAC, and DOCTYPE is refused), but not
    RSA 1.5 or CBC. The issue and PR to move to xmlseclibs 4 (#654, #655, September 2026) are unmerged.
  - `composer audit` does not report any of this, because the advisories have no CVE and are not in the global
    database.
- **Dependency fit and PHP.** It resolves with Laravel 12 and 13, Symfony 7.4 and 8, and Guzzle 8. It requires PHP
  `>=7.3` and was clean on 8.3, 8.4 and 8.5.

## Criteria Summary

| Criterion                                  | saml2 v6 (6.2.4)                                                                 | saml2 v5 (5.0.8)               | onelogin 4.3.2                                                   |
|--------------------------------------------|----------------------------------------------------------------------------------|--------------------------------|------------------------------------------------------------------|
| Fixture gate (nothing exploitable)         | Met with re-root glue; AES-256-GCM refused                                       | Met; AES-256-GCM refused       | Met for wrapping, IDs, comments and DTDs; algorithm fixtures LAX |
| Schema validation                          | Bundled; pass the schema path explicitly                                         | Bundled                        | Bundled (`wantXMLValidation`)                                    |
| Verified element reachable (SSO-6.3)       | Yes: `verify()` returns an object rebuilt from the digested bytes                | Yes                            | No: internal XPath only                                          |
| Per-connection algorithm control (SSO-6.7) | Yes: per-call verifier and decryptor; digest and content checks on parsed values | Yes, as v6                     | No                                                               |
| Verify before decrypt                      | Caller controls the order                                                        | Caller controls the order      | No: decrypts in the constructor                                  |
| PHP 8.3 to 8.5                             | Clean                                                                            | Clean                          | Clean                                                            |
| Laravel 12 and 13, Symfony 7.4 and 8       | Yes; caps Guzzle at 7; needs `allow-plugins`                                     | No (`symfony/finder` `~6.4.0`) | Yes                                                              |
| Octane and queue safety                    | Container set once at boot; nothing per request                                  | As v6                          | Static base URL and `$_SERVER` reads                             |
| Maintenance                                | Active; two 6.x lines; fixes land on v7 (PHP 8.5)                                | Security fixes only            | Slow; vulnerable xmlseclibs 3.x pinned                           |

## Decision

The package uses `simplesamlphp/saml2` v6, constrained to `~6.2.4`, with `simplesamlphp/xml-security` constrained to
`~2.3.1`. It is the only candidate that meets SSO-6.3 and SSO-6.7 through the library rather than around it.
onelogin's handling of wrapping is sound, but it cannot control algorithms, it decrypts before verifying, it keeps
process-wide state, and it is pinned to an xmlseclibs line with unfixed advisories, so it fails SSO-6.7 and the suite's
Octane rule. v5 cannot be installed beside Laravel 12 or 13.

The decision holds under these conditions, and the package's SAML adapter has a test for each one:

1. **Only the low-level API.** Use `DOMDocumentFactory::fromString()`, `Response::schemaValidate()` with the absolute
   schema path, `fromXML()`, `verify()` and `decrypt()`. Never use `Response\Processor` or the `Signature\Validator`
   chain.
2. **Always a pinned verifier.** `verify()` always receives a verifier built from the connection's trusted
   certificates, and an architecture test forbids calling it without one.
3. **Re-root every signed assertion.** Copy it into a document of its own before `verify()`, the same change as
   upstream PR #424, and read every value only from the object `verify()` returned. Before decrypting or verifying,
   check by absolute path that the signed element is the root `Response` or the single `/samlp:Response/saml:Assertion`.
4. **The package owns SSO-6.7 policy.** Check `SignatureMethod`, `DigestMethod`, a single `Reference` and its
   transforms on the parsed `SignedInfo`. Build the decryptor for RSA-OAEP only, check `EncryptionMethod` before
   `decrypt()`, and verify a trusted Response signature before decrypting AES-CBC. The ordering must be enforceable,
   and v6 lets the caller control it.
5. **AES-256-GCM is out until v7.** The package's SP metadata advertises AES-128-GCM and AES-192-GCM only, and the
   documentation states the limit.
6. **Guzzle is held at 7.** The package requires `guzzlehttp/guzzle` `^7.9` and documents why. Guzzle 8 returns when
   saml2's dependencies allow `guzzlehttp/psr7` 3.x, or with v7, which requires PHP 8.5.
7. **Composer setup.** The installation guide tells applications to allow the
   `simplesamlphp/composer-xmlprovider-installer` plugin.

Move to saml2 v7 when the package's PHP floor reaches 8.5. v7 removes conditions 3, 5 and 6, but the API changes to
PHP's new DOM classes, so the adapter has to be rewritten, not reconfigured.

## Implementation Anchors

- The package's hardened SAML parsing wraps the calls in condition 1, and the re-rooting in condition 3, behind one
  package-owned adapter, so no other class touches the library.
- The fixture generator and the 40 fixtures, with their manifest, move into the test suite with the package's fake
  SAML identity provider. Each fixture's required outcome becomes a test of the package's validator, not of the
  library.

## Change Triggers

- saml2 6.2.x backports PR #424, or `xml-security` 2.x fixes the AES-256-GCM URI: drop the matching condition.
- `assert` or `xml-common` 2.x loosens `guzzlehttp/psr7` to allow 3.x: restore Guzzle 8.
- The package's PHP floor moves to 8.5: re-run this comparison against saml2 v7 and plan the adapter rewrite.
- An advisory against `saml2`, `xml-security` or `xml-common`: re-run the fixture set against the patched version
  before taking it.
- onelogin moves to xmlseclibs 4 and adds incoming algorithm allow-lists: it can be reconsidered.
