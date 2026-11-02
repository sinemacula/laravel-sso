# Signing In with SAML

This guide is for whoever sets up a SAML 2.0 connection: the settings an administrator chooses, what the package holds
every response to, and the limits it applies. Setting a connection up step by step is described in
[Setting up a SAML connection](saml-connections.md); completing the flow in your API in
[Completing a Flow](completing-a-flow.md); the connection's keys and the identity provider certificates it trusts in
[Keys](keys.md).

## What the identity provider is given

Give the identity provider the connection's service provider entity id and its assertion consumer service URL, both
built from `sso.endpoints` and never from a request. Every response must be posted (HTTP-POST binding) to exactly that
URL: its `Destination`, which must be present whether or not the response is signed, and the `Recipient` of its bearer
confirmation, are compared with it byte for byte, and every `AudienceRestriction` in the assertion must name the entity
id. An identity provider that leaves `Destination` out is refused with `recipient_mismatch`.

## The connection's settings

| Setting                          | Default                  | What it decides                                     |
|----------------------------------|--------------------------|-----------------------------------------------------|
| `idp_entity_id`                  | none                     | The `Issuer` of every response and assertion        |
| `subject_source`                 | `name_id`                | Whether the subject is the `NameID` or an attribute |
| `subject_attribute`              | none                     | The attribute holding a stable identifier           |
| `name_id_format`                 | `persistent`             | The one `NameID` format accepted                    |
| `want_assertions_signed`         | on                       | Whether the assertion must carry its own signature  |
| `require_encrypted_assertions`   | off                      | Whether a plain assertion is refused                |
| `signature_algorithms`           | RSA, SHA-256 or stronger | The signature algorithms accepted                   |
| `encryption_algorithms`          | RSA-OAEP, AES-GCM        | The key transport and data encryption algorithms    |
| `requested_authn_context`        | none                     | The context classes one of which must be asserted   |
| `max_authentication_age_seconds` | none                     | How long ago the person may have authenticated      |
| `idp_initiated`                  | off                      | Whether an unsolicited response is re-initiated     |
| `idp_initiated_start_url`        | none                     | Where a re-initiated sign-in sends the browser      |

The settings that decide how requests are sent (`sso_url`, `sso_binding`, `sign_authn_requests`, `force_authn`) and
how metadata is refreshed (`metadata_url`, `metadata_refresh`) are listed with what each allows in
[Managing connections](managing-connections.md#saml-settings). An unsolicited response never signs anyone in: with
`idp_initiated` on it is checked in full and the browser sent to the start URL (see
[IdP-initiated sign-in](idp-initiated-sign-in.md)).

## The subject

By default the subject is a persistent `NameID`. Its `Format` must be the one the connection names, exactly; a transient
`NameID` is never a subject, and a `NameID` without a `Format` is accepted only when the connection names
`unspecified`. Its `NameQualifier`, when present, must be the identity provider's entity id, and its `SPNameQualifier`,
when present, the service provider's.

> **Warning:** choose `email` or `unspecified` only when the identity provider offers nothing stable. An identity
> provider may reassign an email address or an unspecified identifier to another person, who would then sign in to the
> first person's account. Prefer `persistent`, or an attribute holding an identifier the provider never reuses.

The subject is stored with its kind, its format and its qualifiers, exactly as received: never trimmed, case-folded or
normalised. A qualifier that the provider starts or stops sending, or a change of format, therefore makes a different
subject, and the existing link no longer matches: plan such a change with the subject migration helper. A subject
whose stored form would exceed 1,024 bytes is refused, never truncated.

With `subject_source` set to `attribute`, the subject is the one value of the one attribute whose `Name` is exactly
`subject_attribute`: present once, with exactly one non-empty text value.

## Signatures and encryption

Every signature in a response must verify with a certificate the connection trusts; a certificate the response carries
only selects among those. The assertion must be covered by a verified signature, its own or the response's, and, with
`want_assertions_signed` on, by its own.

Encrypted assertions are decrypted with the connection's current encryption key, or a retiring one still within its
overlap, by RSA-OAEP only. Content encryption is AES-128-GCM or AES-192-GCM. AES-256-GCM cannot be accepted: the SAML
library the package uses cannot decrypt it until a later major version, so it is neither accepted nor advertised.
AES-CBC is accepted only when you list it in `encryption_algorithms`, for an identity provider that offers nothing
else, and then only inside a response whose own signature verifies before anything is decrypted. Every decryption
failure is the same `decryption_failed`, whatever the cause.

With `require_encrypted_assertions` on (and `sso.features.encrypted_assertions` enabled), a plain assertion is refused
with `encryption_required`, so a response cannot be downgraded.

## Time

Every time check allows the clock skew `sso.clock.skew_seconds` (60 seconds by default, at most 300):

- the assertion's `Conditions`, when present, must have started and not ended;
- the bearer confirmation must carry a `NotOnOrAfter` that has not passed, and must not carry `NotBefore`;
- the response's and the assertion's `IssueInstant` must not be in the future, nor older than
  `sso.saml2.issue_instant_max_age_seconds` (300 by default, 30 to 3,600);
- the `AuthnInstant` must not be in the future, and, with `max_authentication_age_seconds` set, no older than it; a
  reauthentication must have authenticated after the request started;
- a `SessionNotOnOrAfter` that has passed refuses the response, with no skew; otherwise it becomes the result's provider
  session deadline.

Each assertion is recorded against replay until the last moment any of these rules would still accept it, so the same
assertion is never accepted twice.

## Failures

A refused response redirects to your application with the reason once its request has been found, or is rejected with
`request_unknown` when it names none. An identity provider's error status is `provider_error`: its status message is
logged only after sanitising, and is never shown or put in an event. The other reasons are listed in
[Events](events.md).
