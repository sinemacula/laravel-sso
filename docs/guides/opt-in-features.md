# Opt-In Features and Their Risks

Every feature of the package is off until you turn it on, but for the scheduled refresh of what connections fetch from
their identity providers, and every security check of a feature that is on is always on. This guide lists each flow
and each opt-in once: what it does, what turning it on commits you to, and what can go wrong. Each entry links to the
guide that describes it in full. Read the entries for what you are about to turn on before you turn it on.

A switch under `sso.features` makes a feature available; it never opts a connection or an application in. The boot
check (`php artisan sso:check`) refuses what is on without what it needs.

## The flows

Every flow starts with an authorisation request, completes at the connection's assertion consumer service or callback,
and ends with a single-use handoff code the client redeems with its verifier. What each proves differs.

| Flow                                                                     | What it proves                                                                                         | What it does not prove, and the risk                                                                                                                                                                                                                           |
|--------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `sign_in` ([Completing](completing-a-flow.md))                           | The identity provider authenticated the subject its link names, for the client that started the flow   | Nothing about a further factor ([Evidence](#accepting-provider-evidence)). The client's duties hold the binding together: a client that leaks its verifier or keeps the code in a URL undoes it ([The client's part](example-application.md#the-clients-part)) |
| `link` ([Links](links.md))                                               | The caller your application authenticated also controls this subject                                   | Holding the code proves which client started the flow, not who calls now: the redemption must be given the authenticated caller. It needs fresh authentication and your eligibility contract, both refusing by default                                         |
| `reauthenticate` ([Re-authenticating](reauthenticating.md))              | Fresh authentication at the provider, after the request started, by the same identity, for one session | Not a further factor. It renews one session's authentication time and nothing else, and depends on the provider honouring `ForceAuthn` or `prompt=login`: a provider that does not report a fresh time is refused                                              |
| Discovery ([Discovery](discovery.md))                                    | Which connection an email's verified domain routes to                                                  | Never whether a person has an account, but always whether a domain uses single sign-on: see [Discovery](#discovery)                                                                                                                                            |
| IdP-initiated ([IdP-initiated sign-in](idp-initiated-sign-in.md))        | Nothing: an unsolicited response is checked, recorded and re-initiated                                 | Signs nobody in. See [Sign-in started at the identity provider](#sign-in-started-at-the-identity-provider)                                                                                                                                                     |
| Provisioning ([Provisioning](provisioning.md))                           | That a `sign_in` resolved to nobody                                                                    | That the person is new to your application: resolving an existing identity from the email or any attribute is forbidden, and the identity your listener creates must be new. A provisioned identity can survive a later failure of the completion              |
| Linking by a verified domain ([Linking by domain](linking-by-domain.md)) | That a tenant's existing member signed in through its provider, by email                               | See [Linking by a verified domain](#linking-by-a-verified-domain): the strongest assumptions the package makes                                                                                                                                                 |

## Protocols

`SSO_SAML2` and `SSO_OIDC` (`sso.features.saml2`, `sso.features.oidc`) turn the protocols on. With neither on the
package is not in use. A protocol on needs `sso.endpoints.base_url` and at least one application, and each connection
is created disabled and is used only once it is complete and enabled.

- **SAML** is RSA only on PHP 8.3, with AES-128-GCM or AES-192-GCM for encryption: a provider that signs only with
  ECDSA or encrypts only with AES-256-GCM cannot be connected yet ([Installation](installation.md)).
- **OpenID Connect** pins each connection's ID token algorithms and never negotiates them; a narrow list can refuse a
  provider that moves to another algorithm ([Setting up an OIDC connection](oidc-connections.md#risks)).

## Discovery

`SSO_DISCOVERY` with `sso.applications.<name>.discovery.enabled` and a `fallback_url`. A person types an email address
and the package routes its domain to the connection the domain is verified for.

- **What it discloses.** Discovery reads only the domain, so it never reveals whether a person has an account. But
  where the answer leads still shows whether a domain signs in through single sign-on: anyone can learn that
  `example.com` uses an identity provider by trying an address at it. Do not offer discovery where that fact is itself
  sensitive.
- **Timing is mitigated, not hidden.** A match and a miss answer in the same shape, and every start is padded to
  `sso.discovery.minimum_duration_milliseconds`. Work that outlasts the floor (a slow provider or database) still
  shows, and every start holds its worker for the floor, so plan capacity for it.

See [Discovery](discovery.md).

## Enforcement and exemptions

`SSO_ENFORCEMENT`, then a tenant's rule through `EnforcementService::update()`. Every session in the tenant must be
established through one of the rule's enabled connections.

- **Existing sessions.** Turning a rule on revokes the sessions it no longer allows, through your
  `Contracts\SessionRevocation`, in the same transaction. **The default revocation does nothing**: without
  `laravel-authentication`, bind your own, or every session established before the rule survives it.
- **Lock-out.** A rule needs one of its connections enabled with a completed sign-in, so an untried connection cannot
  lock a tenant out; disabling or deleting the last satisfying connection is allowed, keeps the rule, and revokes the
  sessions through it.
- **Exemptions** (`Contracts\EnforcementExemption`, asked through `ExemptionGate`) let a break-glass administrator in
  while the provider is down. Each exemption granted is reported as `ExemptionUsed`; keep the list short and watch the
  event.
- **An enforcement contract of your own** must serialise an admission against changes to its rule until the session's
  transaction commits; a current read alone lets a session escape a change.

See [Enforcement](enforcement.md).

## Encrypted assertions

`SSO_ENCRYPTED_ASSERTIONS`, then `require_encrypted_assertions` on a SAML connection, with a service provider
encryption key whose certificate the provider encrypts to.

- **What it buys.** The assertion is unreadable to the browser and anything on its way, so its attributes do not leak
  through a log or an extension. Signatures, not encryption, decide what is trusted.
- **What it costs.** Once required, a plain assertion is refused (`encryption_required`), so a provider that stops
  encrypting stops signing people in. The encryption key has to be rotated with the provider in step
  ([Keys](keys.md)), and only RSA-OAEP with AES-128-GCM or AES-192-GCM is accepted by default.

## AES-CBC compatibility

Listing an AES-CBC algorithm in a SAML connection's `encryption_algorithms`, for a provider that encrypts with nothing
else.

- **The risk.** CBC is malleable: an attacker who can alter a ciphertext and observe how decryption fails can learn
  its plaintext. The package therefore accepts CBC only inside a response whose own signature verifies before anything
  is decrypted, and answers every decryption failure with the same `decryption_failed`.
- **What it needs.** The provider must sign the whole response, not only the assertion; a CBC assertion in an
  unsigned response is refused. Prefer AES-GCM wherever the provider offers it, and take CBC off the list when it does.

See [Signing in with SAML](saml-sign-in.md#signatures-and-encryption).

## Reassignable NameID formats

A SAML connection's `name_id_format` of `email` or `unspecified`, in place of the default `persistent`.

- **The risk.** A link is keyed by the subject. An identity provider may reassign an email address or an unspecified
  identifier to another person, who then signs in to the first person's account through the existing link.
- **Prefer** a persistent `NameID`, or `subject_source` `attribute` naming an attribute that holds an identifier the
  provider never reuses (an immutable object id). Changing the subject settings of a connection with links needs a
  subject migration ([Managing connections](managing-connections.md#migrating-subjects)).

See [Signing in with SAML](saml-sign-in.md#the-subject).

## UserInfo

`fetch_userinfo` on an OIDC connection, with its `userinfo_endpoint`.

- **What it changes.** Claims the ID token leaves out come from UserInfo, for attribute mapping and the linking email
  only, never for the issuer or the subject, and only when its `sub` equals the ID token's byte for byte.
- **It fails closed.** While it is on, a UserInfo failure stops the sign-in: one attempt, no retry, within
  `sso.oidc.userinfo_timeout_seconds`. A provider whose UserInfo endpoint is down stops sign-in through the connection.
  Only plain JSON is accepted. Turning it on or off is a trust change.

See [OIDC claims](oidc-claims.md).

## Metadata refresh

`SSO_METADATA_REFRESH`, the one feature on by default, with a queue worker and the schedule.

- **OpenID Connect.** A connection's discovery document and JWKS are refetched on the schedule, and the JWKS once more
  when an ID token names an unknown key, at most once per cooldown. A refresh can move the token endpoint and the
  JWKS: it voids what is in flight and reports `ConnectionUpdated`. A document is trusted as far as TLS to the issuer's
  host; enter endpoints by hand and turn `metadata_refresh` off on the connection if that is more than you accept.
- **SAML with a signing anchor** refreshes by default: the metadata's signature, by an anchor you trusted, decides.
- **SAML without an anchor** refreshes only after an administrator sets `metadata_refresh` to `true`, which delegates
  trust to the URL and its TLS: whoever controls the URL then decides which certificates you trust.
- **The stale limit.** What a refreshing connection fetched stops being used 30 days after its last validated fetch,
  schedule or no schedule, so a provider serving a broken document eventually stops sign-in. Watch
  `MetadataRefreshFailed` and `JwksRefreshFailed` well before then.
- **Large federation metadata** raises memory, time and queue timeouts together ([SAML metadata](saml-metadata.md)).

See [SAML metadata](saml-metadata.md#refreshing-on-a-schedule) and
[Setting up an OIDC connection](oidc-connections.md#scheduled-refresh).

## Sign-in started at the identity provider

`SSO_IDP_INITIATED`, then `idp_initiated` and `idp_initiated_start_url` on a SAML connection.

- **Re-initiation only.** An unsolicited response is checked in full and recorded against replay, then the browser is
  sent to your start URL, which starts an ordinary SP-initiated sign-in. Consuming an unsolicited assertion directly is
  not supported: it is bound to no request and no browser, so whoever posts it is believed (login CSRF), and a leaked
  assertion works once.
- **Your start URL** must start a fresh flow and must not treat the request as signed in. The `connection` it is given
  is untrusted input; `RelayState` is never read.

See [IdP-initiated sign-in](idp-initiated-sign-in.md).

## Unlinked handoffs

`sso.applications.<name>.unlinked_handoffs`: a `sign_in` that resolves to no identity is still handed off.

- **What it hands you.** A code with no linked identity, for an application that resolves identities itself at
  redemption, in place of refusing the sign-in with `unlinked`.
- **The risk.** Resolving an existing identity from the email or any other mapped attribute there is an account
  takeover waiting to happen: an identity provider asserts what it likes about its own users. Attach to an existing
  identity only through a `link` flow or a verified domain. A suspended link, a link whose scope could not be judged
  and another flow's live reservation are refused whatever this says. Under `laravel-iam` the adapter refuses an
  unlinked handoff; leave this off.

See [Completing a flow](completing-a-flow.md#unlinked-sign-ins).

## Linking by a verified domain

`SSO_DOMAIN_LINKING`, then a connection's linking policy through `LinkingPolicyService`, with your email matcher,
principal scope and tenant membership contracts, each refusing by default.

- **The DNS caveat.** A DNS check proves that someone controls a domain now. It does not prove that the domain's owner
  never changed. That is why the person's membership of the tenant must have been accepted before the domain's current
  verification: a tenant that claims a domain cannot add people and then capture them.
- **The SAML statement.** Turning it on for a SAML connection states that the identity provider decides which subject
  holds each of the domain's addresses and that people cannot set their own. A signature alone does not establish it.
- **Shared issuers.** An issuer that serves many organisations (Google, Microsoft Entra ID's per-tenant issuers under
  their preset) is eligible only with its organisation claim and value, such as `hd`; an unclassified issuer reserves
  nothing.
- **Afterwards.** A link made this way keeps its provenance: if the person later holds a principal outside the tenant,
  the link is suspended and its sessions revoked, until the person confirms it through a `link` flow authenticated
  independently of the provider. The default confirmation contract refuses everyone.
- **What it establishes.** Who the person is, nothing more: the further-factor requirement and the evidence contract
  apply as for any sign-in. Activation reports `LinkActivated`, with what you need to tell the person on their own
  channels.

See [Linking by a verified domain](linking-by-domain.md).

## Accepting provider evidence

Binding `Evidence\ConnectionEvidencePolicy` as `Contracts\EvidencePolicy`, then a connection's policy through
`EvidenceSettingsService`. By default no provider assertion counts towards a further factor.

- **What it means.** An accepted `amr` or `acr` is the provider's own statement of how the person authenticated,
  judged against your policy at redemption, within `sso.linking.evidence_max_age_seconds` and the connection's own
  tighter age. It is an input to your MFA policy, never an automatic pass: under `laravel-iam`, `laravel-mfa`'s default
  combination policy still does not treat it as a second factor until you rebind that policy to trust the provider.
- **The risk.** You inherit the provider's enforcement: a provider that says `mfa` without doing it, or that an
  administrator of the tenant can reconfigure, satisfies your requirement anyway. Accept only values whose meaning at
  that provider you have checked, and only for connections whose administrators you trust with it.

See [Provider evidence](evidence.md).

## Provider session deadlines

Binding your own `Contracts\ProviderSessionDeadline` to answer `ignored`. By default a SAML `SessionNotOnOrAfter` caps
the session the handoff establishes.

- **What it changes.** Your session can outlive the provider's: a person whose provider session ended stays signed in
  to your application until your own session ends. The raw deadline is still kept in the session's provenance
  (`sso.provider_session_deadline`), with no cap (`sso.session_not_after` `null`).
- **When it is right.** When your sessions are deliberately independent of the provider's, with short-lived access
  tokens and revocation of your own. Removing a person's access is then deactivation in your application.

See [Completing a flow](completing-a-flow.md#the-contracts-it-asks) and [Session provenance](session-provenance.md).

## Other opt-ins

| Opt-in                                                      | What it changes                                                                                                                          | See                                                                        |
|-------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| `delivery: query` on an application                         | The code arrives in the query, which reaches your web server's logs and anything the page loads; keep the default fragment if you can    | [Completion responses](completion-responses.md#where-the-code-goes)        |
| A `LinkLimit` above one                                     | An identity may hold several subjects in one connection                                                                                  | [Links](links.md#how-many-links-an-identity-may-hold)                      |
| `client_assertion_algorithm: RS256`                         | PKCS #1 v1.5 client assertions, for a provider that accepts nothing else; prefer `PS256` or a P-256 key                                  | [Setting up an OIDC connection](oidc-connections.md#client-authentication) |
| A `HandoffIssuer` of your own                               | You store and redeem the codes, through `HandoffRecheck`, inside the transaction that consumes them; `laravel-iam` never does this       | [Redeeming a handoff](redeeming-a-handoff.md#redeeming-codes-of-your-own)  |
| `SSO_OPERATIONS_CACHE_MUTEXES`                              | Laravel's overlap and one-server mutexes for the scheduled commands; saves work, guarantees nothing, and needs a shared cache with locks | [Operations](operations.md#several-servers-and-the-cache)                  |
| A DNS resolver of your own                                  | Bounded deadlines, DNSSEC or DNS-over-HTTPS in place of the system resolver; answer `lookup_failed` rather than throw                    | [Domain rechecks](domain-rechecks.md#the-dns-resolver)                     |
| `sso.linking.shared_issuers`                                | Adds an issuer that serves many organisations, with its organisation claim; it can never change a built-in one                           | [Linking by domain](linking-by-domain.md#classifying-the-issuer)           |
| A protocol driver of your own (`ProtocolManager::extend()`) | A protocol the package does not ship; it completes at either endpoint and is held to its own validation                                  | [Connections](connections.md#registering-your-own-protocol)                |
