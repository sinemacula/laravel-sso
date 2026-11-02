# Events

The package reports what it does through Laravel events. Events report only: nothing that must happen for security
depends on a listener, so an audit log, a SIEM forwarder or a notification can attach to them, but a check your
application must enforce belongs in the package's contracts, which are called synchronously.

## Listening on every package event

Every package event implements `SineMacula\Laravel\Sso\Contracts\SsoEvent` and carries one
`SineMacula\Laravel\Sso\Events\EventContext`, returned by `context()`. Laravel delivers an event to the listeners of the
interfaces it implements, so one listener on the contract receives them all:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;

Event::listen(SsoEvent::class, function (SsoEvent $event): void {
    // $event->context()->toArray() is the record to keep
});
```

### Recording them with `laravel-audit-log`

With `laravel-iam` installed there is nothing to wire: it maps the package's events. Without it, register a mapper for
the events you record, in a service provider's `boot()`:

```php
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\Sso\Events\FlowFailed;

AuditLog::map(FlowFailed::class, SsoAuditMapper::class);
```

The mapper implements `laravel-audit-log`'s `SineMacula\Laravel\AuditLog\Contracts\EventMapper`, whose `map(object
$event, PendingRecord $record): ?PendingRecord` fills the record and returns it, or returns `null` to skip the event.
Give each event an explicit code rather than deriving one from the class name, and correlate the records of one flow by
the connection and the request's public reference, skipping the correlation when an event has no reference:

```php
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\Sso\Events\FlowFailed;

final class SsoAuditMapper implements EventMapper
{
    public function map(object $event, PendingRecord $record): ?PendingRecord
    {
        if (!$event instanceof FlowFailed) {
            return null;
        }

        $context = $event->context()->toArray();

        $record->event('sso.flow_failed')
            ->failed($event->reason->value)
            ->withProperties(['flow' => $event->flow->value, 'application' => $context['application']]);

        if ($context['identity_morph_class'] !== null && $context['identity_id'] !== null) {
            $record->by(Reference::of($context['identity_morph_class'], $context['identity_id']));
        }

        if ($context['tenant_id'] !== null) {
            $record->forTenant($context['tenant_id']);
        }

        if ($context['request_reference'] !== null) {
            $record->correlatedWith("sso:{$context['connection_id']}:{$context['request_reference']}");
        }

        return $record;
    }
}
```

A mapped event is recorded as soon as it is dispatched, and the package dispatches every event once the write it
reports has committed (see below), so nothing is recorded for a change that rolled back.

## The context record

`toArray()` is the record to keep: strings only, with snake_case keys, ready to store or to queue on its own. A part the
event's flow did not establish, or that does not apply to it, is `null`.

| Key                                                 | What it holds                                                          |
|-----------------------------------------------------|------------------------------------------------------------------------|
| `occurred_at`                                       | When the event was built, ISO 8601 UTC to the microsecond              |
| `ip`, `user_agent`                                  | The client of the request being served                                 |
| `connection_id`                                     | The connection the event concerns                                      |
| `tenant_id`                                         | The tenant the connection belongs to                                   |
| `protocol`                                          | `saml2`, `oidc`, or a registered driver's name                         |
| `application`                                       | The application the flow is for                                        |
| `purpose`                                           | `sign_in`, `link` or `reauthenticate`                                  |
| `request_reference`                                 | The authorisation request's public reference                           |
| `identity_morph_class`, `identity_id`               | The identity, once the flow resolved one                               |
| `acting_identity_morph_class`, `acting_identity_id` | The identity acting, for administration, as your application passes it |
| `principal_morph_class`, `principal_id`             | The session's principal, where one applies                             |
| `active_tenant_id`                                  | The tenant a session is active in, where one applies                   |
| `session_id`                                        | The session, where one applies                                         |
| `method`                                            | The sign-in method, where one applies                                  |

The names match `laravel-authentication`'s event context, so one audit sink can attribute both packages' events the same
way. `tenant_id` is the tenant that owns the connection; `active_tenant_id` is the tenant a session acts within.

`request_reference` is the only flow identifier an event carries: use it to correlate the events of one sign-in, here
and in `laravel-authentication`, which carries the same reference at redemption. No event carries a secret, an
assertion, a provider token, a verifier, a handoff code, protocol state (`state`, `RelayState`, a nonce), a raw payload
or a transport header. Mapped attributes appear only on the unlinked-result event, which a provisioning listener needs.

The client is read from the request being served, and every value is cleaned before it is kept: the IP address only
when it is a valid IPv4 or IPv6 address, and the user agent and every id with control characters and Unicode
bidirectional controls removed and invalid UTF-8 replaced, the user agent cut to 512 characters and every other value to
255. Your sink can store them without escaping them again, and a crafted header cannot forge a log line.

## Refused operations: `FlowFailed`

Every refused operation fires exactly one `SineMacula\Laravel\Sso\Events\FlowFailed`, however many checks it failed,
with the operation's flow (`$event->flow`, a `Flow`) and a machine-readable reason (`$event->reason`, a
`FailureReason`). It carries no message: the details go to the package's log.

| Flow                    | The operation refused                                                       |
|-------------------------|-----------------------------------------------------------------------------|
| `authorization_request` | Starting a flow for a connection, or by discovery from an email domain      |
| `assertion`             | A SAML response at the assertion consumer service, solicited or unsolicited |
| `callback`              | An OIDC authorisation response at the callback                              |
| `redemption`            | A handoff code presented for redemption                                     |

| Reason                                | Meaning                                                                                            |
|---------------------------------------|----------------------------------------------------------------------------------------------------|
| `connection_unavailable`              | The connection is unknown, disabled or incomplete; the same answer for each                        |
| `application_not_allowed`             | The application does not allow sign-in through an external provider                                |
| `request_unknown`                     | No stored authorisation request matches, or it was already used                                    |
| `request_expired`                     | The authorisation request expired                                                                  |
| `signature_invalid`                   | A required signature is missing, does not verify, or uses a key or algorithm not allowed           |
| `issuer_mismatch`                     | The issuer is not the connection's                                                                 |
| `audience_mismatch`                   | The audience does not name this service provider or client                                         |
| `recipient_mismatch`                  | The recipient or destination is not the connection's assertion consumer service                    |
| `assertion_expired`                   | The assertion or ID token is not yet valid, expired, or is too old                                 |
| `replayed`                            | The assertion was seen before, or could not be recorded as seen                                    |
| `nonce_mismatch`                      | The ID token's nonce is not the one the request stored                                             |
| `provider_error`                      | The identity provider answered with an error                                                       |
| `metadata_expired`                    | Something fetched for the connection is past its `validUntil` or stale limit                       |
| `unlinked`                            | A sign-in resolved to no identity and the application does not allow unlinked handoffs             |
| `purpose_mismatch`                    | A handoff code was presented to the redemption of another purpose                                  |
| `verifier_mismatch`                   | The verifier presented with a handoff code does not match its challenge                            |
| `rate_limited`                        | The IP address, email domain or connection used up its attempts for now                            |
| `challenge_invalid`                   | The S256 challenge a start was given is not 43 base64url characters                                |
| `session_ineligible`                  | A `reauthenticate` flow's identity is not signed in through the connection on its session          |
| `discovery_no_match`                  | Discovery found no connection for the email's domain; the client got the fallback                  |
| `connection_mismatch`                 | A response or a handoff code was presented for another connection than its own                     |
| `application_mismatch`                | A handoff code was presented for another application than its own                                  |
| `enforcement_unsatisfied`             | The connection does not satisfy its tenant's enforcement for the application                       |
| `handoff_unknown`                     | No handoff code is stored for what was presented, or it was voided                                 |
| `handoff_expired`                     | The handoff code expired                                                                           |
| `link_changed`                        | The link a handoff code resolved was removed, or now names another identity                        |
| `freshness_required`                  | A `link` flow was started without fresh enough authentication                                      |
| `fetch_refused`                       | An outbound request to the identity provider was refused before it was sent                        |
| `fetch_failed`                        | An outbound request to the identity provider was sent and failed                                   |
| `response_invalid`                    | The SAML response is too large, malformed, not schema-valid, or holds a misplaced element          |
| `decryption_failed`                   | The encrypted assertion could not be decrypted under the connection's algorithms                   |
| `encryption_required`                 | The connection requires an encrypted assertion and the response carried a plain one                |
| `subject_invalid`                     | The subject is missing, transient, of a format not allowed, or has a wrong qualifier               |
| `request_mismatch`                    | The `RelayState` or a signed `InResponseTo` names another request than the consumed one            |
| `authentication_expired`              | The authentication is older than allowed or than a reauthentication request, or its time is absent |
| `authentication_context_mismatch`     | The authentication context is not one the connection requires                                      |
| `condition_unsupported`               | The assertion carries a condition the package does not understand                                  |
| `unsolicited_not_allowed`             | An unsolicited response reached a connection that does not allow IdP-initiated sign-in             |
| `metadata_invalid`                    | The identity provider's metadata is malformed, not schema-valid, or holds nothing usable           |
| `metadata_signature_invalid`          | The metadata is not signed by the connection's metadata signing anchor                             |
| `metadata_entity_not_found`           | The metadata holds no entity with the connection's entity id                                       |
| `metadata_conflict`                   | A metadata refresh lost to a change made while it fetched, and wrote nothing                       |
| `metadata_refresh_in_progress`        | Another server is refreshing the connection's metadata                                             |
| `id_token_invalid`                    | The ID token is missing, malformed, too large, or has a claim missing or wrongly typed             |
| `token_response_invalid`              | The token endpoint's answer is not a JSON object with an access token of type `Bearer`             |
| `at_hash_mismatch`                    | The ID token's `at_hash` does not match the access token                                           |
| `userinfo_invalid`                    | The UserInfo answer is malformed, or its `sub` is not the ID token's                               |
| `discovery_invalid`                   | The OpenID provider's discovery document is malformed or names nothing usable                      |
| `jwks_invalid`                        | The OpenID provider's JWKS is malformed, too large, or holds no usable key                         |
| `link_suspended`                      | The link is suspended until a confirming `link` flow                                               |
| `link_reserved`                       | Another flow's live reservation holds the subject                                                  |
| `link_ineligible`                     | The link eligibility contract does not let the identity link through the connection                |
| `independent_authentication_required` | The identity holds a verified domain link, and the caller did not authenticate apart from it       |
| `identity_mismatch`                   | The caller or the result's link is not the flow's identity; names nobody                           |
| `reservation_invalid`                 | The code's reservation is gone, expired, or a condition of it no longer holds                      |
| `subject_already_linked`              | Another identity holds the subject, which is never named                                           |
| `link_limit_reached`                  | The identity holds as many links in the connection as it may                                       |

The reasons and flows are stable: a value is never renamed or reused, so you can count failure modes by them.

## Flow and link events

Each flow reports what it did with one event per step that changed something, once the step's transaction commits.
Each is in `SineMacula\Laravel\Sso\Events` and carries the context above, the request's public reference among it;
none holds a handoff code, a verifier, protocol state, a subject, a mapped attribute or the verified result, but for
`ResultUnlinked`, which carries the result and its grant for a [provisioning](provisioning.md) listener.

| Event                            | Fields beyond the context | Dispatched when                                                                                                                               |
|----------------------------------|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `AuthorizationRequestStarted`    | none                      | A start stored its authorisation request and sent the client on                                                                               |
| `ResultVerified`                 | none                      | A completion's response passed every check, before what the completion did with it                                                            |
| `HandoffIssued`                  | none                      | A completion issued a handoff code                                                                                                            |
| `HandoffRedeemed`                | none                      | The package's own redemption redeemed a handoff code                                                                                          |
| `LinkCreated`                    | `origin`: how it was made | A link was made by a `link` flow, provisioning, a verified domain or a migration                                                              |
| `LinkRemoved`                    | none                      | A link was removed, and the identity's sessions through the connection revoked                                                                |
| `LinkActivated`                  | `linkId`                  | A [verified domain](linking-by-domain.md)'s reservation became a link, after `LinkCreated`, for you to notify the person on your own channels |
| `LinkConfirmed`                  | none                      | A confirming `link` flow cleared a link's verified domain provenance and any suspension                                                       |
| `LinkSuspended`                  | none                      | A link by a verified domain was suspended, until a confirming `link` flow                                                                     |
| `ReauthenticationCompleted`      | none                      | A [reauthentication](reauthenticating.md) renewed a session, with its redemption's commit                                                     |
| `ResultUnlinked`                 | `result`, `grant`         | A `sign_in` resolved to nobody: synchronously, before any handoff                                                                             |
| `UnsolicitedResponseReinitiated` | none                      | An unsolicited SAML response passed every check and the client was sent to start again                                                        |

`AuthorizationRequestStarted`'s context names the connection, its tenant and protocol, the application, the purpose and
the request's public reference, with the identity a `link` or `reauthenticate` was started for and the session of a
`reauthenticate`. A refused start's `FlowFailed` names the purpose, the identity and session your application gave, and
as much more as the start had established: the application once admitted, the connection once found, the reference
once made.

A completion that issues a code reports `ResultVerified` then `HandoffIssued`; one refused after its response verified
reports `ResultVerified` then `FlowFailed`; one refused before reports `FlowFailed` alone. `ResultVerified` at
completion and the sign-in's own event at redemption both carry the connection and the request's public reference, so
an audit trail correlates them rather than counting a sign-in twice.

## When events are dispatched

An event is dispatched once the transaction that caused it commits: at once when the package's storage connection
(`sso.storage.connection`) has no open transaction, on that transaction's commit otherwise, and never when it, or the
savepoint the event was dispatched in, rolls back. A transaction your application has open on another connection
neither delays nor withdraws it. So a listener never reports something that did not happen, and a listener that reads
the database sees what the event reports.

Events go to the dispatcher bound when they are dispatched, so `Event::fake()` in a test receives them. A listener that
throws propagates as it does for any Laravel event, after the write it reports has committed.

A queued listener (`ShouldQueue`) receives every package event as a synchronous one does: the context is strings, and
`FlowFailed`'s flow and reason are enums.

The unlinked-result event is the one exception: it is dispatched synchronously, inside the flow and before any handoff
is issued, so a listener can create the identity in time. A queued listener on it fails loudly, because the event refuses
to be serialised: it would run too late to provision anything. See [Provisioning](provisioning.md).

## Administration events

Every change your administration screens make through the management helpers (see [Managing
connections](managing-connections.md) and [Keys and certificates](keys.md)) is reported with one event, once the change
commits, so an audit trail can record who changed which identity provider's trust, and when. Each is in
`SineMacula\Laravel\Sso\Events` and carries the context above, with the connection's id, its tenant and its protocol.

| Event                   | Fields beyond the context                                 | Dispatched when                                                                 |
|-------------------------|-----------------------------------------------------------|---------------------------------------------------------------------------------|
| `ConnectionCreated`     | none                                                      | `ConnectionService::create()` created a connection, disabled                    |
| `ConnectionUpdated`     | `changedSettings`: the names of what changed              | `update()` or `SubjectMigration::migrate()` changed what the connection holds   |
| `ConnectionEnabled`     | none                                                      | `enable()` enabled a disabled connection                                        |
| `ConnectionDisabled`    | none                                                      | `ConnectionLifecycle::disable()` disabled an enabled connection                 |
| `ConnectionDeleted`     | none                                                      | `ConnectionLifecycle::delete()` deleted a connection and everything it held     |
| `KeyAdded`              | `keyId`, `use`, `state`, `fingerprint`, `notAfter`        | `KeyService::addNext()` added a key pair, or `trustCertificate()` a certificate |
| `KeyMadeCurrent`        | `keyId`, `use`, `fingerprint`, `previousKeyId`            | `makeCurrent()` made a key current, or `addNext()` added a use's first key      |
| `KeyRetired`            | `keyId`, `use`, `fingerprint`                             | `retire()` removed a key, or `distrustCertificate()` a certificate              |
| `KeyNearingExpiry`      | `keyId`, `use`, `fingerprint`, `notAfter`                 | `ExpiryReport::report()` found its validity ending within the warning, or ended |
| `MetadataRefreshed`     | `changedSettings`, `metadataVersion`, `trustChanged`      | A metadata refresh validated the identity provider's metadata and applied it    |
| `MetadataRefreshFailed` | `reason`, `failures`, `nextAttemptAt`                     | A metadata refresh failed; the last good metadata is kept                       |
| `JwksRefreshed`         | `jwksVersion`, `keysAdded`, `keysRemoved`, `trustChanged` | An ID token's unknown `kid` refetched the connection's JWKS and stored it       |
| `JwksRefreshFailed`     | `reason`, `nextRefetchAt`                                 | That refetch failed; the stored keys are kept until the cooldown ends           |

A metadata refresh, of a SAML connection's metadata or an OIDC connection's discovery document and JWKS, reports
`MetadataRefreshed` or `MetadataRefreshFailed`; an OIDC connection's refetch of its JWKS on an unknown `kid` reports
`JwksRefreshed` or `JwksRefreshFailed` instead, with no acting identity, and a refetch that removes a key lets the one
sign-in that asked finish, so `trustChanged` true does not always mean that flow failed. A metadata refresh's
`changedSettings` names the settings it changed, such as `['sso_url', 'idp_signing_certificates']`, and none when
nothing changed; `trustChanged` says whether it removed or replaced a trusted certificate or moved the single sign-on
URL or binding, which voids every flow in flight through the connection, and `metadataVersion` is the connection's
version after it. A failed refresh's `reason` is `fetch_refused`, `fetch_failed`, `metadata_invalid`,
`metadata_signature_invalid`, `metadata_entity_not_found`, `metadata_conflict` or `metadata_expired`, `failures` the
failures in a row, and `nextAttemptAt` when the next scheduled attempt is due.

`changedSettings` names what changed, never its value: the settings in the order the protocol lists them, then the
secrets, then `display_name` and `attribute_mapping`, such as `['token_endpoint', 'client_secret', 'display_name']`. A
rotated client secret is reported as `client_secret`, and nothing of the secret itself. `use` is a `KeyUse`, `state` a
`KeyState` (`current` or `next` for a key pair, `null` for a trusted certificate), `fingerprint` the lower-case hex
SHA-256 an administrator compares with the identity provider's, `notAfter` the end of the certificate's validity, and
`previousKeyId` the key a new current key replaced, now retiring, or `null`. The first key of a use is reported twice,
`KeyAdded` then `KeyMadeCurrent`.

A refused change (`freshness_required`, `settings_invalid` and the rest) and a change that changed nothing (an update
giving the stored values, enabling an enabled connection) report nothing, not even `FlowFailed`: the helper's result is
the answer. No administration event carries a secret, a private key, a ciphertext or a setting's value.

### Domain and enforcement events

A connection's domains (see [Domains](domains.md)) and a tenant's enforcement report their changes the same way, once
the change commits. A domain event's context names the connection that claimed the domain, its tenant and protocol;
an enforcement event's names the tenant.

| Event                 | Fields beyond the context                                | Dispatched when                                                                                   |
|-----------------------|----------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `DomainClaimed`       | `domainId`, `domain`, `recordName`, `pendingExpiresAt`   | `DomainService::claim()` claimed a domain, or claimed an expired claim again                      |
| `DomainVerified`      | `domainId`, `domain`, `verifiedAt`                       | `DomainService::verify()` found the token in the domain's TXT record                              |
| `DomainRemoved`       | `domainId`, `domain`, `state`                            | `DomainService::remove()` removed a claim, in the state it was in                                 |
| `DomainRecheckFailed` | `domainId`, `domain`, `failure`, `lapsesAt`              | `sso:domains:recheck` found a verified domain's record absent or changed, or could not look it up |
| `DomainRestored`      | `domainId`, `domain`, `verifiedAt`, `checkedAt`          | `sso:domains:recheck` confirmed a domain whose record had gone, within its grace period           |
| `DomainLapsed`        | `domainId`, `domain`                                     | `sso:domains:recheck` lapsed a domain at the end of its grace period                              |
| `EnforcementChanged`  | `enabled`, `connectionIds`, `version`, `previousVersion` | A tenant's enforcement was turned on or off, or its satisfying connections changed                |
| `ExemptionUsed`       | `enforcementVersion`                                     | A session was established in an enforcing tenant under an exemption                               |

`domain` is the normalised domain, `recordName` the name its TXT record is looked up at, and `failure` a
`RecheckFailure`: `record_absent` or `record_changed`, which suspend linking by the domain at once and set `lapsesAt`,
or `lookup_failed`, which changes nothing. No domain event carries the verification token or a record's value. An
`ExemptionUsed` context names the enforcing tenant as `tenant_id`, the tenant the session is active in as
`active_tenant_id`, the application, the identity and the session when the caller has one.

### The acting identity

Each helper takes the identity making the change as its last argument, an `ActingIdentity` of a type and an id as your
application knows them; under `laravel-iam`, the identity's morph class and key. It reaches the context as
`acting_identity_morph_class` and `acting_identity_id`, and is `null` when you pass none. The package never decides who
may make a change: authorise the user first, then pass them so the event says who did.

```php
use SineMacula\Laravel\Sso\Administration\ActingIdentity;

$actor = new ActingIdentity($user->getMorphClass(), (string) $user->getKey());

$connections->update($tenantId, $connectionId, ['settings' => ['token_endpoint' => $url]], $actor);
```

### Recording an audit trail

Listen on the administration events you keep, and store the context's record with the event's own fields. A queued
listener receives them as a synchronous one does, and only once the change has committed:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\ConnectionCreated;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\ConnectionEnabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\KeyAdded;
use SineMacula\Laravel\Sso\Events\KeyMadeCurrent;
use SineMacula\Laravel\Sso\Events\KeyRetired;

Event::listen([
    ConnectionCreated::class,
    ConnectionUpdated::class,
    ConnectionEnabled::class,
    ConnectionDisabled::class,
    ConnectionDeleted::class,
    KeyAdded::class,
    KeyMadeCurrent::class,
    KeyRetired::class,
], function (SsoEvent $event): void {
    $context = $event->context();

    AuditEntry::create([
        'event'         => class_basename($event),
        'tenant_id'     => $context->tenantId,
        'connection_id' => $context->connectionId,
        'actor_type'    => $context->actingIdentityMorphClass,
        'actor_id'      => $context->actingIdentityId,
        'details'       => match (true) {
            $event instanceof ConnectionUpdated => ['changed' => $event->changedSettings],
            $event instanceof KeyAdded          => ['key_id' => $event->keyId, 'use' => $event->use->value, 'fingerprint' => $event->fingerprint],
            $event instanceof KeyMadeCurrent    => ['key_id' => $event->keyId, 'replaced' => $event->previousKeyId],
            $event instanceof KeyRetired        => ['key_id' => $event->keyId, 'fingerprint' => $event->fingerprint],
            default                             => [],
        },
        'context'       => $context->toArray(),
    ]);
});
```

### Keys and certificates nearing expiry

`SineMacula\Laravel\Sso\Keys\ExpiryReport::report()` finds every key and certificate, of every connection, whose
validity ends within `keys.expiry_warning_days` (30 days by default), or within the days you pass (1 to 365), or has
already ended. It dispatches one `KeyNearingExpiry` for each, with no acting identity, and returns them as `KeySummary`
values, earliest end of validity first. A retiring key whose overlap has ended is left out, and so is a key with no end
of validity.

The expiry is reported, never enforced: an expired certificate is still trusted, since trust comes from the certificate
you configured, not its dates. The report changes nothing, so run it on a schedule and tell an administrator to rotate:

```php
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schedule;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Keys\ExpiryReport;

Schedule::call(static fn () => app(ExpiryReport::class)->report())->daily();

Event::listen(KeyNearingExpiry::class, function (KeyNearingExpiry $event): void {
    SecurityTeam::notify(new CertificateExpiring($event->context()->connectionId, $event->fingerprint, $event->notAfter));
});
```

Each run reports every such key again, until it is rotated or removed.
