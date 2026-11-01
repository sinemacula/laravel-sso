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
use SineMacula\Laravel\Sso\Events\FlowFailed;

Event::listen(SsoEvent::class, function (SsoEvent $event): void {
    AuditLog::record(
        event: $event::class,
        context: $event->context()->toArray(),
        reason: $event instanceof FlowFailed ? $event->reason->value : null,
    );
});
```

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

| Reason                    | Meaning                                                                                  |
|---------------------------|------------------------------------------------------------------------------------------|
| `connection_unavailable`  | The connection is unknown, disabled or incomplete; the same answer for each              |
| `application_not_allowed` | The application does not allow sign-in through an external provider                      |
| `request_unknown`         | No stored authorisation request matches, or it was already used                          |
| `request_expired`         | The authorisation request expired                                                        |
| `signature_invalid`       | A required signature is missing, does not verify, or uses a key or algorithm not allowed |
| `issuer_mismatch`         | The issuer is not the connection's                                                       |
| `audience_mismatch`       | The audience does not name this service provider or client                               |
| `recipient_mismatch`      | The recipient or destination is not the connection's assertion consumer service          |
| `assertion_expired`       | The assertion or ID token is not yet valid, expired, or is too old                       |
| `replayed`                | The assertion was seen before, or could not be recorded as seen                          |
| `nonce_mismatch`          | The ID token's nonce is not the one the request stored                                   |
| `provider_error`          | The identity provider answered with an error                                             |
| `metadata_expired`        | The connection's metadata is past its `validUntil` and no refresh has succeeded          |
| `unlinked`                | A sign-in resolved to no identity and the application does not allow unlinked handoffs   |
| `purpose_mismatch`        | A handoff code was presented to the redemption of another purpose                        |
| `verifier_mismatch`       | The verifier presented with a handoff code does not match its challenge                  |
| `rate_limited`            | The IP address, email domain or connection used up its attempts for now                  |
| `fetch_refused`           | An outbound request to the identity provider was refused before it was sent              |
| `fetch_failed`            | An outbound request to the identity provider was sent and failed                         |

The reasons and flows are stable: a value is never renamed or reused, so you can count failure modes by them.

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
is issued, so a listener can create the identity in time. A queued listener on it runs too late to provision anything.

## Administration events

Every change your administration screens make through the management helpers (see [Managing
connections](managing-connections.md) and [Keys and certificates](keys.md)) is reported with one event, once the change
commits, so an audit trail can record who changed which identity provider's trust, and when. Each is in
`SineMacula\Laravel\Sso\Events` and carries the context above, with the connection's id, its tenant and its protocol.

| Event                | Fields beyond the context                          | Dispatched when                                                                 |
|----------------------|----------------------------------------------------|---------------------------------------------------------------------------------|
| `ConnectionCreated`  | none                                               | `ConnectionService::create()` created a connection, disabled                    |
| `ConnectionUpdated`  | `changedSettings`: the names of what changed       | `update()` changed a setting, a secret, the display name or the mapping         |
| `ConnectionEnabled`  | none                                               | `enable()` enabled a disabled connection                                        |
| `ConnectionDisabled` | none                                               | A connection was disabled; no helper does so yet                                |
| `ConnectionDeleted`  | none                                               | A connection was deleted; no helper does so yet                                 |
| `KeyAdded`           | `keyId`, `use`, `state`, `fingerprint`, `notAfter` | `KeyService::addNext()` added a key pair, or `trustCertificate()` a certificate |
| `KeyMadeCurrent`     | `keyId`, `use`, `fingerprint`, `previousKeyId`     | `makeCurrent()` made a key current, or `addNext()` added a use's first key      |
| `KeyRetired`         | `keyId`, `use`, `fingerprint`                      | `retire()` removed a key, or `distrustCertificate()` a certificate              |
| `KeyNearingExpiry`   | `keyId`, `use`, `fingerprint`, `notAfter`          | `ExpiryReport::report()` found its validity ending within the warning, or ended |

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
