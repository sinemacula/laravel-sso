# Re-authenticating

The `reauthenticate` purpose asks a person who is already signed in through a connection to prove, at the identity
provider and now, that they are still there. It renews one session's authentication time and nothing else. It creates no
session, issues no refresh token and is not a further factor.

The package keeps no sessions, so nothing here works until you bind your own `ReauthenticationSessions`. By default no
identity is ever signed in on any session, and every `reauthenticate` start is refused with `session_ineligible`.

## The flow

```php
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;

$start = app(AuthorizationRequestService::class)->start(
    'web',
    Purpose::REAUTHENTICATE,
    $connectionId,
    $codeChallenge,
    $identity,   // the signed-in identity, an IdentityReference
    $sessionId,  // the session to renew, 1 to 255 bytes
);
```

1. **Start.** The package asks `standing()` whether the identity is signed in through the connection on the session.
   Anything but `signed_in` is `session_ineligible`, and no request is stored.
2. **At the provider.** The driver forces fresh authentication: `ForceAuthn="true"` for SAML, `prompt=login` with
   `max_age=0` for OpenID Connect, whatever the connection configures. A connection's own `prompt` extra parameter or
   `max_age` never overrides them.
3. **Completion.** The result must state when the provider authenticated (`AuthnInstant`, `auth_time`), no earlier than
   the request's start less the clock skew and no later than now plus it, and must resolve to the identity the flow was
   started for. A handoff code bound to the identity and the session is issued.
4. **Redemption.** Your endpoint redeems the code through `admit()`, inside your transaction. The package checks the
   exact link and the session under locks, and renews the session in that transaction.

## Redeem through `admit()`

A renewal must commit with the code's consumption, under the locks of the redemption, so `redeem()` with no transaction
open refuses a `reauthenticate` code with a `LogicException` and leaves it unconsumed.

```php
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;

$result = DB::connection(StorageConnection::name())->transaction(
    fn () => app(HandoffRedemption::class)->admit(
        Purpose::REAUTHENTICATE,
        'web',
        $connectionId,
        $code,
        $verifier,
    ),
);

if ($result->isRedeemed() && $result->sessionId !== $currentSessionId) {
    // The code renewed the session it was started on, which is not this one.
    // Treat this caller as not reauthenticated.
}
```

`admit()` renews the session the code is bound to, the one in `$result->sessionId`, never the one the caller happens to
be using. Compare the two before you tell the caller that its own session is fresh. To undo the renewal as well, throw
from inside the transaction instead: everything rolls back, the code stays unconsumed and no event is reported.

Retry a failed redemption only as your whole transaction, never a part of it.

## Binding the contract

```php
use SineMacula\Laravel\Sso\Contracts\ReauthenticationSessions;

$this->app->bind(ReauthenticationSessions::class, YourSessions::class);
```

Three methods, each with its own obligation:

| Method                  | When                                        | Obligation                                                                             |
|-------------------------|---------------------------------------------|----------------------------------------------------------------------------------------|
| `standing()`            | The start, in no transaction of the package | The current answer for the identity, the session and the connection. It locks nothing. |
| `lockedStanding()`      | Redemption, inside the caller's transaction | Every value matches, and the session's row is locked until that transaction ends.      |
| `renewAuthentication()` | Redemption, after `lockedStanding()`        | Writes the authentication time, and the evidence when there is any, on the locked row. |

Answer `signed_in` only when you know it. If you cannot tell, answer `not_signed_in`. An exception propagates and rolls
the redemption back with the code unconsumed, so use one for a failure, not for a refusal.

### Locking the session

`lockedStanding()` has to hold the session's row, with a locking read on the package's storage connection, so that a
logout, a revocation or a change of the session's binding waits for the redemption to commit:

```php
public function lockedStanding(
    IdentityReference $identity,
    string $sessionId,
    string $application,
    SsoConnection $connection,
    string $linkId,
): SessionStanding {
    $session = Session::query()
        ->useWritePdo()
        ->lockForUpdate()
        ->whereKey($sessionId)
        ->first();

    $matches = $session !== null
        && $session->isActive()
        && $session->identity_type === $identity->type
        && $session->identity_id === $identity->id
        && $session->application === $application
        && $session->connection_id === $connection->getConnectionId()
        && $session->sso_link_id === $linkId;

    return $matches ? SessionStanding::SIGNED_IN : SessionStanding::NOT_SIGNED_IN;
}
```

A check followed by an unprotected write races those changes: the person logs out, and the renewal then writes to a
session that has ended. A session store on another Laravel connection cannot make this promise. Writers must also keep
to the lock order: the package takes its own locks first, so the session's row comes last. A logout that locks only the
session's row is fine, and `SessionRevocation` is called with the connection's lock already held. Something that locks a
session's row and then calls into the package would invert the order.

On PostgreSQL under `REPEATABLE READ`, a transaction whose snapshot predates another's change to that row fails to
serialise when it locks it. That is a safe outcome: retry the whole transaction.

### Recording the session's link

The package accepts only the exact link that established the session. Where an identity may hold two links in one
connection, a second subject does not stand in for the credential being reauthenticated.

So your session has to remember its link. Record it when you write the session at sign-in, inside the same transaction:

```php
DB::connection(StorageConnection::name())->transaction(function () use ($connectionId, $code, $verifier) {
    $result = app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $connectionId, $code, $verifier);

    if ($result->isAdmitted() && $result->linkedIdentity !== null) {
        Session::create([
            'identity_type'    => $result->linkedIdentity->type,
            'identity_id'      => $result->linkedIdentity->id,
            'application'      => 'web',
            'connection_id'    => $connectionId,
            'sso_link_id'      => $result->linkId,
            'authenticated_at' => $result->result?->authenticationContext->authenticatedAt,
        ]);
    }

    return $result;
});
```

A link's id is compared rather than its identity, so a link removed and made again for the same identity is another
link, and a session bound to the old one cannot be renewed through it. A session with no bound link, such as one from an
unlinked handoff, is `not_signed_in`.

## What a renewal changes

| Renewed                                                             | Never changed                                                |
|---------------------------------------------------------------------|--------------------------------------------------------------|
| The session's authentication time, from the provider's              | The session's lifetime or expiry                             |
| Evidence newly accepted from this authentication, when there is any | Refresh tokens, none issued and none rotated                 |
|                                                                     | The session's sign-in provenance: connection, link, provider |
|                                                                     | Evidence accepted earlier, which this does not refresh       |

A `reauthenticate` also acknowledges no completed sign-in on the connection, activates no reservation and creates no
link. A subject held only by a reservation is `identity_mismatch`.

The time given is the provider's, as its assertion stated it. If your session already holds a later one, from another
flow redeemed first, keep the later one: under the session's lock, in the redemption's transaction, write `max(current,
provider_time)`, so a renewal never moves it backwards. That is your adapter's obligation, since the package does not
hold the session.

### Evidence

`$evidence` is what `EvidencePolicy` accepted of this result's own assertion, asked at redemption against current
policy. By default nothing is accepted and it is `null`. A `null` means nothing new, and leaves what the session already
holds as it is. Accepted evidence is an input to your further-factor policy, never a pass in itself. `$result->evidence`
carries the same value on the answer. See [Provider Evidence for Further Factors](evidence.md).

## Refusals

| Reason                    | Where      | Meaning                                                                                      |
|---------------------------|------------|----------------------------------------------------------------------------------------------|
| `session_ineligible`      | Start      | `standing()` did not answer `signed_in`                                                      |
| `id_token_invalid`        | Completion | An OpenID Connect ID token with no `auth_time`                                               |
| `response_invalid`        | Completion | A SAML assertion without exactly one `AuthnStatement`                                        |
| `authentication_expired`  | Completion | No authentication time from another driver, or one before the request less the skew          |
| `assertion_expired`       | Completion | An authentication time after now plus the skew                                               |
| `identity_mismatch`       | Completion | The subject resolves to nobody, a reservation or another identity                            |
| `link_suspended`          | Both       | The link is suspended until a confirming `link` flow                                         |
| `principal_scope_unknown` | Both       | The link's verified domain provenance needs a scope your contract could not judge, this once |
| `identity_mismatch`       | Redemption | The link observed at completion is gone or replaced, by its id                               |
| `session_ineligible`      | Redemption | The session is gone, revoked, of another application or connection, or bound to another link |
| `authentication_expired`  | Redemption | An adapter's own result states no authentication time                                        |

A refusal at redemption keeps the code consumed and renews nothing. The rest of the redemption's checks apply as they do
to every code: see [Redeeming a Handoff](redeeming-a-handoff.md).

## Events

| Event                         | When                                                                       |
|-------------------------------|----------------------------------------------------------------------------|
| `AuthorizationRequestStarted` | The start                                                                  |
| `ResultVerified`              | The response verified                                                      |
| `HandoffIssued`               | The code issued                                                            |
| `HandoffRedeemed`             | The code redeemed, once your transaction commits                           |
| `ReauthenticationCompleted`   | The renewal committed, straight after `HandoffRedeemed`; never on rollback |

A response the driver refuses reports one `FlowFailed` with no `ResultVerified`. A refusal after that, at completion,
reports `ResultVerified` then one `FlowFailed`, and one at redemption reports one `FlowFailed`. Every context names the
identity and the session the flow was started for. None carries a subject, an email, the authentication context, the
code or the verifier. See [Events](events.md).
