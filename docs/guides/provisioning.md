# Provisioning

Provisioning creates a new identity the first time someone signs in through a connection, just in time, inside the flow.
When a `sign_in` result resolves to no identity and holds no reservation, the package offers it to your listeners,
synchronously and before any handoff is issued, with a single-use grant. A listener may create the identity and its
membership and link the result to it. The package then resolves the link again, so the same sign-in finishes as a linked
one.

The package itself creates no identity, principal or membership. Under `laravel-iam`, its listener does.

## When a result is offered

Only a genuinely unlinked `sign_in` is offered. These are never offered:

- a result already linked;
- a result that reserved a link through a [verified domain](domains.md), since linking by a verified domain runs first;
- a subject whose link is suspended, which ends with `link_suspended` until the person confirms it;
- a subject another flow's live reservation holds, which ends with `link_reserved`;
- a `link` or a `reauthenticate` flow.

## Writing the listener

The listener is a class of your application, here `ProvisionNewPerson`, which takes `Provisioning\ProvisioningHelper`
by injection. It creates a new `User`, named from the mapped `display_name`, and their membership of the result's
tenant, each a model of yours stored on the package's storage connection, and links the result to the user, all in one
transaction on that connection, which it commits only when the helper answers `created`:

<!-- snippet: tests/Integration/Examples/Provisioning/ProvisionNewPerson.php#provisioning-listener -->

```php
/**
 * Take the helper that links the result to the new person.
 *
 * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningHelper  $provisioning
 */
public function __construct(

    /** Links the result to a new identity, once, with the event's grant. */
    private ProvisioningHelper $provisioning,
) {}

/**
 * Create a new user and their membership, and link the result to them, in
 * one transaction on the package's storage connection.
 *
 * @param  \SineMacula\Laravel\Sso\Events\ResultUnlinked  $event
 * @return void
 *
 * @throws \Throwable
 */
public function handle(ResultUnlinked $event): void
{
    $storage = DB::connection(StorageConnection::name());

    $storage->beginTransaction();

    try {
        // Always a new user: never one found by an attribute
        $user = User::create(['name' => $event->result->attributes['display_name'] ?? 'New person']);

        $user->memberships()->create(['tenant_id' => $event->result->tenantId]);

        $identity = new IdentityReference($user->getMorphClass(), (string) $user->getKey());

        $client = new ClientContext($event->context()->ip, $event->context()->userAgent); // the completion's client

        $answer = $this->provisioning->link($event->grant, $event->result, $identity, $client);
    } catch (\Throwable $exception) {
        $storage->rollBack();

        throw $exception;
    }

    if (!$answer->isCreated()) {

        // A refusal wrote nothing, so neither does the listener
        $storage->rollBack();

        return;
    }

    $storage->commit();
}
```

Bind the package's `Links\LinkStore` as your `Contracts\Linker` ([Links](links.md)), or a wrapper implementing
`Contracts\LinkStorage` that delegates to it: the helper writes to the link store, and the final step of the completion
finds the link through the linker. The default linker links nothing, so the helper refuses over it with a
`LogicException` before it spends the grant or writes anything, since the link would never resolve.

Register the listener synchronously, on the event's class, in a service provider's `boot()`:

<!-- snippet: tests/Integration/Examples/Provisioning/AppServiceProvider.php#provisioning-registration -->

```php
Event::listen(ResultUnlinked::class, ProvisionNewPerson::class);
```

### A queued listener is too late

The event must reach your listener before the handoff is issued, and its grant is void once the dispatch returns, so a
listener that implements `ShouldQueue` can provision nothing. It does not fail quietly: the event refuses to be
serialised, so queuing it throws. The queue reports that it could not serialise the job, with the event's
`LogicException` as the cause, and the completion ends as a server error.

### The identity must be new

A listener must create a new identity. Resolving an existing identity from the email, or from any other mapped
attribute, is forbidden: whoever controls a connection's mapped attributes could otherwise take over any account that
shares that value.

To attach a subject to an existing identity, use one of the two paths made for it:

- the [`link` purpose](starting-a-flow.md), started for an identity your application has authenticated with fresh
  authentication (SSO-8.5);
- [linking by a verified domain](linking-by-domain.md), which requires the conditions of SSO-8.8.

The package holds only an opaque identity reference, so it cannot tell when an identity was created: the grant proves
the authority to provision for this result, not that the identity is new. That the identity is new is your listener's
obligation, and under `laravel-iam` its adapter's.

### One transaction, on the same connection

Wrap the identity, its membership and the link in one transaction on the package's storage connection, and roll it back
when the helper refuses. The helper then runs in a savepoint inside yours, and takes the package's locks until you
commit. Writes through another connection are not atomic with the link.

Commit or roll back before the listener returns. A transaction left open is rolled back, and is a `LogicException`,
since it would hold its locks across the rest of the completion.

Take the package's locks before your own guards, in the same relative order as your other writers. Inserting a new
identity needs no guard; a listener that locks shared rows of yours before it calls the helper risks a deadlock against
a concurrent admission.

### Retrying after a deadlock

On MySQL's InnoDB at its default `REPEATABLE READ`, the helper's locking reads of a new identity's links lock the gap
where its rows would go, so two first sign-ins at once can deadlock, and the database rolls one back. Retry the
listener's whole transaction, as `DB::connection(StorageConnection::name())->transaction($work, 3)` does: once that
transaction has rolled back, the grant can be claimed again. Running the listener's transaction at `READ COMMITTED`
takes no such gap locks, and is recommended.

## The helper

`ProvisioningHelper::link()` takes the grant, the exact result the event carried and the new identity, and answers a
`ProvisioningResult`. A refusal is a value, never thrown, and writes nothing.

| `status`                 | `reason()`                   | Why                                                                                                                                       |
|--------------------------|------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| `created`                | `null`                       | The link was made, active, with `provisioning` as its origin; `link` holds its summary                                                    |
| `grant_invalid`          | `provisioning_grant_invalid` | The grant was already used, or its dispatch has ended                                                                                     |
| `grant_wrong_result`     | `provisioning_grant_invalid` | The grant was presented with anything but the exact result object the event carried: a bug in your listener, and the grant is spent       |
| `request_unavailable`    | `connection_unavailable`     | The connection is disabled, gone or incomplete, what was fetched for it has expired, or the request was voided or its trust version moved |
| `expired`                | `request_expired`            | The verified response's deadline has passed                                                                                               |
| `subject_already_linked` | `subject_already_linked`     | The subject is held in the connection: linked, suspended or reserved, to this identity or another; the answer never says which            |
| `link_limit_reached`     | `link_limit_reached`         | The identity holds as many links in the connection as it may ([Links](links.md))                                                          |

### One use

The grant allows one use, claimed before anything else is attempted:

- A refused attempt cannot be repeated, for this identity or another.
- A claim is given back only when the transaction it was made in rolls back as a whole: your outermost transaction on
  the storage connection, or the helper's own when you have none. A commit, or a rollback of a savepoint inside it,
  leaves the grant used.
- A second listener, and a call made from inside the helper's own work, get `grant_invalid`. Every listener shares the
  one grant, so register one listener that provisions.
- The grant is bound to the exact result object, not to its fields: a result rebuilt from the same values is
  `grant_wrong_result`, and that attempt spends the grant too. Roll your identity and membership transaction back when
  it answers so, like any refusal; recovery is a new flow, not another use of that grant.
- A grant kept after the dispatch returned or a listener threw is void, however fresh the request looks.

Neither the grant nor the event can be serialised, and the grant cannot be cloned. Neither shows the result, the subject
or an attribute in a dump, an export or JSON.

### The verified response's deadline

A verified response stops being valid at the earlier of its request's expiry and
`sso.linking.verified_result_max_age_seconds` (default 120, 5 to 300) from when it was verified. The helper checks it
before it writes, and the completion again before it issues the handoff. A slow listener never finishes on an old
response, and nothing extends a request's authority.

## What happens next

Once the listeners have returned, with no package lock held in between, the completion takes its locks again and checks
everything once more: trust, voiding, the deadline, metadata, enforcement and the application's policy. It resolves the
link anew. It does not record the response against replay again, select a domain or offer the result again.

| Then                            | The completion                                                                 |
|---------------------------------|--------------------------------------------------------------------------------|
| The link resolves               | issues a handoff bound to that link, whichever identity holds it               |
| Still unlinked                  | fails with `unlinked`, unless the application allows unlinked handoffs         |
| Suspended or reserved since     | fails with `link_suspended` or `link_reserved`, never with an unlinked handoff |
| Something else no longer stands | fails with its reason, such as `connection_unavailable` or `request_expired`   |

Allowing unlinked handoffs is for an application that resolves identities itself when it redeems the code; see
[Completing a Flow](completing-a-flow.md). It applies only to a link that is genuinely absent. Under `laravel-iam` the
sign-in adapter always requires a linked identity: it keeps `unlinked_handoffs` off and rolls back a redemption that
admitted none. It provisions on `ResultUnlinked` alone, never on `laravel-authentication`'s own unlinked-result event,
which is informational (see [Integrating with `laravel-iam`](integrating-with-laravel-iam.md#provisioning)).

### A provisioned identity can survive a failed sign-in

Provisioning runs outside the package's locks, so a slow listener cannot hold up a tenant's admissions and
administration. Its transaction commits before the completion's final step, so that step can still refuse: a connection
disabled in between, say, or a deadline passed. The person then sees a failed sign-in, while the identity, its
membership and the link stay made. The link is an ordinary one: their next sign-in through the connection resolves to
it.

Treat a provisioned identity as made once your transaction commits, not once the person is signed in.

## When a listener throws

A listener's exception ends the completion as a server error, and propagates to your exception handler:

- the request stays consumed and unfinished, and no handoff is issued;
- nothing resumes the completion: what let it go on was kept only in memory, as it is after a crash;
- a replay of the response is refused as `request_unknown`, and is not offered again;
- anything the listener already committed stays committed.

The person starts a new flow.

## Events

| Sequence                 | Events                                                                              |
|--------------------------|-------------------------------------------------------------------------------------|
| Provisioned              | `ResultVerified`, `ResultUnlinked`, `LinkCreated` (`provisioning`), `HandoffIssued` |
| Not provisioned          | `ResultVerified`, `ResultUnlinked`, `FlowFailed` (`unlinked`)                       |
| Allowed unlinked handoff | `ResultVerified`, `ResultUnlinked`, `HandoffIssued`                                 |
| A listener threw         | `ResultVerified`, `ResultUnlinked`, and nothing after                               |

`ResultUnlinked` is the one event that is not dispatched after a commit: it runs synchronously, with no package
transaction open. It is also the one that carries a result, as `$event->result`, and it does so only for a listener
reading it. Everything else follows its transaction's commit, so `LinkCreated` waits for your transaction's outer commit
and never comes on its rollback. `ResultVerified` is reported once per verified response.

On PostgreSQL under `REPEATABLE READ`, a listener's transaction whose snapshot predates a change it then waits on fails
to serialise (SQLSTATE `40001`) rather than refusing. Unless the listener retries its whole transaction, the error
propagates as a server error, and the person starts again.
