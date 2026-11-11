# Octane, Queue Workers and Read Replicas

The package is stateless between requests, so it runs under Octane, in queue workers and behind read replicas without
configuration of its own. What it asks of you is about the contracts you bind and the routes you add. The invariants
behind this guide are in [the design note](../design/long-running-processes.md).

## No session

No flow needs a session. The start, both completion endpoints, discovery, the metadata and the public keys, every
redemption and a re-initiation all run with no session middleware, and no response sets a cookie. What a flow needs
later is its own stored request, found by what the identity provider sends back; what the client needs is the
reference and the verifier it keeps. Register the routes outside the `web` group (see
[An example application](example-application.md)).

## Binding your own contracts

One worker serves one tenant, then another, then the first again, so nothing may carry a connection, a tenant, a flow
or a result from one request or job to the next.

- **Keep nothing between calls.** Most contracts are singletons by default, so under Octane one instance answers every
  request the worker serves. Read what you need each time, from the write connection.
- **What you bind is yours.** The package binds each default under a private key, `sso.default:` followed by the
  contract's name, and binds the contract itself to a closure that resolves that key on every call. The defaults that
  read configuration or a connection are scoped: the fetcher, the DNS resolver, the endpoint resolver, the secret
  encrypter, the single-use store, the attempt limiter, the enforcement contract and the handoff issuer. The rest are
  singletons. Whatever you bind over a contract, with `bind()`, `singleton()`, `scoped()` or `instance()`, stands
  from one request to the next, and the default never comes back. An instance serves every request the worker
  handles, so it must keep nothing of any one. `SsoServiceProvider::isPackageDefault($app, $contract)` tells you
  whether a contract is still on the package's default.
- **Extend the default's key, not the contract.** The contract is resolved afresh on every `make()`, so an `extend()`
  or `afterResolving()` callback on it runs every time, not once per request: one that changes the object changes the
  same scoped default again, and one that wraps it wraps it again. An `afterResolving()` on the contract can also run
  twice on the first resolution, once for the default's key and once for the contract. Extend `sso.default:` followed
  by the contract's name instead, or bind your own.
- **Forgetting the package's state yourself.** A long-running command that does several units of work without
  Laravel's reset of the scoped instances calls `SineMacula\Laravel\Sso\Support\RequestState::forget(app())` between
  them. It forgets the package's scoped defaults and its driver scope, and nothing else.
- **A protocol driver of your own** is rebuilt once per request or job by the creator you gave
  `ProtocolManager::extend()`, so it may hold scoped services, and must hold nothing else.
- **A verified result and a provisioning grant** live for their request: a grant kept for later is `grant_invalid`, and
  `ResultUnlinked` refuses to be queued or serialised.

## Read replicas

Whatever decides admission is read from the write connection: a connection's switch and trust version, a request, a
code, a link and a reservation, keys, a domain, enforcement, single-use keys and the rate limit counters. A replica that
lags the primary, either way, can neither fail a valid completion nor pass a replay. Your contracts are asked inside the
package's transactions and must read the same way: from the write connection, with a locking read where your answer
must hold until the commit (see [Links](links.md#deciding-who-may-link) and
[Re-authenticating](reauthenticating.md#locking-the-session)).

## Database errors

A failing statement or commit is a server error from every flow: never a refusal, a failure redirect or a `400`, and it
reports no failure event. Do not catch it to send the browser to your redirect URI with an `error`: an outage is not
the person's to act on. What survives is what each transaction committed, so a completion rolled back by an error
leaves its request consumed and the browser starts again, and a redemption rolled back leaves its code unspent.

## The cache and the queue

No flow uses the cache: with it down, or answering anything, every flow comes to the same result. The schedule is
another matter: Laravel 13's `schedule:run` reads its pause signal from your default cache before any task, and the
package's mutexes are an opt-in that needs a shared cache with locks (see
[Operations](operations.md#several-servers-and-the-cache)).

The one job the package queues is a connection's metadata refresh, which carries the connection's id alone; run a
worker for it ([Operations](operations.md#queues)). A queued listener of the package's events needs a worker too, and
is told of an event only after its transaction commits.
