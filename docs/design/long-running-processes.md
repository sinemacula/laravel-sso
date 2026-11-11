# Long-Running Processes

## Purpose

This note records what the package promises of the processes it runs in, and how the suite proves it (SSO-11.1 to
SSO-11.4, SSO-11.6): no session, nothing kept from one request or job for the next under Octane or a queue worker, every
read that decides admission on the write connection, a database error always a server error, and a cache that is never
needed. It holds no new behaviour: each promise is kept where it is stated, and this note says where to look. The single
use store's own guarantees are in `single-use-store.md`, the transactions a failure rolls back are in `linking.md`, and
the schedule's are in `operations.md`.

## Invariants

### No session (SSO-11.1)

- No flow needs a session. A start, a completion at either endpoint, discovery, service provider metadata, public keys,
  a redemption of each purpose and a re-initiation each run on a route in no middleware group, and neither resolve nor
  start the session.
- What a flow needs later is its request row: the digest of its state and of its nonce, the provider's PKCE verifier
  encrypted, the challenge of the client's verifier, the identity and session it was started for, and its connection's
  trust version. Neither the state, the nonce nor the client's verifier is stored. Without the row, the same answer from
  the provider is refused.
- The client holds its reference and its verifier, and nothing else of the package's. No response sets a cookie.

### Nothing kept (SSO-11.2)

- A binding that reads configuration or a connection is scoped, and one that holds nothing between calls a singleton.
  No service holds a connection, tenant, flow or result. No package class holds such a value in a static property.
- Each default is bound under its private key, `sso.default:` and the contract's name (`Support\PackageDefaults`),
  scoped or a singleton, and the contract to a transient closure the provider declares that resolves the key. The
  contract is never scoped and never holds an instance of the package's, so whatever an application binds over it,
  `instance()` included, outlives every request and job. `SsoServiceProvider::isPackageDefault()` tells the package's
  default from a binding made over it.
- `Support\RequestState::forget()` forgets the package's scoped defaults and `Protocols\DriverScope`, and nothing
  else, for a process that cannot forget every scoped instance between units of work.
- `Events\StrandedTransactions` is a singleton, resolved when the provider boots, though it keeps marks between calls:
  the transaction records a failed commit left on Laravel 12, held weakly, so the `TransactionBeginning` listener that
  marks them and the after-commit callbacks that check them share one instance. It holds nothing of a request.
- `Protocols\ProtocolManager` is a singleton, and a driver holds scoped services: `SecretEncrypter`, `EndpointResolver`
  and `Fetcher`. So the registry keeps a driver for one scope alone, a request's sandbox or a job, knowing the scope by
  the scoped `Protocols\DriverScope`, and builds it again in the next, by its creator when it is a registered driver's.
- One worker serves A, then B, then A, whichever protocols, issuers, keys and allow-lists they have, and under one
  `kid`: each flow is served from its own rows, through success, refusal and exception alike. An exception is answered
  with a 500 by the kernel, leaves no transaction open, and the next request runs in the same worker.
- A `Provisioning\ProvisioningGrant` is good for one dispatch: closed when the dispatch ends or a listener throws, and
  registered in a map that dies with its request, so one kept for the next is `grant_invalid`, for any result.
- A `Protocols\TransitionReceipt` names one connection and one request, and permits one transition: for another
  request, even with every version the same, or once its own request has finished, it permits nothing.
- A verified result and a grant do not outlive their request: nothing keeps a reference to either.
- The one class the package queues is `Metadata\RefreshConnectionMetadata`, which carries a connection's id alone.
  `Events\ResultUnlinked` is dispatched synchronously and refuses to be serialised, so no provisioning listener can be
  queued. A job that throws is the queue worker's to record, and the next job runs.

### The write connection (SSO-11.3)

- Whatever decides admission is read from the write connection, so a replica that contradicts the primary, in either
  direction, cannot fail a valid completion or pass a replay: a connection's switch and trust version, a request, a
  code, a link and a reservation, keys and JWKS, a domain, enforcement and its version, single-use keys, and the rate
  limit counters on their own connection.
- `Pruning\Pruner`, `Keys\ExpiryReport`, `Domains\DomainRechecker` and `Metadata\MetadataRefresher` choose their
  candidates there too.
- A flow never needs the replica: with its tables gone, every flow runs.

### Database errors (SSO-11.4)

- A failing statement or commit propagates from every step of a flow, never as `failed`, `request_unknown`,
  `connection_unavailable`, an invalid response or a failed redemption, and reports no failure event. Through the kernel
  it is a 5xx with no `Location`, and `Responses\CompletionResponses` turns none into a failure redirect.
- What survives is what the transaction owns:

  | Failure in   | Stands                            | Goes                                         |
  |--------------|-----------------------------------|----------------------------------------------|
  | T1           | Nothing: the answer can go again  | The record and `consumed_at`                 |
  | T2           | T1                                | Its code, reservation, record and events     |
  | T3           | T1, T2, its events, `verified_at` | Its code, `completed_at` and its events      |
  | A redemption | Nothing: the code can go again    | The record, `redeemed_at` and the activation |

- A console command exits non-zero and names the exception by its class alone, printing no statement, binding or
  message. `sso:check` opens no connection, so a failing database changes nothing it says.

### The cache (SSO-11.6)

- Nothing the package ships names or resolves a cache, but for `Operations\OperationsSchedule`, which names the
  scheduler's mutexes behind `sso.operations.cache_mutexes`. A flow with the cache down or lying calls it no time, and
  comes to the same result.
- The mutexes are an optimisation an application opts in to: a stuck one stops only those tasks, for at most
  `sso.operations.mutex_minutes`, or until `schedule:clear-cache` runs. With them off, a mutex stops nothing.
- `schedule:run` is the framework's own. On Laravel 13 its pause signal is on by default, and it reads the application's
  default cache before any task: a cache that is down stops the whole schedule, and one that answers anything truthy
  reads as paused. `Schedule::withoutInterruptionPolling()` turns that off, for every task of the application, and
  `schedule:pause` and `schedule:interrupt` with it. With it off, `schedule:run` calls the cache no time.
- An optional cache is one thing; what an application binds as authoritative another. A single-use store over Redis,
  or a queue, is a dependency it chose, with the guarantees `docs/guides/single-use-store.md` asks of it. A store that
  throws, or cannot say, refuses the flow with a server error and never passes it; a queue that is down fails the
  command that queues on it, and no flow.

## Success Path

1. A browser's start reaches a route with no session. The package stores the request and answers the reference, the
   verifier and where the browser goes.
2. The provider's answer reaches another route, perhaps of another worker, with no cookie. The package finds the
   request by the digest of what the provider returned, on the write connection, consumes it, validates, and hands off
   with a code, each through scoped services that are gone when the request ends.
3. The client redeems the code with its verifier on the write connection, in the transaction that writes its session.

## Failure / Edge Cases

- A database error in T2 or T3 leaves a request consumed and unfinished, since T1 committed: nothing resumes it, and the
  person starts again. A provisioned link committed by a listener can survive a later T3 failure.
- A retried redemption, once its transaction rolled back, finds the code unspent and runs as new.
- A statement that fails before the transaction it would be in is no different: the plain reads that find what to lock
  propagate as the locked ones do.
- An `extend()` or `afterResolving()` callback on a contract runs on every resolution, since the contract is
  transient: one that changes the default changes the same scoped instance again, and one that wraps it wraps it again.
  An `afterResolving()` on the contract can run twice on the first resolution, once for the private key and once for
  the contract. An application extends the default's private key instead.
- A cache that is healthy but empty is not a failure of anything: a mutex taken again, nothing more.

## Implementation Anchors

- `src/Support/PackageDefaults.php`: which default is scoped and which a singleton; `src/SsoServiceProvider.php`: how
  each is bound, and `isPackageDefault()`.
- `src/Support/RequestState.php`.
- `src/Flows/AuthorizationRequestService.php`, `src/Flows/RequestConsumption.php`: the request row, and T1.
- `src/Completion/CompletionPipeline.php`, `src/Completion/CompletionLocks.php`: T2 and T3, and that nothing is
  caught.
- `src/Completion/ProvisioningOffer.php`, `src/Provisioning/ProvisioningGrant.php`,
  `src/Provisioning/ProvisioningHelper.php`.
- `src/Metadata/TransitionReceipts.php`, `src/Protocols/TransitionReceipt.php`.
- `src/Handoffs/HandoffRedemption.php`, `src/Handoffs/HandoffRecheck.php`.
- `src/Responses/CompletionResponses.php`: it catches nothing.
- `src/Operations/OperationsSchedule.php`: the one class that names a mutex.

## Authoritative Tests

- `tests/Unit/SsoServiceProviderTest.php`
- `tests/Unit/Support/RequestStateTest.php`
- `tests/Integration/Process/SessionlessFlowsTest.php`
- `tests/Integration/Process/ConsecutiveRequestsTest.php`
- `tests/Integration/Process/QueueWorkerIsolationTest.php`
- `tests/Integration/Replica/LaggingReplicaFlowsTest.php`
- `tests/Integration/Replica/LaggingReplicaOperationsTest.php`
- `tests/Integration/Failures/DatabaseFailureServiceTest.php`
- `tests/Integration/Failures/DatabaseFailureHttpTest.php`
- `tests/Integration/Failures/DatabaseFailureConsoleTest.php`
- `tests/Integration/Failures/CacheOutageTest.php`
- `tests/Unit/Architecture/NoCacheDependencyTest.php`
- `tests/Integration/Completion/OidcWorkerIsolationTest.php`
- `tests/Integration/Clock/ClockAcrossRequestsTest.php`

## Change Triggers

Update this note when a binding moves between scoped and singleton, when a class comes to hold a value of a flow, when a
new read decides admission, when a transaction's boundary moves, when a class comes to be queued, or when the package
comes to name a cache. Check it against the framework when the supported Laravel versions change: the scheduler's own
use of the cache has moved between versions.
