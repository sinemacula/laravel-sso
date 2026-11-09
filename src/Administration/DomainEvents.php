<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Administration;

use SineMacula\Laravel\Sso\Domains\DomainStanding;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure;
use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\DomainClaimed;
use SineMacula\Laravel\Sso\Events\DomainLapsed;
use SineMacula\Laravel\Sso\Events\DomainRecheckFailed;
use SineMacula\Laravel\Sso\Events\DomainRemoved;
use SineMacula\Laravel\Sso\Events\DomainRestored;
use SineMacula\Laravel\Sso\Events\DomainVerified;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;

/**
 * Reports the changes to a connection's domains (SSO-3, SSO-10.3): claimed,
 * verified and removed by the management helpers, and a failed recheck, a
 * restoration and a lapse by the scheduled check. Each method builds the
 * event's context through the one projection (`Events\EventContexts`), from the
 * connection's id, tenant and protocol and, when there is a caller, its
 * identity as the acting identity, and hands the event to
 * `Events\AfterCommitDispatcher`, so it reaches listeners once the change
 * commits and never when it rolls back (SSO-10.5).
 *
 * The caller reports inside the transaction that made the change, after the
 * write, once per change; never for a refusal or a no-op. No event carries the
 * verification token or a DNS record's value (SSO-10.4).
 *
 * Every method takes the client the action is taken for (`Http\ClientContext`),
 * whose IP address and user agent the event's context carries; nothing reads
 * the request being served. It holds the projection and the dispatcher, which
 * read the clock and the transaction from the container on each call, so
 * nothing of one request is kept for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DomainEvents
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContexts  $contexts
     * @param  \SineMacula\Laravel\Sso\Events\AfterCommitDispatcher  $dispatcher
     */
    public function __construct(

        /** The projection every event's context is built through. */
        private EventContexts $contexts,

        /** The dispatcher that waits for the change to commit. */
        private AfterCommitDispatcher $dispatcher,
    ) {}

    /**
     * Report a domain claimed, pending, for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \LogicException
     */
    public function claimed(Connection $connection, Domain $domain, ?Caller $caller, ClientContext $client): void
    {
        $expiresAt = $domain->pending_expires_at ?? throw new \LogicException('A claimed domain has a pending expiry.');

        $context = $this->context($connection, $caller, $client);

        $this->dispatcher->dispatch(new DomainClaimed($context, $domain->id, $domain->domain, DomainStanding::lookupName($domain), $expiresAt));
    }

    /**
     * Report a domain verified for the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \LogicException
     */
    public function verified(Connection $connection, Domain $domain, ?Caller $caller, ClientContext $client): void
    {
        $verifiedAt = $domain->verified_at ?? throw new \LogicException('A verified domain has a verification time.');

        $this->dispatcher->dispatch(new DomainVerified($this->context($connection, $caller, $client), $domain->id, $domain->domain, $verifiedAt));
    }

    /**
     * Report a scheduled check of a verified domain that did not confirm it,
     * with the time it lapses, as the row now holds it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure  $failure
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     */
    public function recheckFailed(Connection $connection, Domain $domain, RecheckFailure $failure, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new DomainRecheckFailed($this->context($connection, null, $client), $domain->id, $domain->domain, $failure, $domain->lapses_at));
    }

    /**
     * Report a domain whose record had gone confirmed again within its grace
     * period, with the verification time it keeps and the time of the check
     * that confirmed it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \LogicException
     */
    public function restored(Connection $connection, Domain $domain, ClientContext $client): void
    {
        $verifiedAt = $domain->verified_at              ?? throw new \LogicException('A restored domain has a verification time.');
        $checkedAt  = $domain->last_successful_check_at ?? throw new \LogicException('A restored domain has a successful check.');

        $this->dispatcher->dispatch(new DomainRestored($this->context($connection, null, $client), $domain->id, $domain->domain, $verifiedAt, $checkedAt));
    }

    /**
     * Report a domain lapsed at the end of its grace period.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     */
    public function lapsed(Connection $connection, Domain $domain, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new DomainLapsed($this->context($connection, null, $client), $domain->id, $domain->domain));
    }

    /**
     * Report a claim removed. Called with the row as it was read before the
     * delete, in the delete's transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     */
    public function removed(Connection $connection, Domain $domain, ?Caller $caller, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new DomainRemoved($this->context($connection, $caller, $client), $domain->id, $domain->domain, $domain->state));
    }

    /**
     * The context of a change to the connection's domain, by the acting
     * identity when there is one.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     */
    private function context(Connection $connection, ?Caller $caller, ClientContext $client): EventContext
    {
        return $this->contexts->make(
            $client,
            connectionId: $connection->id,
            connectionTenantId: $connection->tenant_id,
            protocol: $connection->protocol,
            actingIdentityMorphClass: $caller?->identity->type,
            actingIdentityId: $caller?->identity->id,
        );
    }
}
