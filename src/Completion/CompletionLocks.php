<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Domains\DomainFinder;
use SineMacula\Laravel\Sso\Domains\DomainName;
use SineMacula\Laravel\Sso\Enforcement\DatabaseEnforcement;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Linking\IdentityLock;
use SineMacula\Laravel\Sso\Linking\LinkingDiscovery;
use SineMacula\Laravel\Sso\Linking\ReservationDiscovery;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Metadata\TransitionReceipts;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * Takes a completion's locks and judges what it may do under them (`flows.md`,
 * `docs/design/linking.md`), for its first locked transaction and its final
 * continuation alike.
 *
 * `discover()` runs before the first locked transaction opens, by plain reads
 * (`Linking\ReservationDiscovery`), and finds whether the completion touches
 * linking and whose identity it would reserve for. An ordinary linked sign-in
 * and any path with the feature off take no guard.
 *
 * `take()` locks, each by a locking read on the write connection (SSO-11.3):
 * first, in the first locked transaction of a completion whose discovery found
 * one, the identity's guard (`Linking\IdentityLock`). Then, for a completion
 * still going on under the default `Contracts\Enforcement` with the feature on,
 * the enforcing tenant's rule, then the connection and the rule's connections
 * in ascending id order; otherwise the connection alone. Then, in that first
 * locked transaction of a `sign_in` whose locked connection has linking on
 * under the `domain_linking` feature, unless its discovery found the subject
 * held, this connection's claim of the linking email's canonicalised domain
 * (absent, the connection's row guards its insertion). Then the request.
 *
 * `refusal()` then judges the rows as locked: `connection_unavailable` when the
 * connection is gone or no longer usable, the request gone, voided or of
 * another trust version (unless the receipt permits exactly that transition),
 * or the enforcing tenant has moved; `metadata_expired` when what was fetched
 * for the connection has expired; `request_expired` when the verified
 * response's deadline has passed.
 *
 * It holds the enforcement contract, the drivers' registry, the metadata
 * expiry, the deadlines, the finder, the discovery and the identity lock, none
 * of which keeps anything of one completion for the next (SSO-11.2). A database
 * error propagates (SSO-11.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CompletionLocks
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Enforcement  $enforcement
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataExpiry  $metadata
     * @param  \SineMacula\Laravel\Sso\Completion\VerifiedDeadlines  $deadlines
     * @param  \SineMacula\Laravel\Sso\Domains\DomainFinder  $domains
     * @param  \SineMacula\Laravel\Sso\Linking\ReservationDiscovery  $discovery
     * @param  \SineMacula\Laravel\Sso\Linking\IdentityLock  $identities
     */
    public function __construct(

        /** Locks the enforcement of the connection's tenant, when it is the default. */
        private Enforcement $enforcement,

        /** Whether the connection is still usable under its lock. */
        private ProtocolManager $protocols,

        /** Whether what was fetched for the locked connection has expired. */
        private MetadataExpiry $metadata,

        /** Whether the verified response's deadline has passed. */
        private VerifiedDeadlines $deadlines,

        /** Finds the connection's claim of a domain, locked. */
        private DomainFinder $domains,

        /** Finds, by plain reads, what a completion's locks need. */
        private ReservationDiscovery $discovery,

        /** Locks the identity a reservation would be made for. */
        private IdentityLock $identities,
    ) {}

    /**
     * What plain reads find to lock, before the locked transaction opens.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Linking\LinkingDiscovery
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function discover(CompletionState $state): LinkingDiscovery
    {
        return $this->discovery->discover($state);
    }

    /**
     * Take the locks, in order.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  bool  $goingOn
     * @param  bool  $withDomain
     * @param  ?\SineMacula\Laravel\Sso\Linking\LinkingDiscovery  $discovery
     * @return \SineMacula\Laravel\Sso\Completion\CompletionLock
     *
     * @throws \LogicException
     */
    public function take(CompletionState $state, bool $goingOn, bool $withDomain, ?LinkingDiscovery $discovery = null): CompletionLock
    {
        $held        = $state->connection           ?? throw new \LogicException('A consumed completion holds its connection.');
        $application = $state->application          ?? throw new \LogicException('A consumed completion holds its application.');
        $request     = $state->authorizationRequest ?? throw new \LogicException('A consumed completion holds its request.');

        $this->lockIdentity($discovery, $goingOn && $withDomain);

        $enforcement = $goingOn && $this->enforcement instanceof DatabaseEnforcement ? $this->enforcement->lock($held->tenant_id, $application->name, [$held->id]) : null;
        $connection  = $enforcement === null
            ? Connection::query()->useWritePdo()->lockForUpdate()->whereKey($held->id)->first()
            : $enforcement->connection($held->tenant_id, $held->id);
        $domain = $goingOn && $withDomain && ($discovery->locksDomain ?? true) ? $this->relevantDomain($state, $connection) : null;

        return new CompletionLock($connection, AuthorizationRequest::query()->useWritePdo()->lockForUpdate()->whereKey($request->id)->first(), $enforcement, $domain, $discovery);
    }

    /**
     * Why the completion may not go on under its locks, or `null` when it may.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionLock  $lock
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public function refusal(CompletionLock $lock, CompletionState $state): ?FailureReason
    {
        if (!$this->isGoingOn($lock, $state)) {
            return FailureReason::CONNECTION_UNAVAILABLE;
        }

        return match (true) {
            $lock->connection !== null && $this->metadata->isExpired($lock->connection) => FailureReason::METADATA_EXPIRED,
            $this->deadlines->hasPassed($state->verifiedUntil)                          => FailureReason::REQUEST_EXPIRED,
            default                                                                     => null,
        };
    }

    /**
     * Take the guard of the identity the discovery found, first of the order.
     *
     * @param  ?\SineMacula\Laravel\Sso\Linking\LinkingDiscovery  $discovery
     * @param  bool  $preparing
     * @return void
     *
     * @throws \LogicException
     */
    private function lockIdentity(?LinkingDiscovery $discovery, bool $preparing): void
    {
        $identity = $discovery?->identity;

        if (!$preparing || $identity === null) {
            return;
        }

        $this->identities->acquire($identity);
    }

    /**
     * Whether the connection is usable, the request is live, and the rule
     * locked is still the enforcing tenant's.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionLock  $lock
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return bool
     */
    private function isGoingOn(CompletionLock $lock, CompletionState $state): bool
    {
        $connection = $lock->connection;
        $request    = $lock->request;

        if ($connection === null || $request === null || !$this->protocols->isUsable($connection) || $request->voided_at !== null) {
            return false;
        }

        $live = $request->trust_version === $connection->trust_version || TransitionReceipts::permits($state->transitionReceipt, $connection, $request);

        return $live && ($lock->enforcement?->isCurrent() ?? true);
    }

    /**
     * This connection's claim of the linking email's canonicalised domain,
     * locked, for a `sign_in` whose locked connection has linking on; `null`
     * otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?\SineMacula\Laravel\Sso\Models\Domain
     */
    private function relevantDomain(CompletionState $state, ?Connection $connection): ?Domain
    {
        $email = $state->result?->linkingEmail;

        if ($connection === null || $email === null || !$connection->linking_enabled || $state->consumed?->purpose !== Purpose::SIGN_IN) {
            return null;
        }

        $domain = Features::enabled(Feature::DOMAIN_LINKING) ? DomainName::normalize($email->domain()) : null;

        return $domain === null ? null : $this->domains->find($connection, $domain, true);
    }
}
