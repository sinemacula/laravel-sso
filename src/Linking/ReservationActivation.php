<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkEvents;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * Judges and activates the reservation a `sign_in` handoff is bound to
 * (SSO-8.8) inside its redemption's transaction, with the identity's guard, the
 * connection, the domain claim, the code and then the reservation's row locked,
 * in the package's order.
 *
 * `judge()` answers `passed` only when the row is exactly the handoff's
 * reservation, unexpired, for the result's subject and the identity whose guard
 * is held, so a principal widening cannot slip between this judgement and the
 * commit; the result's linking email and accepted organisation are the ones
 * bound; the domain claim locked is the one bound, at the same verification
 * generation, so a re-verification never revives it; the linking policy version
 * is the one bound; and every condition of
 * `DomainLinkEligibility::isStillEligible()` holds for that same identity.
 * Anything else is `reservation_invalid`, and a different match is never the
 * new target.
 *
 * `activate()` makes the row active with verified domain provenance
 * (`Links\LinkReservations::activate()`), records on the identity's guard that
 * it has held such a link (`Linking\IdentityLock::recordDomainLink()`), which
 * nothing clears, and reports `LinkCreated` then `LinkActivated`, after commit.
 *
 * It holds the storage binding, the eligibility, the identity lock and the
 * reporter, none of which keeps anything of one redemption for the next
 * (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReservationActivation
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkStorageBinding  $storage
     * @param  \SineMacula\Laravel\Sso\Linking\DomainLinkEligibility  $eligibility
     * @param  \SineMacula\Laravel\Sso\Linking\IdentityLock  $identities
     * @param  \SineMacula\Laravel\Sso\Links\LinkEvents  $events
     */
    public function __construct(

        /** Reads and activates the reservation. */
        private LinkStorageBinding $storage,

        /** Judges the conditions a reservation stands on. */
        private DomainLinkEligibility $eligibility,

        /** Records on the identity's guard that it has held a domain link. */
        private IdentityLock $identities,

        /** Reports the activation. */
        private LinkEvents $events,
    ) {}

    /**
     * Whether the handoff's reservation may be activated now.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function judge(RedemptionContext $context): RecheckOutcome
    {
        $row = $this->row($context);

        if ($row === null) {
            return RecheckOutcome::RESERVATION_INVALID;
        }

        $identity = new IdentityReference($row->identity_type, $row->identity_id);
        $holds    = $context->lock->isGuarding($identity)
            && self::isBound($row, $context)
            && $this->eligibility->isStillEligible($context->result, $identity, $context->connection, $context->lock->domain);

        return $holds ? RecheckOutcome::PASSED : RecheckOutcome::RESERVATION_INVALID;
    }

    /**
     * Activate the handoff's reservation, and answer its identity, its link and
     * the provenance the activation gave the link.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return array{0: \SineMacula\Laravel\Sso\Identities\IdentityReference, 1: string, 2: \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin}
     *
     * @throws \LogicException
     */
    public function activate(RedemptionContext $context): array
    {
        $row      = $this->row($context) ?? throw new \LogicException('A reservation is activated once it is judged.');
        $identity = new IdentityReference($row->identity_type, $row->identity_id);
        $link     = $this->reservations()->activate($row);
        $result   = $context->result;

        $this->identities->recordDomainLink($identity);

        $this->events->activated($context->connection, $identity, $link->id, $result->application, $result->requestReference);

        return [$identity, $link->id, $link->provenance];
    }

    /**
     * The handoff's reservation, if it is still exactly its row, locked.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return ?\SineMacula\Laravel\Sso\Models\Link
     *
     * @throws \InvalidArgumentException
     */
    private function row(RedemptionContext $context): ?Link
    {
        $binding = $context->binding;

        if ($binding->reservationId === null || $binding->handoffReference === null) {
            return null;
        }

        $reservations = $this->reservations();
        $row          = $reservations->locked($binding->reservationId);

        if ($row === null || !$reservations->isBoundTo($row, $binding->handoffReference, $context->connection->id, LinkSubject::of($context->result))) {
            return null;
        }

        return $row;
    }

    /**
     * The one writer of a reserved row, of the bound storage.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkReservations
     *
     * @throws \LogicException
     */
    private function reservations(): LinkReservations
    {
        return $this->storage->require('Linking by a verified domain')->reservations();
    }

    /**
     * Whether what the reservation is bound to is exactly what the redemption
     * holds: the request, the email, the organisation, the domain at its
     * generation and the linking policy version.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $row
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return bool
     */
    private static function isBound(Link $row, RedemptionContext $context): bool
    {
        $result = $context->result;
        $email  = $result->linkingEmail;

        if ($email === null || $row->reservation_reference !== $result->requestReference->value || $row->reservation_organization !== $email->organization) {
            return false;
        }

        if ($row->reservation_linking_version !== $context->connection->linking_version || !self::isSameDomain($row, $context->lock->domain)) {
            return false;
        }

        return ConstantTime::equals((string) $row->reservation_email_digest, LinkReservations::emailDigest((string) $row->reservation_id, $email->email));
    }

    /**
     * Whether the claim locked is the reservation's, at the same generation.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Link  $row
     * @param  ?\SineMacula\Laravel\Sso\Models\Domain  $domain
     * @return bool
     */
    private static function isSameDomain(Link $row, ?Domain $domain): bool
    {
        return $domain !== null
            && $row->reservation_domain_id         === $domain->id
            && $row->reservation_domain_generation === $domain->verification_generation;
    }
}
