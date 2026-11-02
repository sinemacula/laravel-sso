<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Domains\DomainFinder;
use SineMacula\Laravel\Sso\Domains\DomainSettings;
use SineMacula\Laravel\Sso\Domains\DomainStanding;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * Finds, before a completion opens its locked transaction, what it needs to
 * lock in the package's order (SSO-8.8, `docs/design/linking.md`): whether the
 * completion touches linking at all, and whose identity guard to take first.
 * Every read is plain and decides nothing; `Linking\DomainLinkEligibility`
 * judges it all again under the locks, and refuses a target it holds no guard
 * of.
 *
 * In this order, each answer ending it:
 *
 * 1. a result that is no `sign_in`, holds no linking email, or arrives with the
 *    feature or the connection's linking off is `notApplicable()`, with nothing
 *    read;
 * 2. the bound `Contracts\Linker` not backed by `Contracts\LinkStorage` is a
 *    `LogicException`: linking by a verified domain is on, and nothing it wrote
 *    would be resolved;
 * 3. one plain read of the subject's row: any but an expired reservation is
 *    `subjectHeld()`, so an ordinary linked sign-in costs what it did and takes
 *    no guard;
 * 4. one plain read of this connection's claim of the email's domain: none, or
 *    one whose standing does not allow linking, is `open()` with no identity,
 *    and the application's contract is not asked;
 * 5. `Contracts\LinkEmailMatcher` is asked; exactly one match is `open()` with
 *    that identity, and anything else `open()` with none.
 *
 * It holds the container's binding, the eligibility, the finder, the settings
 * and the clock, none of which keeps anything of one completion for the next
 * (SSO-11.2). A contract's exception propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReservationDiscovery
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkStorageBinding  $storage
     * @param  \SineMacula\Laravel\Sso\Linking\DomainLinkEligibility  $eligibility
     * @param  \SineMacula\Laravel\Sso\Domains\DomainFinder  $domains
     * @param  \SineMacula\Laravel\Sso\Domains\DomainSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Whether the bound linker is backed by link storage. */
        private LinkStorageBinding $storage,

        /** Canonicalises the email's domain and asks the matcher. */
        private DomainLinkEligibility $eligibility,

        /** Reads the connection's claim of the domain. */
        private DomainFinder $domains,

        /** The linking maximum age. */
        private DomainSettings $settings,

        /** The clock the claim's standing is read at. */
        private Clock $clock,
    ) {}

    /**
     * What the completion needs to lock.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Linking\LinkingDiscovery
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function discover(CompletionState $state): LinkingDiscovery
    {
        $result     = $state->result;
        $connection = $state->connection;
        $email      = $result?->linkingEmail;

        if ($result === null || $connection === null || $email === null || !self::touchesLinking($state, $connection)) {
            return LinkingDiscovery::notApplicable();
        }

        $this->storage->require('Linking by a verified domain');

        if (self::isSubjectHeld($connection, $result, $this->clock->now())) {
            return LinkingDiscovery::subjectHeld();
        }

        return LinkingDiscovery::open($this->isDomainOpen($connection, $email) ? $this->eligibility->match($result, $email)->identity : null);
    }

    /**
     * Whether the state is a `sign_in` through a connection with linking on,
     * under the feature.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private static function touchesLinking(CompletionState $state, Connection $connection): bool
    {
        return $state->consumed?->purpose === Purpose::SIGN_IN && $connection->linking_enabled && Features::enabled(Feature::DOMAIN_LINKING);
    }

    /**
     * Whether a row holds the subject in the connection, by a plain read,
     * compared byte for byte as well as by its key: any but an expired
     * reservation, which is logically absent.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private static function isSubjectHeld(Connection $connection, VerifiedResult $result, CarbonImmutable $now): bool
    {
        $subject = LinkSubject::of($result);
        $row     = Link::query()->useWritePdo()->where('connection_id', $connection->id)->where('subject_key', $subject->key())->first();

        if ($row === null || !(new LinkSubject($row->issuer, $row->subject, $row->name_id_format))->is($subject)) {
            return false;
        }

        return $row->state !== LinkState::RESERVED || ($row->reservation_expires_at?->isAfter($now) ?? false);
    }

    /**
     * Whether this connection's claim of the email's domain allows linking, as
     * a plain read shows it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isDomainOpen(Connection $connection, LinkingEmail $email): bool
    {
        $domain = DomainLinkEligibility::canonicalDomain($email);
        $claim  = $domain === null ? null : $this->domains->find($connection, $domain);

        return $claim !== null && DomainStanding::allowsLinking($claim, $this->clock->now(), $this->settings->linkingMaxAgeSeconds());
    }
}
