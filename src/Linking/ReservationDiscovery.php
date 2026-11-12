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
 * Finds, by plain reads before a completion locks, what it must lock and whose
 * identity guard to take first.
 *
 * It decides nothing: `DomainLinkEligibility` judges it all again under the
 * locks.
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
     * Whether a row other than an expired reservation holds the subject, by a
     * plain read.
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
     * Whether this connection's claim of the email's domain allows linking, by
     * a plain read.
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
