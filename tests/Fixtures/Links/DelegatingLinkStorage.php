<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Links;

use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * A wrapper of the link store, as an application's would be: every method goes
 * to the storage it wraps. Given answers, `resolve()` answers each in turn, the
 * last for ever after, instead of asking it, so a test can move the link under
 * a redemption, or `answering` answers each; `resolutions` counts what it was
 * asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DelegatingLinkStorage implements LinkStorage
{
    /** @var int How many results `resolve()` was asked about. */
    public int $resolutions = 0;

    /** @var ?\Closure(\SineMacula\Laravel\Sso\Results\VerifiedResult): \SineMacula\Laravel\Sso\Links\LinkResolution What answers every resolution, when set. */
    public ?\Closure $answering = null;

    /** @var list<\SineMacula\Laravel\Sso\Links\LinkResolution> What is left to answer. */
    private array $answers;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\LinkStorage  $inner
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  ...$answers
     */
    public function __construct(

        /** The storage every method goes to. */
        private readonly LinkStorage $inner,

        // What it answers first, each in turn, instead of asking
        LinkResolution ...$answers,
    ) {
        $this->answers = array_values($answers);
    }

    /**
     * The next answer given, or what the storage wrapped answers.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Sso\Links\LinkResolution
     */
    #[\Override]
    public function resolve(VerifiedResult $result): LinkResolution
    {
        $this->resolutions++;

        if ($this->answering !== null) {
            return ($this->answering)($result);
        }

        if ($this->answers === []) {
            return $this->inner->resolve($result);
        }

        return count($this->answers) > 1 ? array_shift($this->answers) : $this->answers[0];
    }

    /**
     * What the storage wrapped counts.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return int
     */
    #[\Override]
    public function holdings(string $connectionId, IdentityReference $identity): int
    {
        return $this->inner->holdings($connectionId, $identity);
    }

    /**
     * Create through the storage wrapped.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Links\LinkSubject  $subject
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return \SineMacula\Laravel\Sso\Links\LinkCreation
     */
    #[\Override]
    public function create(
        SsoConnection $connection,
        LinkSubject $subject,
        IdentityReference $identity,
        LinkOrigin $origin,
        ?ActingIdentity $actor = null,
        ?string $application = null,
        ?Purpose $purpose = null,
        ?RequestReference $reference = null,
    ): LinkCreation {
        return $this->inner->create($connection, $subject, $identity, $origin, $actor, $application, $purpose, $reference);
    }

    /**
     * Confirm through the storage wrapped.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $locked
     * @param  string  $linkId
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return void
     */
    #[\Override]
    public function confirm(SsoConnection $locked, string $linkId, ?string $application = null, ?RequestReference $reference = null): void
    {
        $this->inner->confirm($locked, $linkId, $application, $reference);
    }

    /**
     * Suspend through the storage wrapped.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  string  $protocol
     * @return void
     */
    #[\Override]
    public function suspend(string $linkId, IdentityReference $identity, string $connectionId, string $tenantId, string $protocol): void
    {
        $this->inner->suspend($linkId, $identity, $connectionId, $tenantId, $protocol);
    }

    /**
     * Revoke through the storage wrapped.
     *
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @return void
     */
    #[\Override]
    public function revokeSessions(string $linkId, IdentityReference $identity, string $connectionId, string $tenantId): void
    {
        $this->inner->revokeSessions($linkId, $identity, $connectionId, $tenantId);
    }

    /**
     * The reservations of the storage wrapped.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkReservations
     */
    #[\Override]
    public function reservations(): LinkReservations
    {
        return $this->inner->reservations();
    }
}
