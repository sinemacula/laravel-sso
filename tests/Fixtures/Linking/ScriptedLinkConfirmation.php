<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Linking;

use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;

/**
 * A link confirmation contract answering what the test sets, or throwing it,
 * and recording what it was asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedLinkConfirmation implements LinkConfirmation
{
    /** @var list<array{0: string, 1: string, 2: list<string>}> Every question asked: the identity's id, the connection's id and the links. */
    public array $asked = [];

    /** @var ?\Throwable What it throws instead of answering. */
    public ?\Throwable $failure = null;

    /** @var list<\SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict> What it answers first, before the verdict set. */
    public array $queued = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict  $verdict
     */
    public function __construct(

        /** What it answers. */
        public LinkConfirmationVerdict $verdict = LinkConfirmationVerdict::INDEPENDENT,
    ) {}

    /**
     * Answer the verdict set, or throw the failure set.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  non-empty-list<string>  $domainLinkIds
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     *
     * @throws \Throwable
     */
    #[\Override]
    public function judge(IdentityReference $identity, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict
    {
        $this->asked[] = [$identity->id, $connection->getConnectionId(), $domainLinkIds];

        if ($this->failure !== null) {
            throw $this->failure;
        }

        return array_shift($this->queued) ?? $this->verdict;
    }
}
