<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;

/**
 * The example application's link confirmation: only a session no domain link
 * established or renewed is independent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasswordSessionsConfirm implements LinkConfirmation
{
    /**
     * Constructor.
     *
     * @param  \Tests\Integration\Examples\Links\Sessions  $sessions
     */
    public function __construct(

        /** The application's own sessions. */
        private Sessions $sessions,
    ) {}

    // @snippet-start links-confirmation
    /**
     * Whether the caller's session is independent of the links.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  list<string>  $domainLinkIds
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     */
    #[\Override]
    public function judge(Caller $caller, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict
    {
        unset($connection);

        // The caller's own session, none without one, locked under your session
        // writers' guard until the redeemer commits
        $session = $this->sessions->lockedFor($caller);

        // Neither established through a link of verified domain provenance,
        // held now or before, as recorded when the session was admitted, nor
        // renewed through one
        $independent = $session !== null
            && !$this->sessions->wasEstablishedOnADomainLink($session)
            && $this->sessions->wasAuthenticatedApartFrom($session, $domainLinkIds);

        return $independent ? LinkConfirmationVerdict::INDEPENDENT : LinkConfirmationVerdict::DEPENDENT;
    }
    // @snippet-end links-confirmation
}
