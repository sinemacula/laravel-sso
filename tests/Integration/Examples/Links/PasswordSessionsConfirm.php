<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;

/**
 * The example application's link confirmation (SSO-8.8): the caller confirms a
 * link of verified domain provenance only from a session that no such link
 * established or renewed, such as one their password established. It answers by
 * how the request's session was established, as recorded when it was admitted,
 * never by which links remain.
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
     * Whether the caller's current session is independent of the links.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  list<string>  $domainLinkIds
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     */
    #[\Override]
    public function judge(IdentityReference $identity, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict
    {
        unset($connection);

        // Locked under your session writers' guard until the redeemer commits
        $session = $this->sessions->currentLocked($identity);

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
