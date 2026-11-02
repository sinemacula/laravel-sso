<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;

/**
 * Link confirmation contract (SSO-8.8): whether the caller redeeming a `link`
 * authenticated by something independent of the verified domain links its
 * identity holds. The identity provider behind such a link was never chosen by
 * the person, so its own assertion, or a session or freshness it renewed, is
 * not the person's confirmation.
 *
 * It is asked inside a `link` redemption's transaction, in its judgement and
 * again in its admission, only when the identity holds an active or suspended
 * link of verified domain provenance in any connection: the ids of those links
 * are given, oldest first. A `link` of an identity holding none never asks it.
 *
 * Answer `independent` only when the current session was not established
 * through any link given, and its freshness was not renewed through one, nor
 * through the connection a given link belongs to; a password or a passkey the
 * person holds is independent. Answer `dependent` otherwise, and when it cannot
 * tell. A person whose only credential is such a link stays unable to confirm
 * it; removing the link is what remains (`docs/guides/links.md`).
 *
 * Protection through admission: an implementation that reads the session keeps
 * its answer true until the redeemer's transaction commits, by a guard its
 * writers also take, and an implementation with no such guard answers
 * `dependent` (`docs/design/linking.md`).
 *
 * The default, `Linking\RefusingLinkConfirmation`, answers `dependent` for
 * everyone. An implementation reads from the write connection (SSO-11.3), keeps
 * nothing of one call for the next (SSO-11.2), and lets an error propagate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LinkConfirmation
{
    /**
     * Whether the caller's current authentication is independent of the links.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  non-empty-list<string>  $domainLinkIds
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     */
    public function judge(IdentityReference $identity, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict;
}
