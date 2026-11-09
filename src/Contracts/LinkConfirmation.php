<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;

/**
 * Link confirmation contract (SSO-8.8): whether the caller redeeming a `link`
 * authenticated by something independent of the verified domain links its
 * identity holds. The identity provider behind such a link was never chosen by
 * the person, so its own assertion, or a session or freshness it renewed, is
 * not the person's confirmation.
 *
 * It is asked inside a `link` redemption's transaction, in its judgement and
 * again in its admission, when the identity holds an active or suspended link
 * of verified domain provenance in any connection, or has ever held an active
 * one (its guard records that when a reservation is activated, and nothing
 * clears it): the ids of the links it holds now are given, in id order, and
 * none when every one has been removed or confirmed. A `link` of an identity
 * that has never held one never asks it. It is asked under the identity's
 * guard, the connections' and the links' locks (`docs/design/linking.md`), so
 * its own guards come after the package's.
 *
 * It is given the caller the redemption is made for (`Identities\Caller`),
 * whose identity is the one the code is bound to, and judges that caller's
 * session, never the request or job being served. Answer `independent` only
 * when that session was not established through a link that had verified domain
 * provenance when the session was established, whether it is given, removed
 * since or confirmed since, and its freshness was not renewed through one, nor
 * through the connection such a link belongs to; a password or a passkey the
 * person holds is independent. Answer `dependent` otherwise, and when it cannot
 * tell: a caller with no session, and a session it cannot tie to the caller's
 * identity or cannot guard through the redeemer's commit, are `dependent`. So
 * an implementation records, when it admits a session from a redemption,
 * whether the link it stood on (`RedemptionResult::$linkId`) had that
 * provenance then.
 *
 * Removal is not the only way out for a person whose only credential is such a
 * link. Application-controlled recovery, or a credential established
 * independently of the provider, qualifies, and the session they lead to is
 * independent. Removing the link does not turn the session that survives it
 * into independent authentication, so credential enrolment and recovery must
 * preserve that distinction: enrolling a credential from a session the link
 * established proves nothing the provider could not do
 * (`docs/guides/links.md`).
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
     * Whether the caller's session is independent of the links.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  list<string>  $domainLinkIds
     * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
     */
    public function judge(Caller $caller, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict;
}
