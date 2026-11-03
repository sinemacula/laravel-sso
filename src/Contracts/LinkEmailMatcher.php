<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkEmailQuery;

/**
 * Link email contract (SSO-8.8): finds the identities whose email is verified
 * in the application and equal to the linking email, for linking by a verified
 * domain. It answers none, exactly one or ambiguous, and an email merely
 * present and unverified never counts. The application binds it; an adapter to
 * the application's authentication passes the email through that
 * authentication's own email normaliser.
 *
 * The query holds the email exactly as the protocol asserted it, and its domain
 * canonicalised as SSO-3.1 compares one (`Domains\DomainName::normalize()`).
 * The package does not normalise the local part: the application's normaliser
 * does, and matching adds no dot or subaddress removal, Unicode folding or
 * confusable matching. Redemption asks again, and the reservation's identity
 * must still be the sole match; another match never becomes the target.
 *
 * Protection through admission: the answer is read first by a plain read before
 * the completion takes its locks, which only chooses the identity whose guard
 * comes first; it is read again under them, and again inside the redeemer's
 * transaction, on the package's storage connection, and it must stay true until
 * that commits. Locking the rows it returned does not stop another identity
 * from matching later, so an implementation relies on a uniqueness guarantee on
 * the verified email, or takes a guard every writer of a verified email takes,
 * after the package's locks in the documented order (`docs/design/linking.md`).
 *
 * The default, `Linking\NoEmailMatches`, finds none. An implementation reads
 * from the write connection (SSO-11.3), keeps nothing of one call for the next
 * (SSO-11.2), never logs the email, and lets an error propagate: an answer it
 * cannot vouch for is never `exactly one`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface LinkEmailMatcher
{
    /**
     * The identities whose verified email equals the query's.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\LinkEmailQuery  $query
     * @return \SineMacula\Laravel\Sso\Linking\LinkEmailMatch
     */
    public function match(LinkEmailQuery $query): LinkEmailMatch;
}
