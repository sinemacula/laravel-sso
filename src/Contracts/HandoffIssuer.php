<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;

/**
 * Handoff issuer contract (SSO-9.2): issues the single-use, short-lived code
 * that carries a verified result from the API to the client that started the
 * flow, bound to every part of the grant: the purpose, the application, the
 * connection, the request's public reference, the S256 challenge of the
 * client's verifier, the identity the result's link resolved to, the identity
 * of a `link` or `reauthenticate` flow and the session of a `reauthenticate`
 * flow, the link the result resolved to, and the reservation it is bound to.
 *
 * For a grant naming a reservation (SSO-8.8), an implementation stores that
 * binding and the expiry with the code in the same write, and answers the
 * expiry as stored, never later than the grant's, and an opaque reference: the
 * completion writes both to the reservation in the same transaction, so
 * reservation and handoff expire together. One that cannot is unsupported, and
 * fails closed: a missing reference or a later expiry rolls the completion back
 * as a server error. Its redeemer must take `Handoffs\HandoffRecheck`'s locks
 * and admission, which activate the reservation in its transaction (decision
 * D5).
 *
 * Every implementation stores, with the code and in the same write, the grant's
 * `trustVersion` exactly as given, and the grant's `sessionNotAfter`, the
 * effective latest end of the session, exactly or to the whole second as the
 * package's own store keeps it, never later; its redeemer answers them back as
 * stored. The trust version goes in the `Handoffs\HandoffBinding` it hands
 * `Handoffs\HandoffRecheck`, which refuses the code as `connection_unavailable`
 * when the connection's trust version under the lock is another (SSO-2.13: a
 * trust change since issuance, a disable and a later enable included), or when
 * the binding names none, so a store that keeps no trust version fails closed
 * rather than redeem a code across a trust change. The session's latest end
 * goes to `Sessions\Provenance::capture()` with the admission, and caps the
 * session the redeemer writes, which never outlives it (SSO-9.10). A `null`
 * `sessionNotAfter` is stored as `null`: the deadline contract ignored the
 * provider's deadline, or there was none, and the session is not capped by it.
 *
 * The completion pipeline asks it once per completed flow, inside the
 * completion's transaction on the storage connection, after rechecking that the
 * application allows sign-in through an external provider; an implementation
 * that writes elsewhere is not atomic with the completion (decision D5). A code
 * is stored only as a hash, is single-use, and lives until the grant's expiry
 * (60 seconds by default, at most 300). An implementation signals failure by
 * throwing, which refuses the completion as a server error (SSO-11.4); it never
 * answers a code it did not store.
 *
 * The default, `Handoffs\DatabaseHandoffStore`, is the package's own store,
 * which the package's redemption helper redeems: the package issues, stores and
 * redeems every handoff code, so there is one kind of code, redeemed by purpose
 * (SSO-9.9), whether the application redeems it alone or through an adapter. An
 * implementation keeps nothing of one call for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HandoffIssuer
{
    /**
     * Issue a code for the grant.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffGrant  $grant
     * @return \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff
     */
    public function issue(HandoffGrant $grant): IssuedHandoff;
}
