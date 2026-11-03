<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Links;

use Illuminate\Contracts\Session\Session;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;

/**
 * The example application's sessions (SSO-8.8): it records the session the
 * request carries when a person signs in, through an admitted SSO sign-in or
 * with a password, and reads it back, locked, for its link confirmation. It
 * reads and writes them on the package's storage connection, so a locking read
 * takes part in a redemption's transaction.
 *
 * A session admitted from a redemption records the link it stood on and whether
 * that link had verified domain provenance then, from the provenance the
 * redemption captured, so the answer never depends on the links that remain.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Sessions
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Session\Session  $session
     */
    public function __construct(

        /** The session the request carries. */
        private Session $session,
    ) {}

    /**
     * Record the request's session as established by the admitted sign-in.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\RedemptionResult  $result
     * @return \Tests\Integration\Examples\Links\UserSession
     *
     * @throws \LogicException
     */
    public function admitted(RedemptionResult $result): UserSession
    {
        $identity = $result->linkedIdentity ?? throw new \LogicException('An admitted sign-in names the identity it signs in.');

        return UserSession::on(StorageConnection::name())->create([
            'id'              => $this->session->getId(),
            'identity_type'   => $identity->type,
            'identity_id'     => $identity->id,
            'sso_link_id'     => $result->linkId,
            'sso_domain_link' => $result->provenance?->linkProvenance === LinkOrigin::VERIFIED_DOMAIN,
        ]);
    }

    /**
     * Record the request's session as established by the person's password.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \Tests\Integration\Examples\Links\UserSession
     */
    public function signedInWithPassword(IdentityReference $identity): UserSession
    {
        return UserSession::on(StorageConnection::name())->create([
            'id'              => $this->session->getId(),
            'identity_type'   => $identity->type,
            'identity_id'     => $identity->id,
            'sso_domain_link' => false,
        ]);
    }

    /**
     * The request's session of the identity, locked on the package's storage
     * connection until the transaction it is read in ends, or `null` when the
     * request carries none of the identity's.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return ?\Tests\Integration\Examples\Links\UserSession
     */
    public function currentLocked(IdentityReference $identity): ?UserSession
    {
        return UserSession::on(StorageConnection::name())
            ->useWritePdo()
            ->whereKey($this->session->getId())
            ->where('identity_type', $identity->type)
            ->where('identity_id', $identity->id)
            ->lockForUpdate()
            ->first();
    }

    /**
     * Whether the session was established through a link that had verified
     * domain provenance when it was admitted, whatever became of the link.
     *
     * @param  \Tests\Integration\Examples\Links\UserSession  $session
     * @return bool
     */
    public function wasEstablishedOnADomainLink(UserSession $session): bool
    {
        return $session->sso_domain_link;
    }

    /**
     * Whether the session was neither established nor renewed through any of
     * the links.
     *
     * @param  \Tests\Integration\Examples\Links\UserSession  $session
     * @param  list<string>  $linkIds
     * @return bool
     */
    public function wasAuthenticatedApartFrom(UserSession $session, array $linkIds): bool
    {
        return !in_array($session->sso_link_id, $linkIds, true) && !in_array($session->renewed_link_id, $linkIds, true);
    }
}
