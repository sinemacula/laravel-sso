<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;

/**
 * The default handoff issuer: stores a code's digest and encrypted result in
 * the completion's transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DatabaseHandoffStore implements HandoffIssuer
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SecretEncrypter  $encrypter
     */
    public function __construct(

        /** Encrypts the verified result the code carries. */
        private SecretEncrypter $encrypter,
    ) {}

    /**
     * Issue a new code for the grant, storing only its digest; expiry is kept
     * to the whole second.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffGrant  $grant
     * @return \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff
     *
     * @throws \JsonException
     * @throws \Random\RandomException
     * @throws \RuntimeException
     */
    #[\Override]
    public function issue(HandoffGrant $grant): IssuedHandoff
    {
        $code   = HandoffCode::generate();
        $result = $grant->result;
        $row    = new StoredCode;

        $row->forceFill([
            'code_digest'          => $code->digest(),
            'purpose'              => $result->purpose,
            'application'          => $result->application,
            'connection_id'        => $result->connectionId,
            'request_reference'    => $result->requestReference->value,
            'handoff_challenge'    => $grant->challenge->value,
            'identity_type'        => $grant->identity?->type,
            'identity_id'          => $grant->identity?->id,
            'session_id'           => $grant->sessionId,
            'linked_identity_type' => $grant->linkedIdentity?->type,
            'linked_identity_id'   => $grant->linkedIdentity?->id,
            'link_id'              => $grant->linkId,
            'reservation_id'       => $grant->reservationId,
            'result'               => $this->encrypter->encrypt(json_encode($result->toArray(), JSON_THROW_ON_ERROR)),
            'trust_version'        => $grant->trustVersion,
            'session_not_after'    => $grant->sessionNotAfter,
            'expires_at'           => $grant->expiresAt,
        ])->save();

        // Writing the locked row keeps a stale voider from missing the code.
        Connection::query()->useWritePdo()->whereKey($result->connectionId)->increment('flows_version');

        return new IssuedHandoff($code, $row->expires_at, $row->id);
    }
}
