<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;

/**
 * The package's own handoff store (SSO-9.2): the default handoff issuer, whose
 * codes `Handoffs\HandoffRedemption` redeems.
 *
 * `issue()` generates a new `HandoffCode` and inserts one row through
 * `Models\HandoffCode`, on the storage connection, inside the transaction the
 * completion has open, so the code is kept only when the completion commits
 * (decision D5). The row holds the code's SHA-256 digest, never the code; what
 * the code is bound to: the result's purpose, application, connection and
 * request's public reference, the S256 challenge of the client's verifier, the
 * identity a `link` or `reauthenticate` flow was started for, the session a
 * `reauthenticate` flow was started on, and the identity the result's link
 * resolved to; the verified result, as the JSON of `VerifiedResult::toArray()`
 * encrypted through `Contracts\SecretEncrypter`, since it carries personal
 * data; the enforcement version and the session's latest end (SSO-9.10); and
 * the expiry. Times are kept to the whole second, so a code expires at most a
 * second before its grant says; the issued handoff carries the expiry as
 * stored.
 *
 * The completion holds the connection's row lock when it asks, and the issue
 * raises the connection's flows version by one under it, so the code's insert
 * also writes the connection's row: a PostgreSQL `REPEATABLE READ` change whose
 * snapshot predates the code then fails to serialise when it locks the row,
 * rather than void the connection's codes without this one
 * (`Connections\InFlightVoider`).
 *
 * The code is answered once, in the `IssuedHandoff`, for the completion's
 * redirect; it is never stored, logged or put in an event. A database error, a
 * result that cannot be encoded and an encrypter that cannot encrypt propagate,
 * which refuses the completion as a server error (SSO-11.4).
 *
 * It holds the encrypter, which keeps nothing of one call for the next
 * (SSO-11.2), and is bound scoped.
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
     * Issue a new code for the grant, storing only its digest.
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
            'result'               => $this->encrypter->encrypt(json_encode($result->toArray(), JSON_THROW_ON_ERROR)),
            'enforcement_version'  => $grant->enforcementVersion,
            'session_not_after'    => $grant->sessionNotAfter,
            'expires_at'           => $grant->expiresAt,
        ])->save();

        self::raiseFlowsVersion($result->connectionId);

        return new IssuedHandoff($code, $row->expires_at);
    }

    /**
     * Raise the connection's flows version by one, under the lock the
     * completion holds, so the code's insert also writes the connection's row.
     *
     * @param  string  $connectionId
     * @return void
     */
    private static function raiseFlowsVersion(string $connectionId): void
    {
        Connection::query()->useWritePdo()->whereKey($connectionId)->increment('flows_version');
    }
}
