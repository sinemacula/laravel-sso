<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * One authorisation request (SSO-5.1, SSO-5.2): one attempt at a flow, started
 * by an application for a purpose through a connection, and consumed once,
 * whether the flow succeeds or fails.
 *
 * It holds its public reference, the only flow identifier the package shows;
 * the SHA-256 digest of its random protocol state (the OIDC `state`, the SAML
 * `RelayState`), never the state itself; what it is for, the application and
 * the connection; the issuer the response must come from and whether that
 * issuer must return `iss` (SSO-7.1); the digest of the OIDC nonce; the PKCE
 * verifier the package uses with the identity provider, encrypted through
 * `Contracts\SecretEncrypter`, never the client's verifier; the SAML
 * `AuthnRequest` id; the S256 challenge of the client's verifier; the identity
 * a `link` or `reauthenticate` flow was started for and the session a
 * `reauthenticate` flow was started on; its connection's trust version when it
 * started, which the completion compares with the connection's before it
 * validates the response and again under its lock; when it expires; and when it
 * was consumed by a completion, voided by a change to its connection, and
 * completed.
 *
 * Its key is a lower-case ULID and its timestamps come from the package's clock
 * (see `SsoModel`). The digests and the encrypted verifier are hidden from
 * serialisation and never put in an event (SSO-10.4). The table comes from
 * `sso.authorization_requests.table`, the connection from the storage
 * connection; every read that decides a flow is made on the write connection
 * (SSO-11.3).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $reference
 * @property string $state_digest
 * @property \SineMacula\Laravel\Sso\Flows\Enums\Purpose $purpose
 * @property string $application
 * @property string $connection_id
 * @property ?string $expected_issuer
 * @property bool $issuer_required
 * @property ?string $nonce_digest
 * @property ?string $code_verifier
 * @property ?string $saml_request_id
 * @property string $handoff_challenge
 * @property int $trust_version
 * @property ?string $identity_type
 * @property ?string $identity_id
 * @property ?string $session_id
 * @property \Carbon\CarbonImmutable $expires_at
 * @property ?\Carbon\CarbonImmutable $consumed_at
 * @property ?\Carbon\CarbonImmutable $verified_at
 * @property ?\Carbon\CarbonImmutable $voided_at
 * @property ?\Carbon\CarbonImmutable $completed_at
 * @property \Carbon\CarbonImmutable $created_at
 * @property \Carbon\CarbonImmutable $updated_at
 */
final class AuthorizationRequest extends SsoModel
{
    /** @var string The key, under `sso.`, of the setting that names the model's table. */
    protected const string TABLE = 'authorization_requests.table';

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Indicates if the model should be timestamped: the package stamps it from its clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var list<string> The attributes hidden from serialisation: the digests and the encrypted verifier. */
    protected $hidden = ['state_digest', 'nonce_digest', 'code_verifier'];

    /** @var array<string, mixed> The model's default attribute values: no issuer needs to return `iss`. */
    protected $attributes = [
        'issuer_required' => false,
    ];

    /**
     * Key and stamp each new request.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::identifiedAndStamped();
    }

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'purpose'         => Purpose::class,
            'issuer_required' => 'boolean',
            'trust_version'   => 'integer',
            'expires_at'      => UtcDateTime::class,
            'consumed_at'     => UtcDateTime::class,
            'verified_at'     => UtcDateTime::class,
            'voided_at'       => UtcDateTime::class,
            'completed_at'    => UtcDateTime::class,
            'created_at'      => UtcDateTime::class,
            'updated_at'      => UtcDateTime::class,
        ];
    }
}
