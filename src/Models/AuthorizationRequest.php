<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * One attempt at a flow, consumed once whether it succeeds or fails; protocol
 * state and nonce are held only as digests.
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
    /** @var string The `sso.` setting that names the table. */
    protected const string TABLE = 'authorization_requests.table';

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Stamped from the package's clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var list<string> The attributes hidden from serialisation. */
    protected $hidden = ['state_digest', 'nonce_digest', 'code_verifier'];

    /** @var array<string, mixed> The model's default attribute values. */
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
