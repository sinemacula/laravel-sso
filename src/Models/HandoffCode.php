<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * A single-use handoff code, held as its SHA-256 digest with the verified
 * result encrypted, since it carries personal data.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $code_digest
 * @property \SineMacula\Laravel\Sso\Flows\Enums\Purpose $purpose
 * @property string $application
 * @property string $connection_id
 * @property string $request_reference
 * @property string $handoff_challenge
 * @property ?string $identity_type
 * @property ?string $identity_id
 * @property ?string $session_id
 * @property ?string $linked_identity_type
 * @property ?string $linked_identity_id
 * @property ?string $link_id
 * @property ?string $reservation_id
 * @property string $result
 * @property int $trust_version
 * @property ?\Carbon\CarbonImmutable $session_not_after
 * @property \Carbon\CarbonImmutable $expires_at
 * @property ?\Carbon\CarbonImmutable $redeemed_at
 * @property ?\Carbon\CarbonImmutable $voided_at
 * @property \Carbon\CarbonImmutable $created_at
 * @property \Carbon\CarbonImmutable $updated_at
 */
final class HandoffCode extends SsoModel
{
    /** @var string The `sso.` setting that names the table. */
    protected const string TABLE = 'handoff_codes.table';

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Stamped from the package's clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var list<string> The attributes hidden from serialisation. */
    protected $hidden = ['code_digest', 'result'];

    /**
     * Key and stamp each new code.
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
            'purpose'           => Purpose::class,
            'trust_version'     => 'integer',
            'session_not_after' => UtcDateTime::class,
            'expires_at'        => UtcDateTime::class,
            'redeemed_at'       => UtcDateTime::class,
            'voided_at'         => UtcDateTime::class,
            'created_at'        => UtcDateTime::class,
            'updated_at'        => UtcDateTime::class,
        ];
    }
}
