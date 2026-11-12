<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * A connection's own rotated key pair, or a trusted identity provider signing
 * certificate; a private key is stored only encrypted.
 *
 * Only the class name is public API; the columns belong to the key operations.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $connection_id
 * @property \SineMacula\Laravel\Sso\Keys\Enums\KeyUse $use
 * @property ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState $state
 * @property \SineMacula\Laravel\Sso\Keys\Enums\KeyType $key_type
 * @property int $key_bits
 * @property ?string $certificate
 * @property string $public_key
 * @property ?string $private_key
 * @property string $fingerprint
 * @property ?\Carbon\CarbonImmutable $not_before
 * @property ?\Carbon\CarbonImmutable $not_after
 * @property ?\Carbon\CarbonImmutable $made_current_at
 * @property ?\Carbon\CarbonImmutable $retiring_until
 * @property ?int $expiry_notified_threshold
 * @property ?\Carbon\CarbonImmutable $expiry_notified_at
 * @property ?\Carbon\CarbonImmutable $expiry_claimed_until
 * @property \Carbon\CarbonImmutable $created_at
 * @property \Carbon\CarbonImmutable $updated_at
 */
final class ConnectionKey extends SsoModel
{
    /** @var string The `sso.` setting that names the table. */
    protected const string TABLE = 'keys.table';

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Stamped from the package's clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var list<string> The attributes hidden from serialisation. */
    protected $hidden = ['private_key'];

    /**
     * Key and stamp each new row.
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
            'use'                       => KeyUse::class,
            'state'                     => KeyState::class,
            'key_type'                  => KeyType::class,
            'key_bits'                  => 'integer',
            'not_before'                => UtcDateTime::class,
            'not_after'                 => UtcDateTime::class,
            'made_current_at'           => UtcDateTime::class,
            'retiring_until'            => UtcDateTime::class,
            'expiry_notified_threshold' => 'integer',
            'expiry_notified_at'        => UtcDateTime::class,
            'expiry_claimed_until'      => UtcDateTime::class,
            'created_at'                => UtcDateTime::class,
            'updated_at'                => UtcDateTime::class,
        ];
    }
}
