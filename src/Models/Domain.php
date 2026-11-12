<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * A connection's claim of an email domain.
 *
 * `verified_domain` is unique and set only while verified, so a domain is
 * verified for at most one connection across every tenant.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $connection_id
 * @property string $domain
 * @property ?string $verified_domain
 * @property \SineMacula\Laravel\Sso\Domains\Enums\DomainState $state
 * @property string $record_name
 * @property string $verification_token
 * @property \Carbon\CarbonImmutable $claimed_at
 * @property ?\Carbon\CarbonImmutable $pending_expires_at
 * @property ?\Carbon\CarbonImmutable $verified_at
 * @property int $verification_generation
 * @property ?\Carbon\CarbonImmutable $last_successful_check_at
 * @property ?\Carbon\CarbonImmutable $linking_suspended_at
 * @property ?\Carbon\CarbonImmutable $lapses_at
 * @property ?\Carbon\CarbonImmutable $lapsed_at
 * @property ?\Carbon\CarbonImmutable $recheck_leased_until
 * @property \Carbon\CarbonImmutable $created_at
 * @property \Carbon\CarbonImmutable $updated_at
 */
final class Domain extends SsoModel
{
    /** @var string The `sso.` setting that names the table. */
    protected const string TABLE = 'domains.table';

    /** @var list<string> The columns fixed when the claim is made. */
    private const array FIXED = ['connection_id', 'domain'];

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Stamped from the package's clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var list<string> Published in DNS, but kept out of serialisation. */
    protected $hidden = ['verification_token'];

    /**
     * Key and stamp each new claim, and fix its connection and domain.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::identifiedAndStamped();

        self::updating(static function (self $domain): void {
            if ($domain->isDirty(self::FIXED)) {
                throw new \LogicException('A claimed domain\'s connection and domain are fixed when it is claimed.');
            }
        });
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
            'state'                    => DomainState::class,
            'claimed_at'               => UtcDateTime::class,
            'pending_expires_at'       => UtcDateTime::class,
            'verified_at'              => UtcDateTime::class,
            'verification_generation'  => 'integer',
            'last_successful_check_at' => UtcDateTime::class,
            'linking_suspended_at'     => UtcDateTime::class,
            'lapses_at'                => UtcDateTime::class,
            'lapsed_at'                => UtcDateTime::class,
            'recheck_leased_until'     => UtcDateTime::class,
            'created_at'               => UtcDateTime::class,
            'updated_at'               => UtcDateTime::class,
        ];
    }
}
