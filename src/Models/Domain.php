<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * One connection's claim of an email domain (SSO-3.1 to SSO-3.3): the domain,
 * normalised (lower-case ASCII, no trailing dot); the connection that claimed
 * it; its state; the TXT record name under the domain and the random token the
 * record must carry; when it was claimed and when the claim expires while it is
 * pending; when it became verified, kept until it lapses and set anew when it
 * is verified again; when it last passed a check; when linking by it was
 * suspended and when it lapses, once a recheck found its record gone; when it
 * lapsed; and the lease that keeps two servers from rechecking it at once.
 *
 * `verified_domain` holds the domain while it is verified and `null` otherwise,
 * under a unique index, so a domain is verified for at most one connection at a
 * time across every tenant, however two verifications race.
 *
 * The token is published in DNS and so not a secret, but it is hidden from
 * serialisation, never put in an event (SSO-10.4), and read only through
 * `Domains\DomainSummary::verificationToken()`.
 *
 * Its key is a lower-case ULID and its timestamps come from the package's clock
 * (see `SsoModel`); its connection and domain are fixed once it exists. The
 * table comes from `sso.domains.table`, the connection from the storage
 * connection.
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
    /** @var string The key, under `sso.`, of the setting that names the model's table. */
    protected const string TABLE = 'domains.table';

    /** @var list<string> The columns fixed when the claim is made. */
    private const array FIXED = ['connection_id', 'domain'];

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Indicates if the model should be timestamped: the package stamps it from its clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var list<string> The attributes hidden from serialisation: the verification token. */
    protected $hidden = ['verification_token'];

    /**
     * Key and stamp each new claim, and refuse a change to its connection or
     * domain once it exists.
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
