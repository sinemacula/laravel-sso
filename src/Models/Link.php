<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use Illuminate\Database\Eloquent\Casts\Attribute;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Casts\BinaryString;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * A connection's issuer and subject linked to an identity, with the subject
 * stored byte for byte.
 *
 * `subject_key` hashes issuer, format and subject, unique per connection, so
 * lookups are exact whatever the collation.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $connection_id
 * @property string $issuer
 * @property ?string $name_id_format
 * @property string $subject
 * @property string $subject_key
 * @property string $identity_type
 * @property string $identity_id
 * @property \SineMacula\Laravel\Sso\Links\Enums\LinkState $state
 * @property ?\Carbon\CarbonImmutable $suspended_at
 * @property \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin $provenance
 * @property bool $domain_provenance
 * @property ?string $reservation_id
 * @property ?\Carbon\CarbonImmutable $reservation_expires_at
 * @property ?string $reservation_reference
 * @property ?string $reservation_handoff
 * @property ?string $reservation_email_digest
 * @property ?string $reservation_organization
 * @property ?string $reservation_domain_id
 * @property ?int $reservation_domain_generation
 * @property ?int $reservation_linking_version
 * @property ?\Carbon\CarbonImmutable $last_used_at
 * @property \Carbon\CarbonImmutable $created_at
 * @property \Carbon\CarbonImmutable $updated_at
 */
final class Link extends SsoModel
{
    /** @var string The `sso.` setting that names the table. */
    protected const string TABLE = 'links.table';

    /** @var list<string> The columns fixed when the link is made. */
    private const array FIXED = ['connection_id', 'issuer', 'name_id_format', 'subject', 'subject_key'];

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Stamped from the package's clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var list<string> The attributes hidden from serialisation. */
    protected $hidden = ['reservation_email_digest', 'reservation_organization'];

    /** @var array<string, mixed> The model's default attribute values. */
    protected $attributes = [
        'state'      => 'active',
        'provenance' => 'link_purpose',
    ];

    /**
     * Key and stamp each new link, and fix what it links.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::identifiedAndStamped();

        self::updating(static function (self $link): void {
            if ($link->isDirty(self::FIXED)) {
                throw new \LogicException('A link\'s connection, issuer, NameID format and subject are fixed when it is made.');
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
            'subject'                       => BinaryString::class,
            'state'                         => LinkState::class,
            'provenance'                    => LinkOrigin::class,
            'suspended_at'                  => UtcDateTime::class,
            'reservation_expires_at'        => UtcDateTime::class,
            'reservation_domain_generation' => 'integer',
            'reservation_linking_version'   => 'integer',
            'last_used_at'                  => UtcDateTime::class,
            'created_at'                    => UtcDateTime::class,
            'updated_at'                    => UtcDateTime::class,
        ];
    }

    /**
     * Whether the link stands on a verified domain, not since confirmed.
     *
     * @return \Illuminate\Database\Eloquent\Casts\Attribute<bool, never>
     */
    protected function domainProvenance(): Attribute
    {
        return Attribute::get(fn (): bool => $this->provenance === LinkOrigin::VERIFIED_DOMAIN);
    }
}
