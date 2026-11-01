<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Casts\BinaryString;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * One link (SSO-8.2 to SSO-8.4): a connection's issuer and subject, and for
 * SAML the subject's `NameID` format, associated with an identity, held as an
 * opaque reference (a type and an id).
 *
 * The subject is stored exactly as received, byte for byte, in a binary column
 * (`Casts\BinaryString`), never trimmed or normalised (SSO-6.9); the issuer and
 * format are kept as received too. `subject_key` is the lower-case hex SHA-256
 * of the issuer, the format and the subject, each length-prefixed, unique with
 * the connection: one subject in one connection is linked to one identity at
 * most, however two creations race, and lookups compare it exactly, whatever
 * the engine's collation.
 *
 * It holds its state (active, or reserved by a completion that matched it by a
 * verified domain, with when the reservation expires and the request it was
 * made for, SSO-8.8); whether it was made by a verified domain, a provenance a
 * confirming `link` clears; and when it was created, last used and last
 * changed.
 *
 * Its key is a lower-case ULID and its timestamps come from the package's clock
 * (see `SsoModel`); its connection, issuer, format, subject and key are fixed
 * once it exists. The table comes from `sso.links.table`, the connection from
 * the storage connection; every read that decides a flow is made on the write
 * connection (SSO-11.3).
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
 * @property bool $domain_provenance
 * @property ?\Carbon\CarbonImmutable $reservation_expires_at
 * @property ?string $reservation_reference
 * @property ?\Carbon\CarbonImmutable $last_used_at
 * @property \Carbon\CarbonImmutable $created_at
 * @property \Carbon\CarbonImmutable $updated_at
 */
final class Link extends SsoModel
{
    /** @var string The key, under `sso.`, of the setting that names the model's table. */
    protected const string TABLE = 'links.table';

    /** @var list<string> The columns fixed when the link is made. */
    private const array FIXED = ['connection_id', 'issuer', 'name_id_format', 'subject', 'subject_key'];

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Indicates if the model should be timestamped: the package stamps it from its clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var array<string, mixed> The model's default attribute values: a link is active and has no verified domain provenance. */
    protected $attributes = [
        'state'             => 'active',
        'domain_provenance' => false,
    ];

    /**
     * Key and stamp each new link, and refuse a change to what it links once it
     * exists.
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
            'subject'                => BinaryString::class,
            'state'                  => LinkState::class,
            'domain_provenance'      => 'boolean',
            'reservation_expires_at' => UtcDateTime::class,
            'last_used_at'           => UtcDateTime::class,
            'created_at'             => UtcDateTime::class,
            'updated_at'             => UtcDateTime::class,
        ];
    }
}
