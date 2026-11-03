<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * One handoff code the package's own store issued (SSO-9.2): single-use and
 * short-lived, held only as the SHA-256 digest of the code.
 *
 * It holds what the code is bound to: the purpose, the application, the
 * connection, the request's public reference and the S256 challenge of the
 * client's verifier; the identity the result's link resolved to at completion,
 * if any; the identity a `link` or `reauthenticate` flow was started for, and
 * the session a `reauthenticate` flow was started on. It holds the verified
 * result, serialised and encrypted through `Contracts\SecretEncrypter`, since
 * it carries personal data; the connection's trust version when it was issued
 * (SSO-2.13); the latest end of the application's session the provider's
 * deadline sets (SSO-9.10); when it expires; and when it was redeemed or voided
 * by a change to its connection.
 *
 * Its key is a lower-case ULID and its timestamps come from the package's clock
 * (see `SsoModel`). The digest and the encrypted result are hidden from
 * serialisation and never put in an event (SSO-10.4). The table comes from
 * `sso.handoff_codes.table`, the connection from the storage connection; every
 * read that decides a redemption is made on the write connection (SSO-11.3).
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
    /** @var string The key, under `sso.`, of the setting that names the model's table. */
    protected const string TABLE = 'handoff_codes.table';

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var bool Indicates if the model should be timestamped: the package stamps it from its clock instead. */
    public $timestamps = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /** @var list<string> The attributes hidden from serialisation: the digest and the encrypted result. */
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
