<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Events;

use Illuminate\Database\Eloquent\Model;

/**
 * The example application's record of one administration change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $event
 * @property ?string $tenant_id
 * @property ?string $connection_id
 * @property ?string $actor_type
 * @property ?string $actor_id
 * @property array<string, mixed> $details
 * @property array<string, ?string> $context
 *
 * @internal
 */
final class AuditEntry extends Model
{
    /** @var string The application's table. */
    public const string TABLE = 'audit_entries';

    /** @var ?string The table the model is stored in. */
    protected $table = self::TABLE;

    /** @var list<string> The attributes that may be filled. */
    protected $fillable = ['event', 'tenant_id', 'connection_id', 'actor_type', 'actor_id', 'details', 'context'];

    /**
     * The attributes stored as JSON.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return ['details' => 'array', 'context' => 'array'];
    }
}
