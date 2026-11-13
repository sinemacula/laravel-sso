<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * An application's sessions as the contract kits' tests keep them, in a table
 * on the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KitSessions
{
    /** @var string The table the sessions are kept in. */
    public const string TABLE = 'kit_sessions';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Create the table.
     *
     * @return void
     */
    public static function create(): void
    {
        Schema::connection(StorageConnection::name())->create(self::TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('tenant_id')->nullable();
            $table->string('identity_type');
            $table->string('identity_id');
            $table->string('application')->default('web');
            $table->string('connection_id')->nullable();
            $table->string('link_id')->nullable();
            $table->timestamp('authenticated_at')->nullable();
            $table->boolean('revoked')->default(false);
        });
    }

    /**
     * Drop the table.
     *
     * @return void
     */
    public static function drop(): void
    {
        Schema::connection(StorageConnection::name())->dropIfExists(self::TABLE);
    }

    /**
     * Start a session; its id.
     *
     * @param  ?string  $tenantId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $connectionId
     * @param  ?string  $linkId
     * @param  ?\Carbon\CarbonImmutable  $authenticatedAt
     * @return string
     */
    public static function start(?string $tenantId, IdentityReference $identity, ?string $connectionId, ?string $linkId, ?CarbonImmutable $authenticatedAt = null): string
    {
        return (string) self::query()->insertGetId([
            'tenant_id'        => $tenantId,
            'identity_type'    => $identity->type,
            'identity_id'      => $identity->id,
            'connection_id'    => $connectionId,
            'link_id'          => $linkId,
            'authenticated_at' => $authenticatedAt?->utc()->format('Y-m-d H:i:s'),
        ]);
    }

    /**
     * When the session last authenticated, as stored.
     *
     * @param  string  $sessionId
     * @return \Carbon\CarbonImmutable
     */
    public static function authenticatedAt(string $sessionId): CarbonImmutable
    {
        $stored = self::query()->where('id', $sessionId)->value('authenticated_at');

        return CarbonImmutable::parse(is_string($stored) ? $stored : '', 'UTC');
    }

    /**
     * The sessions on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    public static function query(): Builder
    {
        return DB::connection(StorageConnection::name())->table(self::TABLE);
    }
}
