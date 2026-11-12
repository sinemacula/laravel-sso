<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;

/**
 * A tenant's enforcement as stored, including ids of connections since disabled
 * or deleted.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnforcementSummary implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  string  $tenantId
     * @param  bool  $enabled
     * @param  list<string>  $connectionIds
     * @param  ?string  $version
     * @param  ?\Carbon\CarbonImmutable  $changedAt
     */
    public function __construct(

        /** The tenant the enforcement belongs to. */
        public string $tenantId,

        /** Whether sign-in through a satisfying connection is required. */
        public bool $enabled,

        /** The ids stored as satisfying it, each once, in id order. */
        public array $connectionIds,

        /** The rule's version, `null` when none was ever stored. */
        public ?string $version = null,

        /** When the rule last changed, `null` when none was stored. */
        public ?CarbonImmutable $changedAt = null,
    ) {}

    /**
     * Summarise the row; an unconfigured row reads exactly as no row.
     *
     * @param  string  $tenantId
     * @param  ?\SineMacula\Laravel\Sso\Models\TenantEnforcement  $enforcement
     * @return self
     */
    public static function of(string $tenantId, ?TenantEnforcement $enforcement): self
    {
        if ($enforcement?->version === null) {
            return new self($tenantId, false, []);
        }

        return new self($tenantId, $enforcement->enabled, self::sorted($enforcement->connection_ids), $enforcement->version, $enforcement->changed_at);
    }

    /**
     * The string ids given, deduplicated and sorted.
     *
     * @param  array<array-key, mixed>  $ids
     * @return list<string>
     */
    public static function sorted(array $ids): array
    {
        $ids = array_values(array_unique(array_filter($ids, is_string(...))));

        sort($ids, SORT_STRING);

        return $ids;
    }

    /**
     * Snake_case keys, with the time as an ISO 8601 UTC string.
     *
     * @return array{tenant_id: string, enabled: bool, connection_ids: list<string>, version: ?string, changed_at: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'tenant_id'      => $this->tenantId,
            'enabled'        => $this->enabled,
            'connection_ids' => $this->connectionIds,
            'version'        => $this->version,
            'changed_at'     => $this->changedAt?->utc()->format('Y-m-d\TH:i:s\Z'),
        ];
    }
}
