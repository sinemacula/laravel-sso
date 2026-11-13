<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

/**
 * Whether sessions in a tenant must come through one of its enforcing tenant's
 * connections; a required policy with no connection left is satisfied by none.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnforcementPolicy implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  string  $tenantId
     * @param  string  $enforcingTenantId
     * @param  bool  $required
     * @param  list<string>  $connectionIds
     * @param  ?string  $version
     */
    private function __construct(

        /** The tenant asked about. */
        public string $tenantId,

        /** The tenant whose rule applies. */
        public string $enforcingTenantId,

        /** Whether sign-in through a satisfying connection is required. */
        public bool $required,

        /** The enabled connections that satisfy it, in id order. */
        public array $connectionIds,

        /** Changes with the rule and with which of its connections are enabled; `null` when no rule is stored. */
        public ?string $version,
    ) {}

    /**
     * Sessions active in the tenant need not come through a connection; the
     * rule's own version is `null` when none is stored.
     *
     * @param  string  $tenantId
     * @param  string  $enforcingTenantId
     * @param  ?string  $ruleVersion
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function notRequired(string $tenantId, string $enforcingTenantId, ?string $ruleVersion = null): self
    {
        self::assertTenants($tenantId, $enforcingTenantId);

        return new self($tenantId, $enforcingTenantId, false, [], $ruleVersion === null ? null : self::fingerprint($ruleVersion, []));
    }

    /**
     * Sessions in the tenant must come through one of the connections given,
     * under the rule of the version given.
     *
     * @param  string  $tenantId
     * @param  string  $enforcingTenantId
     * @param  list<string>  $connectionIds
     * @param  string  $ruleVersion
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function required(string $tenantId, string $enforcingTenantId, array $connectionIds, string $ruleVersion): self
    {
        self::assertTenants($tenantId, $enforcingTenantId);

        if ($ruleVersion === '') {
            throw new \InvalidArgumentException('A required enforcement has a version.');
        }

        $ids = array_values(array_unique(array_filter($connectionIds, static fn (string $id): bool => $id !== '')));

        sort($ids, SORT_STRING);

        return new self($tenantId, $enforcingTenantId, true, $ids, self::fingerprint($ruleVersion, $ids));
    }

    /**
     * Whether sign-in through a satisfying connection is required.
     *
     * @return bool
     */
    public function isRequired(): bool
    {
        return $this->required;
    }

    /**
     * Whether a session established through the connection complies.
     *
     * @param  string  $connectionId
     * @return bool
     */
    public function isSatisfiedBy(string $connectionId): bool
    {
        return !$this->required || in_array($connectionId, $this->connectionIds, true);
    }

    /**
     * Snake_case keys.
     *
     * @return array{tenant_id: string, enforcing_tenant_id: string, required: bool, connection_ids: list<string>, version: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'tenant_id'           => $this->tenantId,
            'enforcing_tenant_id' => $this->enforcingTenantId,
            'required'            => $this->required,
            'connection_ids'      => $this->connectionIds,
            'version'             => $this->version,
        ];
    }

    /**
     * Refuse an empty tenant id.
     *
     * @param  string  $tenantId
     * @param  string  $enforcingTenantId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertTenants(string $tenantId, string $enforcingTenantId): void
    {
        if ($tenantId === '' || $enforcingTenantId === '') {
            throw new \InvalidArgumentException('An enforcement policy names its tenant and the tenant whose rule applies.');
        }
    }

    /**
     * The lower-case hex SHA-256 of the rule's version and the connections that
     * satisfy it.
     *
     * @param  string  $ruleVersion
     * @param  list<string>  $connectionIds
     * @return string
     */
    private static function fingerprint(string $ruleVersion, array $connectionIds): string
    {
        return hash('sha256', implode("\0", [$ruleVersion, ...$connectionIds]));
    }
}
