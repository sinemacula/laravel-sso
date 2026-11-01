<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

/**
 * What the `Contracts\Enforcement` contract answers for a tenant and an
 * application (SSO-4.1, SSO-4.2, SSO-4.6): whether sessions active in the
 * tenant must be established through a connection, which connections satisfy
 * that, whose rule it is, and the version of that rule.
 *
 * - `tenantId` is the tenant asked about, the one a session is active in.
 * - `enforcingTenantId` is the tenant whose rule applies, as the
 *   `Contracts\EnforcementInheritance` contract chose it: the tenant itself by
 *   default, or an ancestor the application names. The satisfying connections
 *   always belong to it.
 * - `required` is whether sign-in through one of `connectionIds` is required.
 * - `connectionIds` are the connections that satisfy it, each of the enforcing
 *   tenant and enabled, in id order; none when it is not required.
 * - `version` changes with every change to the enforcing tenant's rule, so an
 *   adapter that records it against a session rechecks the session once it is
 *   stale; `null` while that tenant has never had a rule stored.
 *
 * A policy that is required with no connection left (every satisfying
 * connection since disabled) is satisfied by none: only an exemption admits a
 * session then (SSO-4.4). Ids are compared byte for byte.
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

        /** The connections that satisfy it, in id order. */
        public array $connectionIds,

        /** The version of the enforcing tenant's rule, `null` when it has none stored. */
        public ?string $version,
    ) {}

    /**
     * Sessions active in the tenant need not come through a connection.
     *
     * @param  string  $tenantId
     * @param  string  $enforcingTenantId
     * @param  ?string  $version
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function notRequired(string $tenantId, string $enforcingTenantId, ?string $version = null): self
    {
        self::assertTenants($tenantId, $enforcingTenantId);

        return new self($tenantId, $enforcingTenantId, false, [], $version);
    }

    /**
     * Sessions active in the tenant must have been established through one of
     * the connections given, which are de-duplicated and put in id order.
     *
     * @param  string  $tenantId
     * @param  string  $enforcingTenantId
     * @param  list<string>  $connectionIds
     * @param  string  $version
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function required(string $tenantId, string $enforcingTenantId, array $connectionIds, string $version): self
    {
        self::assertTenants($tenantId, $enforcingTenantId);

        if ($version === '') {
            throw new \InvalidArgumentException('A required enforcement has a version.');
        }

        $ids = array_values(array_unique(array_filter($connectionIds, static fn (string $id): bool => $id !== '')));

        sort($ids, SORT_STRING);

        return new self($tenantId, $enforcingTenantId, true, $ids, $version);
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
     * Whether a session established through the connection complies: always
     * when nothing is required, and only through a satisfying connection when
     * something is.
     *
     * @param  string  $connectionId
     * @return bool
     */
    public function isSatisfiedBy(string $connectionId): bool
    {
        return !$this->required || in_array($connectionId, $this->connectionIds, true);
    }

    /**
     * The policy, with snake_case keys.
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
     * Refuse an empty tenant id: the application's or the contract's mistake.
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
}
