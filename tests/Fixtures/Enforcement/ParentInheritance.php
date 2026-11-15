<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Enforcement;

use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;

/**
 * An inheritance contract over a small tenant tree: a tenant listed with a
 * parent inherits that parent's rule, and any other tenant keeps its own. It
 * records each question, so a test proves the contract was asked, and with
 * what.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ParentInheritance implements EnforcementInheritance
{
    /** @var list<array{0: string, 1: string}> Each tenant and application asked about, in order. */
    private array $asked = [];

    /**
     * Constructor.
     *
     * @param  array<string, string>  $parents
     */
    public function __construct(

        /** Each tenant whose parent's rule applies, and that parent. */
        private readonly array $parents = [],
    ) {}

    /**
     * The tenant, then its parent when it has one listed.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @param  \Closure(string): bool  $isConfigured
     * @return non-empty-list<string>
     */
    #[\Override]
    public function enforcementPath(string $tenantId, string $application, \Closure $isConfigured): array
    {
        $this->asked[] = [$tenantId, $application];

        return isset($this->parents[$tenantId]) ? [$tenantId, $this->parents[$tenantId]] : [$tenantId];
    }

    /**
     * Each tenant and application asked about, in order.
     *
     * @return list<array{0: string, 1: string}>
     */
    public function asked(): array
    {
        return $this->asked;
    }
}
