<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Enforcement;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;

/**
 * An inheritance contract over a tenant tree: the path runs from the tenant up
 * to the nearest tenant with a stored rule, or to its root. It runs a hook
 * after each answer and counts the queries each call made.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NearestRuleInheritance implements EnforcementInheritance
{
    /** @var list<int> The queries each call's questions made, in call order. */
    public array $queries = [];

    /**
     * Constructor.
     *
     * @param  array<string, string>|\Closure(string): ?string  $parents
     * @param  ?\Closure(int): void  $after
     */
    public function __construct(

        /** Each tenant with a parent and that parent, or what names a tenant's parent. */
        private readonly array|\Closure $parents,

        /** Run with the call's number once it has answered. */
        private readonly ?\Closure $after = null,
    ) {}

    /**
     * The tenant up to the nearest tenant with a rule, or its root.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @param  \Closure(string): bool  $isConfigured
     * @return non-empty-list<string>
     */
    #[\Override]
    public function enforcementPath(string $tenantId, string $application, \Closure $isConfigured): array
    {
        unset($application);

        $made = 0;

        DB::listen(static function () use (&$made): void {
            $made++;
        });

        $path   = [$tenantId];
        $parent = $this->parentOf($tenantId);

        while ($parent !== null && !$isConfigured($path[array_key_last($path)])) {
            $path[] = $parent;
            $parent = $this->parentOf($parent);
        }

        $this->queries[] = $made;

        if ($this->after !== null) {
            ($this->after)(count($this->queries));
        }

        return $path;
    }

    /**
     * The tenant's parent, `null` for a root.
     *
     * @param  string  $tenantId
     * @return ?string
     */
    private function parentOf(string $tenantId): ?string
    {
        return $this->parents instanceof \Closure ? ($this->parents)($tenantId) : $this->parents[$tenantId] ?? null;
    }
}
