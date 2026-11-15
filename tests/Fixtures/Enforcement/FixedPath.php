<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Enforcement;

use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;

/**
 * An inheritance contract that answers the same path, whatever is asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedPath implements EnforcementInheritance
{
    /**
     * Constructor.
     *
     * @param  mixed  $path
     */
    public function __construct(

        /** What every call answers, well formed or not. */
        private mixed $path,
    ) {}

    /**
     * The path given.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @param  \Closure(string): bool  $isConfigured
     * @return non-empty-list<string>
     */
    #[\Override]
    public function enforcementPath(string $tenantId, string $application, \Closure $isConfigured): array
    {
        /** @var non-empty-list<string> */
        return $this->path;
    }
}
