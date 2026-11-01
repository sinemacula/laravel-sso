<?php

declare(strict_types = 1);

namespace Tests\Unit\Config\Fixtures;

use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * A check that applies and finds nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PassingCheck implements ConfigurationCheck
{
    /**
     * It applies.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * One check, which passes.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [static fn (): bool => true];
    }
}
