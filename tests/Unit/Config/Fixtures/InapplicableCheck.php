<?php

declare(strict_types = 1);

namespace Tests\Unit\Config\Fixtures;

use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * A check that does not apply, and whose checks would fail if they ran.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InapplicableCheck implements ConfigurationCheck
{
    /**
     * It does not apply.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return false;
    }

    /**
     * A check that must never run.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [
            static function (): void {
                throw new \LogicException('A check that does not apply was run.');
            },
        ];
    }
}
